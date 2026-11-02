// src/svc/store/SqliteDb.h                    namespace cairn::store
// sqlite3 C API 的極薄 RAII 封裝（part2 §2.3.3：不用 ORM / wrapper 套件）。
//
// ★ 可攜程式碼：只相依 sqlite3.h，不 include <windows.h>。
//
// 連線規則（part2 §2.3.3 / SDD-02 §6.5）：
//   - Writer 連線：只有 WriterThread（T4）持有，READWRITE|CREATE，負責 schema 與所有寫入
//   - Reader 連線：每個 RPC / LLM 執行緒各一條，READONLY + query_only=1，禁止顯式交易
//   - 程序啟動時 sqlite3_config(SQLITE_CONFIG_MULTITHREAD)：對應 THREADSAFE=2 語意
//     （多連線安全、單一連線不得跨執行緒共用）。vcpkg 的 sqlite3 預設編為 THREADSAFE=1，
//     執行期降為 multi-thread 模式即可去掉每次 API 呼叫的互斥鎖。
#pragma once
#include <sqlite3.h>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_map>

#include "base/Result.h"

namespace cairn::store {

struct Sqlite3Deleter {
    void operator()(sqlite3* d) const noexcept { ::sqlite3_close_v2(d); }
};
struct StmtDeleter {
    void operator()(sqlite3_stmt* s) const noexcept { ::sqlite3_finalize(s); }
};
using UniqueDb   = std::unique_ptr<sqlite3, Sqlite3Deleter>;
using UniqueStmt = std::unique_ptr<sqlite3_stmt, StmtDeleter>;

enum class ConnRole { Writer, Reader };

// 分級持久性（SDD-02 §6.3.3）：事件可以丟，告警與稽核不可以。
enum class Durability : uint8_t {
    Fast,   // synchronous = NORMAL —— events / process_tree / scores / agent_health
    Safe,   // synchronous = FULL   —— alerts / audit_log
};

inline constexpr int kSchemaVersion = 2;

// SQLite 錯誤碼 → cairn::ErrorCode（BUSY/LOCKED → DbBusy、CORRUPT/NOTADB → DbCorrupt、FULL → DbDiskFull）
[[nodiscard]] ErrorCode MapSqliteError(int rc) noexcept;

class SqliteDb;

// 快取中的 prepared statement 的使用權。解構時自動 sqlite3_reset + clear_bindings，
// 呼叫端不會忘記重置（忘記會讓下一次使用拿到上一次的綁定或 SQLITE_MISUSE）。
class Stmt {
public:
    Stmt(sqlite3_stmt* s, sqlite3* db) noexcept : m_stmt(s), m_db(db) {}
    ~Stmt();
    Stmt(Stmt&& o) noexcept : m_stmt(o.m_stmt), m_db(o.m_db) { o.m_stmt = nullptr; }
    Stmt& operator=(Stmt&&) = delete;
    Stmt(const Stmt&) = delete;
    Stmt& operator=(const Stmt&) = delete;

    // 參數索引從 1 開始（sqlite3 慣例）。
    Stmt& Bind(int idx, int64_t v);
    Stmt& Bind(int idx, double v);
    Stmt& BindBool(int idx, bool v) { return Bind(idx, static_cast<int64_t>(v ? 1 : 0)); }
    // 預設 SQLITE_TRANSIENT（SQLite 複製字串）。批次寫入中來源資料生命週期涵蓋整個 step 時可用 BindTextStatic。
    Stmt& BindText(int idx, std::string_view v);
    Stmt& BindTextStatic(int idx, std::string_view v);
    Stmt& BindNull(int idx);
    // 空字串 → NULL（DB 中「無值」一律存 NULL，查詢端只需判 IS NULL）
    Stmt& BindTextOrNull(int idx, std::string_view v) { return v.empty() ? BindNull(idx) : BindText(idx, v); }
    template <class T>
    Stmt& BindOpt(int idx, const std::optional<T>& v)
    {
        if (!v) return BindNull(idx);
        if constexpr (std::is_same_v<T, std::string>) return BindText(idx, *v);
        else if constexpr (std::is_same_v<T, bool>) return BindBool(idx, *v);
        else if constexpr (std::is_floating_point_v<T>) return Bind(idx, static_cast<double>(*v));
        else return Bind(idx, static_cast<int64_t>(*v));
    }

    // true = 有一列（SQLITE_ROW），false = 完成（SQLITE_DONE）
    [[nodiscard]] Result<bool> Step();
    // 執行至完成（INSERT / UPDATE / DELETE）
    [[nodiscard]] Status Run();

    [[nodiscard]] int64_t     Int64(int col) const noexcept;
    [[nodiscard]] double      Double(int col) const noexcept;
    [[nodiscard]] std::string Text(int col) const;
    [[nodiscard]] bool        IsNull(int col) const noexcept;
    [[nodiscard]] std::optional<int64_t>     OptInt64(int col) const noexcept;
    [[nodiscard]] std::optional<double>      OptDouble(int col) const noexcept;
    [[nodiscard]] std::optional<std::string> OptText(int col) const;
    [[nodiscard]] int ColumnCount() const noexcept;

    [[nodiscard]] sqlite3_stmt* Raw() const noexcept { return m_stmt; }

private:
    sqlite3_stmt* m_stmt;
    sqlite3*      m_db;
};

struct OpenInfo {
    bool    created         = false;   // 新建的空資料庫（已套 schema）
    bool    autoVacuumOk    = true;    // PRAGMA auto_vacuum 回讀 == INCREMENTAL（T-09）
    int     userVersion     = 0;
};

class SqliteDb {
public:
    struct Options {
        int busyTimeoutMs = 5000;   // Writer 5000；Reader 3000（SDD-02 §6.5）
        bool applySchema  = true;   // Writer 開庫時套用 schema / 遷移
    };

    // 工廠：開檔、PRAGMA、schema 皆可能失敗（P-3：建構子不得失敗）。
    [[nodiscard]] static Result<std::unique_ptr<SqliteDb>> Open(const std::filesystem::path& path, ConnRole role)
    {
        return Open(path, role, Options{role == ConnRole::Writer ? 5000 : 3000, role == ConnRole::Writer});
    }
    [[nodiscard]] static Result<std::unique_ptr<SqliteDb>> Open(const std::filesystem::path& path, ConnRole role,
                                                                Options opt);

    ~SqliteDb();
    SqliteDb(const SqliteDb&) = delete;
    SqliteDb& operator=(const SqliteDb&) = delete;

    [[nodiscard]] Status Exec(std::string_view sql);            // 可含多個語句；不快取
    [[nodiscard]] Result<Stmt> Prepare(std::string_view sql);   // 快取：同一條 SQL 只 prepare 一次

    [[nodiscard]] Status SetDurability(Durability d);
    [[nodiscard]] Durability CurrentDurability() const noexcept { return m_durability; }

    // PASSIVE（告警/稽核提交後）/ TRUNCATE（停止服務時）
    [[nodiscard]] Status Checkpoint(bool truncate);
    // 崩潰後啟動：PRAGMA quick_check（不是 integrity_check，SDD-02 §6.7.2）
    [[nodiscard]] Result<bool> QuickCheck();

    // Reader 用：本查詢的時間上限（SDD-02 §6.5「長查詢保護」2 秒）。0 = 取消限制。
    void SetQueryDeadline(std::chrono::milliseconds budget) noexcept;

    [[nodiscard]] int64_t LastInsertRowId() const noexcept { return ::sqlite3_last_insert_rowid(m_db.get()); }
    [[nodiscard]] int     Changes() const noexcept { return ::sqlite3_changes(m_db.get()); }
    [[nodiscard]] sqlite3* Handle() const noexcept { return m_db.get(); }
    [[nodiscard]] ConnRole Role() const noexcept { return m_role; }
    [[nodiscard]] const OpenInfo& Info() const noexcept { return m_info; }
    [[nodiscard]] const std::filesystem::path& Path() const noexcept { return m_path; }
    [[nodiscard]] std::string LastErrorMessage() const { return ::sqlite3_errmsg(m_db.get()); }

    // 單一整數查詢的便利函式（PRAGMA / COUNT / MAX）。無列回 nullopt。
    [[nodiscard]] Result<std::optional<int64_t>> QueryInt64(std::string_view sql);

    void ClearStatementCache() noexcept { m_cache.clear(); }

private:
    SqliteDb(UniqueDb db, ConnRole role, std::filesystem::path path) noexcept;
    [[nodiscard]] Status ApplyWriterPragmasAndSchema();
    [[nodiscard]] Status ApplyReaderPragmas();
    static int ProgressHandler(void* ctx) noexcept;

    UniqueDb                                     m_db;
    ConnRole                                     m_role;
    std::filesystem::path                        m_path;
    Durability                                   m_durability = Durability::Fast;
    std::unordered_map<std::string, UniqueStmt>  m_cache;
    OpenInfo                                     m_info;
    std::chrono::steady_clock::time_point        m_deadline{};
    bool                                         m_deadlineActive = false;
};

// RAII 交易：BEGIN IMMEDIATE（一開始就取寫鎖，SDD-02 §6.3.1），解構時若未 Commit 則 ROLLBACK。
class Transaction {
public:
    explicit Transaction(SqliteDb& db) noexcept : m_db(db) {}
    ~Transaction();
    Transaction(const Transaction&) = delete;
    Transaction& operator=(const Transaction&) = delete;

    [[nodiscard]] Status Begin();
    [[nodiscard]] Status Commit();
    void Rollback() noexcept;

private:
    SqliteDb& m_db;
    bool      m_active    = false;
};

// 嵌入的 schema 文字（由 CMake 自 schema/001_init.sql 產生，見 store/CMakeLists.txt）
[[nodiscard]] std::string_view EmbeddedSchemaSql() noexcept;

} // namespace cairn::store
