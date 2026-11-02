#include "store/SqliteDb.h"

#include <mutex>

namespace cairn::store {

namespace {

std::once_flag g_sqliteInit;

void GlobalInitOnce() noexcept
{
    std::call_once(g_sqliteInit, [] {
        // THREADSAFE=2 語意：必須在任何連線開啟、sqlite3_initialize 之前設定。
        // 若已初始化（SQLITE_MISUSE）代表別處已先開過連線 —— 無害，維持編譯時的模式。
        (void)::sqlite3_config(SQLITE_CONFIG_MULTITHREAD);
        (void)::sqlite3_initialize();
    });
}

Error SqlError(int rc, sqlite3* db, std::string_view ctx)
{
    std::string msg(ctx);
    msg.append(" rc=").append(std::to_string(rc));
    if (db) msg.append(" — ").append(::sqlite3_errmsg(db));
    return MakeError(MapSqliteError(rc), msg);
}

} // namespace

ErrorCode MapSqliteError(int rc) noexcept
{
    switch (rc & 0xFF) {
    case SQLITE_OK: return ErrorCode::Ok;
    case SQLITE_BUSY:
    case SQLITE_LOCKED: return ErrorCode::DbBusy;
    case SQLITE_CORRUPT:
    case SQLITE_NOTADB: return ErrorCode::DbCorrupt;
    case SQLITE_FULL: return ErrorCode::DbDiskFull;
    case SQLITE_CANTOPEN: return ErrorCode::DbOpenFailed;
    case SQLITE_INTERRUPT: return ErrorCode::Timeout;
    case SQLITE_IOERR: return ErrorCode::IoError;
    default: return ErrorCode::DbQueryFailed;
    }
}

// ------------------------------------------------------------------ Stmt

Stmt::~Stmt()
{
    if (m_stmt) {
        ::sqlite3_reset(m_stmt);
        ::sqlite3_clear_bindings(m_stmt);
    }
}

Stmt& Stmt::Bind(int idx, int64_t v)
{
    ::sqlite3_bind_int64(m_stmt, idx, static_cast<sqlite3_int64>(v));
    return *this;
}

Stmt& Stmt::Bind(int idx, double v)
{
    ::sqlite3_bind_double(m_stmt, idx, v);
    return *this;
}

Stmt& Stmt::BindText(int idx, std::string_view v)
{
    ::sqlite3_bind_text(m_stmt, idx, v.data(), static_cast<int>(v.size()), SQLITE_TRANSIENT);
    return *this;
}

Stmt& Stmt::BindTextStatic(int idx, std::string_view v)
{
    ::sqlite3_bind_text(m_stmt, idx, v.data(), static_cast<int>(v.size()), SQLITE_STATIC);
    return *this;
}

Stmt& Stmt::BindNull(int idx)
{
    ::sqlite3_bind_null(m_stmt, idx);
    return *this;
}

Result<bool> Stmt::Step()
{
    const int rc = ::sqlite3_step(m_stmt);
    if (rc == SQLITE_ROW) return true;
    if (rc == SQLITE_DONE) return false;
    return SqlError(rc, m_db, "sqlite3_step");
}

Status Stmt::Run()
{
    for (;;) {
        auto r = Step();
        if (!r) return r.GetError();
        if (!r.Value()) return Ok();
    }
}

int64_t Stmt::Int64(int col) const noexcept { return ::sqlite3_column_int64(m_stmt, col); }
double Stmt::Double(int col) const noexcept { return ::sqlite3_column_double(m_stmt, col); }
bool Stmt::IsNull(int col) const noexcept { return ::sqlite3_column_type(m_stmt, col) == SQLITE_NULL; }
int Stmt::ColumnCount() const noexcept { return ::sqlite3_column_count(m_stmt); }

std::string Stmt::Text(int col) const
{
    const auto* p = reinterpret_cast<const char*>(::sqlite3_column_text(m_stmt, col));
    const int   n = ::sqlite3_column_bytes(m_stmt, col);
    return p ? std::string(p, static_cast<size_t>(n)) : std::string{};
}

std::optional<int64_t> Stmt::OptInt64(int col) const noexcept
{
    if (IsNull(col)) return std::nullopt;
    return Int64(col);
}

std::optional<double> Stmt::OptDouble(int col) const noexcept
{
    if (IsNull(col)) return std::nullopt;
    return Double(col);
}

std::optional<std::string> Stmt::OptText(int col) const
{
    if (IsNull(col)) return std::nullopt;
    return Text(col);
}

// ------------------------------------------------------------------ SqliteDb

SqliteDb::SqliteDb(UniqueDb db, ConnRole role, std::filesystem::path path) noexcept
    : m_db(std::move(db)), m_role(role), m_path(std::move(path))
{
}

SqliteDb::~SqliteDb()
{
    m_cache.clear();   // finalize 全部 statement 後才 close（close_v2 也容忍，但順序清楚較好）
    if (m_db) ::sqlite3_progress_handler(m_db.get(), 0, nullptr, nullptr);
}

Result<std::unique_ptr<SqliteDb>> SqliteDb::Open(const std::filesystem::path& path, ConnRole role, Options opt)
{
    GlobalInitOnce();

    const int flags = (role == ConnRole::Writer ? (SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE) : SQLITE_OPEN_READONLY) |
                      SQLITE_OPEN_NOMUTEX;   // 每連線單執行緒（架構保證，見檔頭）
    sqlite3* raw = nullptr;
    const auto        u8s = path.u8string();   // C++20：std::u8string
    const std::string u8(u8s.begin(), u8s.end());
    const int rc = ::sqlite3_open_v2(u8.c_str(), &raw, flags, nullptr);
    UniqueDb db{raw};
    if (rc != SQLITE_OK) {
        return SqlError(rc, raw, "sqlite3_open_v2(" + u8 + ")");
    }
    ::sqlite3_extended_result_codes(raw, 1);
    ::sqlite3_busy_timeout(raw, opt.busyTimeoutMs);

    auto self = std::unique_ptr<SqliteDb>(new SqliteDb(std::move(db), role, path));
    if (role == ConnRole::Writer) {
        if (opt.applySchema) CAIRN_CHECK(self->ApplyWriterPragmasAndSchema());
    } else {
        CAIRN_CHECK(self->ApplyReaderPragmas());
    }
    ::sqlite3_progress_handler(self->m_db.get(), 1000, &SqliteDb::ProgressHandler, self.get());
    return self;
}

Status SqliteDb::ApplyWriterPragmasAndSchema()
{
    // ★ 順序有意義：auto_vacuum 必須在第一次建表「之前」（之後再改需整庫 VACUUM）
    CAIRN_CHECK(Exec("PRAGMA auto_vacuum = INCREMENTAL;"));
    CAIRN_CHECK(Exec("PRAGMA journal_mode = WAL;"));
    CAIRN_CHECK(Exec("PRAGMA synchronous = NORMAL;"));
    CAIRN_CHECK(Exec("PRAGMA foreign_keys = ON;"));
    CAIRN_CHECK(Exec("PRAGMA cache_size = -32768;"));
    CAIRN_CHECK(Exec("PRAGMA temp_store = MEMORY;"));
    CAIRN_CHECK(Exec("PRAGMA mmap_size = 268435456;"));
    CAIRN_CHECK(Exec("PRAGMA wal_autocheckpoint = 4000;"));      // SDD-02 §6.7.1
    CAIRN_CHECK(Exec("PRAGMA journal_size_limit = 67108864;"));  // 64 MB

    CAIRN_TRY(auto ver, QueryInt64("PRAGMA user_version;"));
    m_info.userVersion = static_cast<int>(ver.value_or(0));
    if (m_info.userVersion > kSchemaVersion) {
        // 較新的 schema：拒絕啟動，防止舊版服務破壞新版資料（SDD-03 §10.4）
        return MakeError(ErrorCode::MigrationFailed,
                         "database schema v" + std::to_string(m_info.userVersion) + " is newer than supported v" +
                             std::to_string(kSchemaVersion));
    }
    if (m_info.userVersion < kSchemaVersion) {
        CAIRN_TRY(auto tables, QueryInt64("SELECT COUNT(*) FROM sqlite_master WHERE type='table';"));
        m_info.created = tables.value_or(0) == 0;
        // v0/v1 → v2：001_init.sql 全部為 IF NOT EXISTS，可冪等套用。
        // （M0 之前沒有發布過 v1，因此不需要 ALTER 式遷移；之後的版本一律新增 NNN_*.sql。）
        Transaction tx{*this};
        CAIRN_CHECK(tx.Begin());
        CAIRN_CHECK(Exec(EmbeddedSchemaSql()));
        CAIRN_CHECK(Exec("PRAGMA user_version = " + std::to_string(kSchemaVersion) + ";"));
        CAIRN_CHECK(tx.Commit());
        m_info.userVersion = kSchemaVersion;
    }

    // T-09：回讀驗證 auto_vacuum（2 = INCREMENTAL）。舊庫若當初未設，只能記錄（需整庫 VACUUM 才能改）。
    CAIRN_TRY(auto av, QueryInt64("PRAGMA auto_vacuum;"));
    m_info.autoVacuumOk = av.value_or(0) == 2;
    return Ok();
}

Status SqliteDb::ApplyReaderPragmas()
{
    CAIRN_CHECK(Exec("PRAGMA query_only = 1;"));
    CAIRN_CHECK(Exec("PRAGMA cache_size = -8192;"));
    CAIRN_CHECK(Exec("PRAGMA temp_store = MEMORY;"));
    CAIRN_CHECK(Exec("PRAGMA mmap_size = 268435456;"));
    return Ok();
}

Status SqliteDb::Exec(std::string_view sql)
{
    const std::string s(sql);
    char* err = nullptr;
    const int rc = ::sqlite3_exec(m_db.get(), s.c_str(), nullptr, nullptr, &err);
    if (rc != SQLITE_OK) {
        std::string msg = err ? err : ::sqlite3_errmsg(m_db.get());
        ::sqlite3_free(err);
        return MakeError(MapSqliteError(rc), "exec: " + msg);
    }
    return Ok();
}

Result<Stmt> SqliteDb::Prepare(std::string_view sql)
{
    std::string key(sql);
    auto it = m_cache.find(key);
    if (it == m_cache.end()) {
        sqlite3_stmt* raw = nullptr;
        const int rc = ::sqlite3_prepare_v3(m_db.get(), key.c_str(), static_cast<int>(key.size()),
                                            SQLITE_PREPARE_PERSISTENT, &raw, nullptr);
        if (rc != SQLITE_OK) {
            ::sqlite3_finalize(raw);
            return SqlError(rc, m_db.get(), "prepare: " + key.substr(0, 80));
        }
        it = m_cache.emplace(std::move(key), UniqueStmt{raw}).first;
    }
    return Stmt{it->second.get(), m_db.get()};
}

Status SqliteDb::SetDurability(Durability d)
{
    if (d == m_durability) return Ok();
    CAIRN_CHECK(Exec(d == Durability::Safe ? "PRAGMA synchronous = FULL;" : "PRAGMA synchronous = NORMAL;"));
    m_durability = d;
    return Ok();
}

Status SqliteDb::Checkpoint(bool truncate)
{
    int logFrames = 0, ckpt = 0;
    const int rc = ::sqlite3_wal_checkpoint_v2(m_db.get(), nullptr,
                                               truncate ? SQLITE_CHECKPOINT_TRUNCATE : SQLITE_CHECKPOINT_PASSIVE,
                                               &logFrames, &ckpt);
    if (rc != SQLITE_OK && (rc & 0xFF) != SQLITE_BUSY) return SqlError(rc, m_db.get(), "wal_checkpoint");
    return Ok();
}

Result<bool> SqliteDb::QuickCheck()
{
    CAIRN_TRY(auto st, Prepare("PRAGMA quick_check;"));
    CAIRN_TRY(bool row, st.Step());
    if (!row) return false;
    return st.Text(0) == "ok";
}

Result<std::optional<int64_t>> SqliteDb::QueryInt64(std::string_view sql)
{
    CAIRN_TRY(auto st, Prepare(sql));
    CAIRN_TRY(bool row, st.Step());
    if (!row || st.IsNull(0)) return std::optional<int64_t>{};
    return std::optional<int64_t>{st.Int64(0)};
}

void SqliteDb::SetQueryDeadline(std::chrono::milliseconds budget) noexcept
{
    if (budget.count() <= 0) {
        m_deadlineActive = false;
        return;
    }
    m_deadline       = std::chrono::steady_clock::now() + budget;
    m_deadlineActive = true;
}

int SqliteDb::ProgressHandler(void* ctx) noexcept
{
    auto* self = static_cast<SqliteDb*>(ctx);
    if (!self->m_deadlineActive) return 0;
    return std::chrono::steady_clock::now() > self->m_deadline ? 1 : 0;   // 非 0 → SQLITE_INTERRUPT
}

// ------------------------------------------------------------------ Transaction

Transaction::~Transaction()
{
    Rollback();
}

Status Transaction::Begin()
{
    if (m_active) return Ok();
    CAIRN_CHECK(m_db.Exec("BEGIN IMMEDIATE;"));
    m_active = true;
    return Ok();
}

Status Transaction::Commit()
{
    if (!m_active) return MakeError(ErrorCode::NotInitialized, "commit without begin");
    Status st = m_db.Exec("COMMIT;");
    if (st) m_active = false;
    return st;   // COMMIT 失敗時仍為 active，解構時 ROLLBACK
}

void Transaction::Rollback() noexcept
{
    if (!m_active) return;
    m_active = false;
    (void)m_db.Exec("ROLLBACK;");
}

} // namespace cairn::store
