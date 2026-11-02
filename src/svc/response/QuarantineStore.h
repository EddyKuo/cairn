// src/svc/response/QuarantineStore.h          namespace cairn::response
// quarantine_file（SDD-03 §8.2.3、part2 §2.7）。標頭可攜；實作為 Win32（CNG + DPAPI）。
//
// 隔離區佈局（%ProgramData%\Cairn\quarantine\，ACL 僅 SYSTEM 與 Administrators，停用繼承）：
//   vault.key     隨機 32 bytes AES 金鑰，以 CryptProtectData(CRYPTPROTECT_LOCAL_MACHINE) 保護
//   {id}.q        AES-256-GCM 密文（nonce 與 tag 存在 metadata）
//   {id}.json     metadata（明文，供還原與稽核）
//
// 流程：讀原檔 → SHA-256 → 加密寫入 .q → 寫 metadata → **確認寫入成功才刪原檔**（順序絕不可顛倒）。
// 「讀→加密寫→刪」而非 MoveFile，天然支援跨磁碟區（SDD-03 §8.2.3 的被拒方案說明）。
//
// ⚠ 加密目的：防止防毒軟體／使用者誤觸執行，**非機密性**。金鑰在本機，不對抗管理員。
#pragma once
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include "base/IClock.h"
#include "base/Result.h"
#include "response/IResponseAction.h"
#include "response/ResponseTypes.h"

namespace cairn::response {

inline constexpr uint64_t kQuarantineMaxBytes = 100ull * 1024 * 1024;   // 100 MB
inline constexpr const char* kQuarantineDirSddl = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

struct QuarantineRequest {
    std::string              path;      // 原檔完整路徑（UTF-8）
    int64_t                  alertId = 0;
    std::vector<std::string> ruleIds;
    std::string              actor;
    std::optional<std::string> actionId;
};

struct QuarantineOutcome {
    QuarantineEntry entry;
    bool            originalDeleted = true;   // false = 原檔被鎖定，已排程開機時刪除（需重開機才完成）
    std::string     note;
};

struct RestoreResult {
    std::string restoredPath;           // 原路徑被佔用時為「原路徑.restored」
    bool        aclRestored = false;
};

class QuarantineStore {
public:
    // vaultDir：正式為 %ProgramData%\Cairn\quarantine；測試可給暫存目錄。
    // applyVaultAcl=false 供非管理員測試（套用僅 SY/BA 的 ACL 後一般使用者讀不回來）。
    QuarantineStore(std::filesystem::path vaultDir, const IClock& clock, bool applyVaultAcl = true,
                    uint64_t maxBytes = kQuarantineMaxBytes);
    ~QuarantineStore();
    QuarantineStore(const QuarantineStore&) = delete;
    QuarantineStore& operator=(const QuarantineStore&) = delete;

    // 建立目錄（含 ACL）與載入／產生金鑰。可重複呼叫。
    [[nodiscard]] Status Init();

    // 不改動任何東西：檢查檔案存在、大小、計算 SHA-256（供 Prepare 的影響清單）
    struct FileProbe {
        bool        exists = false;
        uint64_t    size = 0;
        std::string sha256;
        uint32_t    win32Error = 0;
        std::string reason;
    };
    [[nodiscard]] FileProbe Probe(const std::string& path) const;

    // 檔案已不存在 → 回傳 NotFound（呼叫端轉為 ok=true "already gone"）
    // 檔案被鎖定 → QuarantineIoFailed，context 含 "sharing violation"（先 suspend 持有者）
    [[nodiscard]] Result<QuarantineOutcome> Quarantine(const QuarantineRequest& req);

    // 解密 → 比對 SHA-256（不符 RestoreHashMismatch）→ 寫回原路徑 → 復原原始 ACL → 刪除隔離檔
    [[nodiscard]] Result<RestoreResult> Restore(const std::string& quarantineId);

    [[nodiscard]] Result<QuarantineEntry> Get(const std::string& quarantineId) const;
    [[nodiscard]] std::vector<QuarantineEntry> List() const;

    [[nodiscard]] const std::filesystem::path& VaultDir() const noexcept { return m_dir; }

private:
    struct Impl;
    std::filesystem::path m_dir;
    const IClock&         m_clock;
    bool                  m_applyAcl;
    uint64_t              m_maxBytes;
    Impl*                 m_impl = nullptr;   // 持有金鑰（以 SecureZeroMemory 清除）
};

// IResponseAction 轉接：quarantine_file 動作
class QuarantineFileAction final : public IResponseAction {
public:
    explicit QuarantineFileAction(QuarantineStore& store) : m_store(store) {}
    [[nodiscard]] model::ActionKind Kind() const noexcept override { return model::ActionKind::QuarantineFile; }
    [[nodiscard]] Result<ActionImpact> Prepare(const ActionContext& ctx) override;
    [[nodiscard]] std::vector<TargetOutcome> Execute(const ActionContext& ctx, ActionRecord& record) override;
    [[nodiscard]] Result<std::vector<TargetOutcome>> Revert(const ActionRecord& record) override;

private:
    QuarantineStore& m_store;
};

// 隔離 id 只允許 hex 與 '-'（防目錄逃逸）
[[nodiscard]] bool IsValidQuarantineId(std::string_view id) noexcept;

} // namespace cairn::response
