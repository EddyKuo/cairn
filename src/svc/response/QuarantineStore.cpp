// src/svc/response/QuarantineStore.cpp        Win32 實作（CNG AES-256-GCM + DPAPI）
#include "response/QuarantineStore.h"

#include <windows.h>
#include <aclapi.h>
#include <bcrypt.h>
#include <sddl.h>
#include <wincrypt.h>
#include <dpapi.h>

#include <wil/resource.h>

#include <algorithm>
#include <fstream>
#include <sstream>

#include <nlohmann/json.hpp>

#include "common/WinUtil.h"
#include "response/ResponseJson.h"
#include "response/Sha256.h"

namespace cairn::response {

namespace fs = std::filesystem;

namespace {

constexpr ULONG kKeyBytes   = 32;
constexpr ULONG kNonceBytes = 12;
constexpr ULONG kTagBytes   = 16;

// ---- CNG RAII ----
struct AlgHandle {
    BCRYPT_ALG_HANDLE h = nullptr;
    ~AlgHandle() { if (h) ::BCryptCloseAlgorithmProvider(h, 0); }
};
struct KeyHandle {
    BCRYPT_KEY_HANDLE h = nullptr;
    ~KeyHandle() { if (h) ::BCryptDestroyKey(h); }
};

Error NtError(std::string_view what, NTSTATUS st)
{
    return MakeWin32Error(ErrorCode::QuarantineIoFailed, static_cast<uint32_t>(st),
                          std::string(what) + " failed (NTSTATUS)");
}

Status GenRandom(void* buf, ULONG len)
{
    const NTSTATUS st = ::BCryptGenRandom(nullptr, static_cast<PUCHAR>(buf), len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS(st)) return NtError("BCryptGenRandom", st);
    return Ok();
}

// 以 AES-256-GCM 加密或解密（就地輸出到 out）
Status AesGcm(bool encrypt, const std::vector<uint8_t>& key, const uint8_t* nonce, uint8_t* tag,
              const std::vector<uint8_t>& in, std::vector<uint8_t>& out)
{
    AlgHandle alg;
    NTSTATUS  st = ::BCryptOpenAlgorithmProvider(&alg.h, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(st)) return NtError("BCryptOpenAlgorithmProvider", st);
    st = ::BCryptSetProperty(alg.h, BCRYPT_CHAINING_MODE,
                             reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
                             static_cast<ULONG>(sizeof(BCRYPT_CHAIN_MODE_GCM)), 0);
    if (!BCRYPT_SUCCESS(st)) return NtError("BCryptSetProperty(GCM)", st);

    KeyHandle k;
    st = ::BCryptGenerateSymmetricKey(alg.h, &k.h, nullptr, 0, const_cast<PUCHAR>(key.data()),
                                      static_cast<ULONG>(key.size()), 0);
    if (!BCRYPT_SUCCESS(st)) return NtError("BCryptGenerateSymmetricKey", st);

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = const_cast<PUCHAR>(nonce);
    info.cbNonce = kNonceBytes;
    info.pbTag   = tag;
    info.cbTag   = kTagBytes;

    out.resize(in.size());
    ULONG written = 0;
    // GCM 為串流模式：密文長度 = 明文長度，不需 padding
    PUCHAR inPtr  = in.empty() ? nullptr : const_cast<PUCHAR>(in.data());
    PUCHAR outPtr = out.empty() ? nullptr : out.data();
    if (encrypt) {
        st = ::BCryptEncrypt(k.h, inPtr, static_cast<ULONG>(in.size()), &info, nullptr, 0, outPtr,
                             static_cast<ULONG>(out.size()), &written, 0);
    } else {
        st = ::BCryptDecrypt(k.h, inPtr, static_cast<ULONG>(in.size()), &info, nullptr, 0, outPtr,
                             static_cast<ULONG>(out.size()), &written, 0);
    }
    if (!BCRYPT_SUCCESS(st)) {
        // STATUS_AUTH_TAG_MISMATCH (0xC000A002)：隔離區被竄改
        return NtError(encrypt ? "BCryptEncrypt" : "BCryptDecrypt (tag mismatch = vault tampered)", st);
    }
    out.resize(written);
    return Ok();
}

Result<std::vector<uint8_t>> ReadAll(const fs::path& path, uint64_t maxBytes, uint64_t* sizeOut = nullptr)
{
    wil::unique_hfile f{::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                      nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr)};
    if (!f) {
        const DWORD err = ::GetLastError();
        if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND)
            return MakeWin32Error(ErrorCode::NotFound, err, "file not found");
        if (err == ERROR_SHARING_VIOLATION || err == ERROR_LOCK_VIOLATION)
            return MakeWin32Error(ErrorCode::QuarantineIoFailed, err,
                                  "sharing violation — file is locked; suspend the holder first");
        return svc::Win32Error(ErrorCode::QuarantineIoFailed, "CreateFileW(read)", err);
    }
    LARGE_INTEGER size{};
    if (!::GetFileSizeEx(f.get(), &size)) return svc::Win32Error(ErrorCode::QuarantineIoFailed, "GetFileSizeEx");
    const auto total = static_cast<uint64_t>(size.QuadPart);
    if (sizeOut) *sizeOut = total;
    if (total > maxBytes)
        return MakeError(ErrorCode::QuarantineIoFailed, "file exceeds quarantine size limit (" +
                                                            std::to_string(maxBytes / (1024 * 1024)) + " MB)");
    std::vector<uint8_t> buf(static_cast<size_t>(total));
    uint64_t done = 0;
    while (done < total) {
        DWORD got = 0;
        const DWORD want = static_cast<DWORD>(std::min<uint64_t>(total - done, 64ull * 1024 * 1024));
        if (!::ReadFile(f.get(), buf.data() + done, want, &got, nullptr))
            return svc::Win32Error(ErrorCode::QuarantineIoFailed, "ReadFile");
        if (got == 0) break;
        done += got;
    }
    buf.resize(static_cast<size_t>(done));
    return buf;
}

Status WriteAllNew(const fs::path& path, const uint8_t* data, size_t len)
{
    wil::unique_hfile f{::CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr)};
    if (!f) return svc::Win32Error(ErrorCode::QuarantineIoFailed, "CreateFileW(write)");
    size_t done = 0;
    while (done < len) {
        DWORD put = 0;
        const DWORD want = static_cast<DWORD>(std::min<size_t>(len - done, 64u * 1024 * 1024));
        if (!::WriteFile(f.get(), data + done, want, &put, nullptr))
            return svc::Win32Error(ErrorCode::QuarantineIoFailed, "WriteFile");
        done += put;
    }
    if (!::FlushFileBuffers(f.get())) return svc::Win32Error(ErrorCode::QuarantineIoFailed, "FlushFileBuffers");
    return Ok();
}

// 盡力啟用特權（還原原始擁有者需要 SeRestorePrivilege）
void TryEnablePrivilege(const wchar_t* name) noexcept
{
    HANDLE tok = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) return;
    wil::unique_handle token{tok};
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (::LookupPrivilegeValueW(nullptr, name, &tp.Privileges[0].Luid))
        ::AdjustTokenPrivileges(token.get(), FALSE, &tp, sizeof(tp), nullptr, nullptr);
}

std::string GetSddl(const fs::path& path)
{
    PSECURITY_DESCRIPTOR psd = nullptr;
    const SECURITY_INFORMATION si = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    if (::GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT, si, nullptr, nullptr, nullptr, nullptr, &psd) !=
        ERROR_SUCCESS)
        return {};
    wil::unique_hlocal sdHolder{psd};
    LPWSTR str = nullptr;
    if (!::ConvertSecurityDescriptorToStringSecurityDescriptorW(psd, SDDL_REVISION_1, si, &str, nullptr)) return {};
    wil::unique_hlocal strHolder{str};
    return svc::WideToUtf8(str);
}

// 套用 SDDL 到檔案／目錄。includeOwner=false 時只設 DACL。
DWORD ApplySddl(const fs::path& path, const std::string& sddl, bool includeOwner)
{
    PSECURITY_DESCRIPTOR psd = nullptr;
    if (!::ConvertStringSecurityDescriptorToSecurityDescriptorW(svc::Utf8ToWide(sddl).c_str(), SDDL_REVISION_1, &psd,
                                                                nullptr))
        return ::GetLastError();
    wil::unique_hlocal sdHolder{psd};

    PSID owner = nullptr, group = nullptr;
    PACL dacl = nullptr;
    BOOL present = FALSE, defaulted = FALSE;
    ::GetSecurityDescriptorDacl(psd, &present, &dacl, &defaulted);
    ::GetSecurityDescriptorOwner(psd, &owner, &defaulted);
    ::GetSecurityDescriptorGroup(psd, &group, &defaulted);
    SECURITY_DESCRIPTOR_CONTROL ctrl = 0;
    DWORD rev = 0;
    ::GetSecurityDescriptorControl(psd, &ctrl, &rev);

    SECURITY_INFORMATION si = 0;
    if (present) {
        si |= DACL_SECURITY_INFORMATION;
        si |= (ctrl & SE_DACL_PROTECTED) ? PROTECTED_DACL_SECURITY_INFORMATION : UNPROTECTED_DACL_SECURITY_INFORMATION;
    }
    if (includeOwner && owner) si |= OWNER_SECURITY_INFORMATION;
    if (includeOwner && group) si |= GROUP_SECURITY_INFORMATION;
    std::wstring wpath = path.wstring();
    return ::SetNamedSecurityInfoW(wpath.data(), SE_FILE_OBJECT, si, includeOwner ? owner : nullptr,
                                   includeOwner ? group : nullptr, present ? dacl : nullptr, nullptr);
}

std::string NewQuarantineId()
{
    uint8_t b[16]{};
    (void)GenRandom(b, sizeof(b));
    static constexpr char kHex[] = "0123456789abcdef";
    std::string s;
    for (int i = 0; i < 16; ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) s.push_back('-');
        s.push_back(kHex[b[i] >> 4]);
        s.push_back(kHex[b[i] & 0x0F]);
    }
    return s;
}

Status WriteJsonFile(const fs::path& path, const nlohmann::json& j)
{
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) return MakeError(ErrorCode::QuarantineIoFailed, "open metadata for write");
    out << j.dump(2);
    out.flush();
    if (!out) return MakeError(ErrorCode::QuarantineIoFailed, "write metadata");
    return Ok();
}

} // namespace

bool IsValidQuarantineId(std::string_view id) noexcept
{
    if (id.empty() || id.size() > 64) return false;
    for (char c : id)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || c == '-')) return false;
    return true;
}

struct QuarantineStore::Impl {
    std::vector<uint8_t> key;
    ~Impl()
    {
        if (!key.empty()) ::SecureZeroMemory(key.data(), key.size());
    }
};

QuarantineStore::QuarantineStore(fs::path vaultDir, const IClock& clock, bool applyVaultAcl, uint64_t maxBytes)
    : m_dir(std::move(vaultDir)), m_clock(clock), m_applyAcl(applyVaultAcl), m_maxBytes(maxBytes), m_impl(new Impl)
{
}

QuarantineStore::~QuarantineStore()
{
    delete m_impl;
}

Status QuarantineStore::Init()
{
    std::error_code ec;
    fs::create_directories(m_dir, ec);
    if (ec) return MakeError(ErrorCode::QuarantineIoFailed, "create quarantine dir: " + ec.message());
    if (m_applyAcl) {
        // 僅 SYSTEM 與 Administrators，停用繼承（防一般使用者讀取隔離樣本）
        if (const DWORD err = ApplySddl(m_dir, kQuarantineDirSddl, /*includeOwner=*/false); err != ERROR_SUCCESS)
            return MakeWin32Error(ErrorCode::QuarantineIoFailed, err, "apply quarantine dir ACL");
    }
    if (!m_impl->key.empty()) return Ok();

    const fs::path keyPath = m_dir / L"vault.key";
    if (fs::exists(keyPath, ec)) {
        auto blob = ReadAll(keyPath, 64 * 1024);
        if (!blob) return blob.GetError();
        DATA_BLOB in{static_cast<DWORD>(blob.Value().size()), blob.Value().data()};
        DATA_BLOB out{};
        if (!::CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out))
            return svc::Win32Error(ErrorCode::QuarantineIoFailed, "CryptUnprotectData(vault.key)");
        wil::unique_hlocal outHolder{out.pbData};
        if (out.cbData != kKeyBytes) {
            ::SecureZeroMemory(out.pbData, out.cbData);
            return MakeError(ErrorCode::QuarantineIoFailed, "vault.key has unexpected length");
        }
        m_impl->key.assign(out.pbData, out.pbData + out.cbData);
        ::SecureZeroMemory(out.pbData, out.cbData);
        return Ok();
    }

    std::vector<uint8_t> key(kKeyBytes);
    CAIRN_CHECK(GenRandom(key.data(), kKeyBytes));
    DATA_BLOB in{kKeyBytes, key.data()};
    DATA_BLOB out{};
    // 服務以 LocalSystem 執行，無使用者 profile 可綁 → 機器範圍
    if (!::CryptProtectData(&in, L"Cairn quarantine vault key", nullptr, nullptr, nullptr,
                            CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN, &out)) {
        ::SecureZeroMemory(key.data(), key.size());
        return svc::Win32Error(ErrorCode::QuarantineIoFailed, "CryptProtectData(vault.key)");
    }
    wil::unique_hlocal outHolder{out.pbData};
    const auto st = WriteAllNew(keyPath, out.pbData, out.cbData);
    if (!st) {
        ::SecureZeroMemory(key.data(), key.size());
        return st.GetError();
    }
    m_impl->key = std::move(key);
    return Ok();
}

QuarantineStore::FileProbe QuarantineStore::Probe(const std::string& path) const
{
    FileProbe p;
    uint64_t size = 0;
    auto data = ReadAll(svc::Utf8ToWide(path), m_maxBytes, &size);
    p.size = size;
    if (!data) {
        p.win32Error = data.GetError().win32;
        p.exists = data.Code() != ErrorCode::NotFound;
        p.reason = data.GetError().context;
        return p;
    }
    p.exists = true;
    p.sha256 = Sha256::HexOf(data.Value().data(), data.Value().size());
    return p;
}

Result<QuarantineOutcome> QuarantineStore::Quarantine(const QuarantineRequest& req)
{
    if (m_impl->key.empty()) CAIRN_CHECK(Init());
    const fs::path original = svc::Utf8ToWide(req.path);

    // 1) 讀原檔（含大小上限檢查）
    uint64_t size = 0;
    CAIRN_TRY(auto plain, ReadAll(original, m_maxBytes, &size));

    QuarantineEntry e;
    e.quarantineId  = NewQuarantineId();
    e.originalPath  = req.path;
    e.originalSddl  = GetSddl(original);
    e.sha256        = Sha256::HexOf(plain.data(), plain.size());
    e.sizeBytes     = plain.size();
    e.quarantinedTs = m_clock.NowMs();
    e.alertId       = req.alertId;
    e.ruleIds       = req.ruleIds;
    e.actor         = req.actor;
    e.actionId      = req.actionId;

    // 2) 加密（每檔獨立隨機 nonce；GCM 的 nonce 重用會完全破壞安全性）
    uint8_t nonce[kNonceBytes]{};
    uint8_t tag[kTagBytes]{};
    CAIRN_CHECK(GenRandom(nonce, kNonceBytes));
    std::vector<uint8_t> cipher;
    const auto encSt = AesGcm(true, m_impl->key, nonce, tag, plain, cipher);
    ::SecureZeroMemory(plain.data(), plain.size());
    if (!encSt) return encSt.GetError();
    e.nonceB64 = Base64Encode(nonce, kNonceBytes);
    e.tagB64   = Base64Encode(tag, kTagBytes);

    // 3) 寫入隔離區：.q → .json；任一失敗即清除殘留，原檔不動
    const fs::path qPath = m_dir / (svc::Utf8ToWide(e.quarantineId) + L".q");
    const fs::path mPath = m_dir / (svc::Utf8ToWide(e.quarantineId) + L".json");
    if (auto st = WriteAllNew(qPath, cipher.data(), cipher.size()); !st) {
        std::error_code ec;
        fs::remove(qPath, ec);
        return st.GetError();
    }
    if (auto st = WriteJsonFile(mPath, ToJson(e)); !st) {
        std::error_code ec;
        fs::remove(qPath, ec);
        fs::remove(mPath, ec);
        return st.GetError();
    }

    // 4) 確認寫入成功後才刪除原檔
    QuarantineOutcome outcome;
    outcome.entry = e;
    if (!::DeleteFileW(original.c_str())) {
        DWORD err = ::GetLastError();
        if (err == ERROR_ACCESS_DENIED) {
            // 唯讀屬性會讓 DeleteFile 回 ACCESS_DENIED：清屬性後重試
            ::SetFileAttributesW(original.c_str(), FILE_ATTRIBUTE_NORMAL);
            if (::DeleteFileW(original.c_str())) err = ERROR_SUCCESS;
            else err = ::GetLastError();
        }
        if (err == ERROR_SHARING_VIOLATION || err == ERROR_LOCK_VIOLATION) {
            // 原檔仍被持有：排程開機時刪除，隔離副本保留（需重開機才完成）
            if (::MoveFileExW(original.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT)) {
                outcome.originalDeleted = false;
                outcome.note = "original file locked; deletion scheduled at reboot（需重開機才完成）";
                return outcome;
            }
            err = ::GetLastError();
        }
        if (err != ERROR_SUCCESS && err != ERROR_FILE_NOT_FOUND) {
            // 刪不掉原檔：撤銷隔離副本，維持「要嘛全成、要嘛不動」
            std::error_code ec;
            fs::remove(qPath, ec);
            fs::remove(mPath, ec);
            return svc::Win32Error(ErrorCode::QuarantineIoFailed, "DeleteFileW(original)", err);
        }
    }
    return outcome;
}

Result<QuarantineEntry> QuarantineStore::Get(const std::string& quarantineId) const
{
    if (!IsValidQuarantineId(quarantineId)) return MakeError(ErrorCode::InvalidArgument, "invalid quarantine id");
    std::ifstream in(m_dir / (svc::Utf8ToWide(quarantineId) + L".json"), std::ios::binary);
    if (!in) return MakeError(ErrorCode::NotFound, "quarantine metadata not found: " + quarantineId);
    std::stringstream ss;
    ss << in.rdbuf();
    const auto j = nlohmann::json::parse(ss.str(), nullptr, false);
    QuarantineEntry e;
    if (j.is_discarded() || !FromJson(j, e)) return MakeError(ErrorCode::QuarantineIoFailed, "corrupt metadata");
    return e;
}

std::vector<QuarantineEntry> QuarantineStore::List() const
{
    std::vector<QuarantineEntry> out;
    std::error_code ec;
    for (fs::directory_iterator it{m_dir, ec}, end; !ec && it != end; it.increment(ec)) {
        if (it->path().extension() != L".json") continue;
        auto e = Get(svc::WideToUtf8(it->path().stem().wstring()));
        if (e) out.push_back(std::move(e).Value());
    }
    return out;
}

Result<RestoreResult> QuarantineStore::Restore(const std::string& quarantineId)
{
    if (m_impl->key.empty()) CAIRN_CHECK(Init());
    CAIRN_TRY(auto e, Get(quarantineId));

    const fs::path qPath = m_dir / (svc::Utf8ToWide(e.quarantineId) + L".q");
    const fs::path mPath = m_dir / (svc::Utf8ToWide(e.quarantineId) + L".json");
    CAIRN_TRY(auto cipher, ReadAll(qPath, m_maxBytes + 1024));

    std::vector<uint8_t> nonce, tag;
    if (!Base64Decode(e.nonceB64, nonce) || nonce.size() != kNonceBytes || !Base64Decode(e.tagB64, tag) ||
        tag.size() != kTagBytes)
        return MakeError(ErrorCode::QuarantineIoFailed, "corrupt nonce/tag in metadata");

    std::vector<uint8_t> plain;
    CAIRN_CHECK(AesGcm(false, m_impl->key, nonce.data(), tag.data(), cipher, plain));

    // 雜湊比對：解密成功（tag 驗過）但內容與隔離時記錄的雜湊不符 → 拒絕還原
    if (Sha256::HexOf(plain.data(), plain.size()) != e.sha256) {
        ::SecureZeroMemory(plain.data(), plain.size());
        return MakeError(ErrorCode::RestoreHashMismatch, "restored content hash mismatch: " + e.quarantineId);
    }

    RestoreResult rr;
    fs::path target = svc::Utf8ToWide(e.originalPath);
    std::error_code ec;
    if (fs::exists(target, ec)) target += L".restored";   // 原路徑已被佔用
    fs::create_directories(target.parent_path(), ec);
    const auto wst = WriteAllNew(target, plain.data(), plain.size());
    ::SecureZeroMemory(plain.data(), plain.size());
    if (!wst) return wst.GetError();
    rr.restoredPath = svc::WideToUtf8(target.wstring());

    // 復原原始 ACL（否則使用者會回報「還原後檔案打不開」）
    if (!e.originalSddl.empty()) {
        TryEnablePrivilege(SE_RESTORE_NAME);
        DWORD err = ApplySddl(target, e.originalSddl, /*includeOwner=*/true);
        if (err != ERROR_SUCCESS) err = ApplySddl(target, e.originalSddl, /*includeOwner=*/false);
        rr.aclRestored = err == ERROR_SUCCESS;
    }

    fs::remove(qPath, ec);
    fs::remove(mPath, ec);
    return rr;
}

// ------------------------------------------------------------
// QuarantineFileAction
// ------------------------------------------------------------
Result<ActionImpact> QuarantineFileAction::Prepare(const ActionContext& ctx)
{
    if (!ctx.target || !ctx.target->filePath || ctx.target->filePath->empty())
        return MakeReject(ErrorCode::InvalidArgument, "INVALID_TARGET", "quarantine_file requires a file path");
    const auto& path = *ctx.target->filePath;
    const auto probe = m_store.Probe(path);

    ImpactItem it;
    it.key        = "file:" + ToLower(path);
    it.label      = BaseNameLower(path);
    it.filePath   = path;
    it.fileSize   = probe.size;
    it.reachable  = probe.exists;
    if (!probe.sha256.empty()) it.fileSha256 = probe.sha256;
    if (!probe.exists) {
        it.warning = "檔案已不存在";
        it.warningLevel = "medium";
    } else if (probe.size > kQuarantineMaxBytes) {
        it.warning = "檔案超過 100 MB 上限，隔離將被拒絕";
        it.warningLevel = "high";
    } else if (probe.sha256.empty()) {
        it.warning = "檔案目前無法讀取（可能被鎖定），建議先暫停持有程序";
        it.warningLevel = "high";
    }
    ActionImpact impact;
    impact.items.push_back(std::move(it));
    impact.totalCount = 1;
    impact.warnings.push_back("隔離區加密的目的是防止誤觸執行，非機密性保護");
    return impact;
}

std::vector<TargetOutcome> QuarantineFileAction::Execute(const ActionContext& ctx, ActionRecord& record)
{
    std::vector<TargetOutcome> outcomes;
    if (!ctx.target || !ctx.target->filePath) return outcomes;
    const auto& path = *ctx.target->filePath;
    TargetOutcome o{"file:" + ToLower(path), BaseNameLower(path), false, 0, {}};

    QuarantineRequest req;
    req.path     = path;
    req.alertId  = ctx.alertId;
    req.actor    = ctx.actor;
    req.actionId = record.actionId;
    auto r = m_store.Quarantine(req);
    if (!r) {
        if (r.Code() == ErrorCode::NotFound) {
            o.ok = true;
            o.reason = "already gone";
        } else {
            o.win32Error = r.GetError().win32;
            o.reason = r.GetError().context;
        }
    } else {
        record.quarantineIds.push_back(r.Value().entry.quarantineId);
        o.ok = r.Value().originalDeleted;
        o.reason = r.Value().originalDeleted ? "quarantined (" + r.Value().entry.quarantineId + ")" : r.Value().note;
    }
    outcomes.push_back(std::move(o));
    return outcomes;
}

Result<std::vector<TargetOutcome>> QuarantineFileAction::Revert(const ActionRecord& record)
{
    std::vector<TargetOutcome> outcomes;
    for (const auto& id : record.quarantineIds) {
        TargetOutcome o{"quarantine:" + id, id, false, 0, {}};
        if (auto meta = m_store.Get(id)) {
            o.key   = "file:" + ToLower(meta.Value().originalPath);
            o.label = BaseNameLower(meta.Value().originalPath);
        }
        auto r = m_store.Restore(id);
        if (r) {
            o.ok = true;
            o.reason = "restored to " + r.Value().restoredPath + (r.Value().aclRestored ? "" : "（原始 ACL 未能完全復原）");
        } else {
            o.win32Error = r.GetError().win32;
            o.reason = r.GetError().context;
        }
        outcomes.push_back(std::move(o));
    }
    return outcomes;
}

} // namespace cairn::response
