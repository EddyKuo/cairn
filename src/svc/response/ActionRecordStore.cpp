#include "response/ActionRecordStore.h"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <fstream>
#include <sstream>

#include <nlohmann/json.hpp>

#include "response/ResponseJson.h"

namespace cairn::response {

namespace fs = std::filesystem;

bool IsValidActionId(std::string_view id) noexcept
{
    if (id.empty() || id.size() > 64) return false;
    for (char c : id) {
        const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
        if (!ok) return false;
    }
    return true;
}

ActionRecordStore::ActionRecordStore(fs::path dir) : m_dir(std::move(dir)) {}

Status ActionRecordStore::EnsureDir()
{
    std::error_code ec;
    fs::create_directories(m_dir, ec);
    if (ec) return MakeError(ErrorCode::IoError, "create actions dir: " + ec.message());
    return Ok();
}

fs::path ActionRecordStore::PathOf(const std::string& actionId) const
{
    return m_dir / (actionId + ".json");
}

std::string ActionRecordStore::NextActionId(int64_t alertId) const
{
    char prefix[48];
    std::snprintf(prefix, sizeof(prefix), "ACT-%04lld-", static_cast<long long>(alertId));
    int maxSeq = 0;
    std::error_code ec;
    for (fs::directory_iterator it{m_dir, ec}, end; !ec && it != end; it.increment(ec)) {
        const auto name = it->path().stem().string();
        if (name.rfind(prefix, 0) == 0) {
            const int seq = std::atoi(name.c_str() + std::char_traits<char>::length(prefix));
            if (seq > maxSeq) maxSeq = seq;
        }
    }
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%s%02d", prefix, maxSeq + 1);
    return buf;
}

Status ActionRecordStore::Save(const ActionRecord& r)
{
    if (!IsValidActionId(r.actionId)) return MakeError(ErrorCode::InvalidArgument, "invalid action id");
    CAIRN_CHECK(EnsureDir());
    const auto finalPath = PathOf(r.actionId);
    auto tmpPath = finalPath;
    tmpPath += ".tmp";
    {
        std::ofstream out(tmpPath, std::ios::binary | std::ios::trunc);
        if (!out) return MakeError(ErrorCode::IoError, "open action record for write");
        out << ToJson(r).dump(2);
        out.flush();
        if (!out) return MakeError(ErrorCode::IoError, "write action record");
    }
    std::error_code ec;
    fs::rename(tmpPath, finalPath, ec);   // MSVC 實作為 MoveFileExW(MOVEFILE_REPLACE_EXISTING)
    if (ec) {
        fs::remove(tmpPath, ec);
        return MakeError(ErrorCode::IoError, "rename action record");
    }
    return Ok();
}

Result<ActionRecord> ActionRecordStore::Load(const std::string& actionId) const
{
    if (!IsValidActionId(actionId)) return MakeReject(ErrorCode::NotFound, "ACTION_NOT_FOUND", "invalid action id");
    std::ifstream in(PathOf(actionId), std::ios::binary);
    if (!in) return MakeReject(ErrorCode::NotFound, "ACTION_NOT_FOUND", actionId);
    std::stringstream ss;
    ss << in.rdbuf();
    const auto j = nlohmann::json::parse(ss.str(), nullptr, /*allow_exceptions=*/false);
    ActionRecord r;
    if (j.is_discarded() || !FromJson(j, r)) return MakeError(ErrorCode::IoError, "corrupt action record " + actionId);
    return r;
}

std::vector<ActionRecord> ActionRecordStore::List() const
{
    std::vector<ActionRecord> out;
    std::error_code ec;
    for (fs::directory_iterator it{m_dir, ec}, end; !ec && it != end; it.increment(ec)) {
        if (it->path().extension() != ".json") continue;
        auto r = Load(it->path().stem().string());
        if (r) out.push_back(std::move(r).Value());
    }
    return out;
}

Result<ActionRecord> ActionRecordStore::FindByAuditId(int64_t auditId) const
{
    for (auto& r : List()) {
        if ((r.auditId && *r.auditId == auditId) || (r.revertAuditId && *r.revertAuditId == auditId)) return r;
    }
    return MakeReject(ErrorCode::NotFound, "ACTION_NOT_FOUND", "no action for audit id " + std::to_string(auditId));
}

Result<ActionRecord> ActionRecordStore::Resolve(const std::string& key) const
{
    if (!key.empty() && key.size() <= 18 && key.find_first_not_of("0123456789") == std::string::npos) {
        return FindByAuditId(std::stoll(key));
    }
    return Load(key);
}

} // namespace cairn::response
