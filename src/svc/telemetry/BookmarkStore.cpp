#include "telemetry/BookmarkStore.h"

#include <fstream>
#include <iterator>
#include <system_error>

namespace cairn::telemetry {

namespace {
// 書籤檔名只允許安全字元（name 來自程式內常數，此處僅為防呆）
std::string SanitizeName(std::string_view name)
{
    std::string out;
    out.reserve(name.size());
    for (char c : name) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' ||
                        c == '_' || c == '.';
        out.push_back(ok ? c : '_');
    }
    return out.empty() ? std::string("default") : out;
}
} // namespace

BookmarkStore::BookmarkStore(std::filesystem::path dir) : m_dir(std::move(dir))
{
    std::error_code ec;
    std::filesystem::create_directories(m_dir, ec);
}

std::filesystem::path BookmarkStore::PathFor(std::string_view name) const
{
    return m_dir / (SanitizeName(name) + ".xml");
}

std::optional<std::string> BookmarkStore::Load(std::string_view name) const
{
    std::ifstream in(PathFor(name), std::ios::binary);
    if (!in) return std::nullopt;
    std::string s((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (s.empty() || s.find("<BookmarkList") == std::string::npos) return std::nullopt;   // 半個或損毀的書籤
    return s;
}

Status BookmarkStore::Save(std::string_view name, std::string_view xml) const
{
    const auto target = PathFor(name);
    auto tmp = target;
    tmp += ".tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) return MakeError(ErrorCode::IoError, "bookmark: open tmp failed");
        out.write(xml.data(), static_cast<std::streamsize>(xml.size()));
        out.flush();
        if (!out) return MakeError(ErrorCode::IoError, "bookmark: write failed");
    }
    std::error_code ec;
    std::filesystem::rename(tmp, target, ec);   // Windows 上 rename 覆蓋既有檔（MoveFileExW REPLACE_EXISTING）
    if (ec) return MakeError(ErrorCode::IoError, "bookmark: rename failed: " + ec.message());
    return Ok();
}

void BookmarkStore::Remove(std::string_view name) const noexcept
{
    std::error_code ec;
    std::filesystem::remove(PathFor(name), ec);
}

} // namespace cairn::telemetry
