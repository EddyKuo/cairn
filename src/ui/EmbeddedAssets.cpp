// EmbeddedAssets.cpp —— 見 EmbeddedAssets.h
#include "pch.h"

#include "EmbeddedAssets.h"

namespace cairn::ui {

namespace {
struct AssetEntry {
    const wchar_t* path;
    int            id;
};

// 由 cmake/EmbedAssets.cmake 於建置期產生
constexpr AssetEntry kAssets[] = {
#include "assets_table.inc"
};

bool EndsWithI(std::wstring_view s, std::wstring_view suffix)
{
    if (s.size() < suffix.size()) return false;
    return _wcsnicmp(s.data() + s.size() - suffix.size(), suffix.data(), suffix.size()) == 0;
}
} // namespace

std::wstring EmbeddedAssets::MimeFor(std::wstring_view p)
{
    if (EndsWithI(p, L".html")) return L"text/html; charset=utf-8";
    if (EndsWithI(p, L".js") || EndsWithI(p, L".mjs")) return L"text/javascript; charset=utf-8";
    if (EndsWithI(p, L".css")) return L"text/css; charset=utf-8";
    if (EndsWithI(p, L".json")) return L"application/json; charset=utf-8";
    if (EndsWithI(p, L".svg")) return L"image/svg+xml";
    if (EndsWithI(p, L".png")) return L"image/png";
    if (EndsWithI(p, L".ico")) return L"image/x-icon";
    if (EndsWithI(p, L".woff2")) return L"font/woff2";
    if (EndsWithI(p, L".woff")) return L"font/woff";
    if (EndsWithI(p, L".txt")) return L"text/plain; charset=utf-8";
    return L"application/octet-stream";
}

size_t EmbeddedAssets::Count() const noexcept
{
    return std::size(kAssets);
}

bool EmbeddedAssets::Find(std::wstring_view path, AssetBlob& out) const
{
    if (const auto q = path.find_first_of(L"?#"); q != std::wstring_view::npos) path = path.substr(0, q);
    if (path.empty() || path == L"/") path = L"/index.html";
    if (path.find(L"..") != std::wstring_view::npos) return false;

    for (const auto& e : kAssets) {
        if (path == e.path) {
            HRSRC res = ::FindResourceW(nullptr, MAKEINTRESOURCEW(e.id), RT_RCDATA);
            if (!res) return false;
            HGLOBAL h = ::LoadResource(nullptr, res);
            if (!h) return false;
            out.data = ::LockResource(h);
            out.size = ::SizeofResource(nullptr, res);
            out.mime = MimeFor(path);
            return out.data != nullptr;
        }
    }
    return false;
}

} // namespace cairn::ui
