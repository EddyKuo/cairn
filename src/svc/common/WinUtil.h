// src/svc/common/WinUtil.h                    namespace cairn::svc
// svc 層共用的 Win32 小工具（header-only，避免多一個靜態庫）。
// 只能被 src/svc 與 src/ui 引用；src/core 不得 include（part4 §4.2）。
#pragma once
#ifndef _WIN32
#error "src/svc 僅支援 Windows"
#endif

#include <windows.h>
#include <shlobj.h>

#include <filesystem>
#include <string>
#include <string_view>

#include "base/Result.h"

namespace cairn::svc {

[[nodiscard]] inline std::wstring Utf8ToWide(std::string_view s)
{
    if (s.empty()) return {};
    const int n = ::MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring out(static_cast<size_t>(n), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n);
    return out;
}

[[nodiscard]] inline std::string WideToUtf8(std::wstring_view s)
{
    if (s.empty()) return {};
    const int n = ::WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0, nullptr, nullptr);
    std::string out(static_cast<size_t>(n), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n, nullptr, nullptr);
    return out;
}

// %ProgramData%\Cairn（資料目錄，CONVENTIONS C-2.2）。不存在時建立。
[[nodiscard]] inline std::filesystem::path DataDir()
{
    PWSTR raw = nullptr;
    std::filesystem::path base = L"C:\\ProgramData";
    if (SUCCEEDED(::SHGetKnownFolderPath(FOLDERID_ProgramData, 0, nullptr, &raw)) && raw) {
        base = raw;
    }
    if (raw) ::CoTaskMemFree(raw);
    auto dir = base / L"Cairn";
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    return dir;
}

// %ProgramFiles%\Cairn（安裝目錄）。開發期以執行檔所在目錄為準。
[[nodiscard]] inline std::filesystem::path ExeDir()
{
    wchar_t buf[MAX_PATH * 2]{};
    const DWORD n = ::GetModuleFileNameW(nullptr, buf, static_cast<DWORD>(std::size(buf)));
    return std::filesystem::path(std::wstring(buf, n)).parent_path();
}

[[nodiscard]] inline std::string LastErrorMessage(DWORD err)
{
    LPWSTR msg = nullptr;
    const DWORD n = ::FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                                         FORMAT_MESSAGE_IGNORE_INSERTS,
                                     nullptr, err, 0, reinterpret_cast<LPWSTR>(&msg), 0, nullptr);
    std::string out = n ? WideToUtf8(std::wstring_view(msg, n)) : std::string{};
    if (msg) ::LocalFree(msg);
    while (!out.empty() && (out.back() == '\r' || out.back() == '\n')) out.pop_back();
    return out;
}

[[nodiscard]] inline Error Win32Error(ErrorCode code, std::string_view ctx, DWORD err = ::GetLastError())
{
    return MakeWin32Error(code, err, std::string(ctx) + " — " + LastErrorMessage(err));
}

// FILETIME（100ns since 1601）→ Unix ms
[[nodiscard]] inline int64_t FileTimeToUnixMs(const FILETIME& ft) noexcept
{
    ULARGE_INTEGER u{};
    u.LowPart  = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return static_cast<int64_t>((u.QuadPart - 116444736000000000ull) / 10000ull);
}

} // namespace cairn::svc
