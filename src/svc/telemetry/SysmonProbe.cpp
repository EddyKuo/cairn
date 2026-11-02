#include "telemetry/SysmonProbe.h"

#include <windows.h>
#include <bcrypt.h>

#include <fstream>
#include <memory>
#include <type_traits>
#include <vector>

#include <wil/resource.h>

#include "common/WinUtil.h"

#pragma comment(lib, "version.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")

namespace cairn::telemetry {

namespace {

struct ScHandleDeleter {
    void operator()(SC_HANDLE h) const noexcept
    {
        if (h) ::CloseServiceHandle(h);
    }
};
using UniqueSc = std::unique_ptr<std::remove_pointer_t<SC_HANDLE>, ScHandleDeleter>;

std::wstring QueryServiceBinary(SC_HANDLE service)
{
    DWORD need = 0;
    ::QueryServiceConfigW(service, nullptr, 0, &need);
    if (need == 0) return {};
    std::vector<BYTE> buf(need);
    auto* cfg = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buf.data());
    if (!::QueryServiceConfigW(service, cfg, need, &need) || !cfg->lpBinaryPathName) return {};
    std::wstring p = cfg->lpBinaryPathName;
    // 去除引號與參數
    if (!p.empty() && p.front() == L'"') {
        const auto end = p.find(L'"', 1);
        p = p.substr(1, end == std::wstring::npos ? std::wstring::npos : end - 1);
    } else if (const auto sp = p.find(L".exe "); sp != std::wstring::npos) {
        p.resize(sp + 4);
    }
    return p;
}

void ReadFileVersion(const std::wstring& path, SysmonStatus& st)
{
    DWORD dummy = 0;
    const DWORD size = ::GetFileVersionInfoSizeW(path.c_str(), &dummy);
    if (size == 0) return;
    std::vector<BYTE> data(size);
    if (!::GetFileVersionInfoW(path.c_str(), 0, size, data.data())) return;
    VS_FIXEDFILEINFO* ffi = nullptr;
    UINT len = 0;
    if (!::VerQueryValueW(data.data(), L"\\", reinterpret_cast<void**>(&ffi), &len) || !ffi) return;
    st.majorVersion = HIWORD(ffi->dwFileVersionMS);
    st.version = std::to_string(HIWORD(ffi->dwFileVersionMS)) + "." + std::to_string(LOWORD(ffi->dwFileVersionMS)) +
                 "." + std::to_string(HIWORD(ffi->dwFileVersionLS)) + "." + std::to_string(LOWORD(ffi->dwFileVersionLS));
}

} // namespace

SysmonStatus ProbeSysmon() noexcept
{
    SysmonStatus st;
    UniqueSc scm{::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT)};
    if (!scm) return st;
    for (const wchar_t* name : {L"Sysmon64", L"Sysmon"}) {
        UniqueSc service{::OpenServiceW(scm.get(), name, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG)};
        if (!service) continue;
        st.installed   = true;
        st.serviceName = svc::WideToUtf8(name);
        SERVICE_STATUS_PROCESS ssp{};
        DWORD need = 0;
        if (::QueryServiceStatusEx(service.get(), SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &need))
            st.running = (ssp.dwCurrentState == SERVICE_RUNNING);
        if (const auto bin = QueryServiceBinary(service.get()); !bin.empty()) ReadFileVersion(bin, st);
        break;
    }
    return st;
}

std::string HashFileSha256(const std::filesystem::path& file) noexcept
{
    std::ifstream in(file, std::ios::binary);
    if (!in) return {};
    BCRYPT_ALG_HANDLE alg = nullptr;
    if (::BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) return {};
    BCRYPT_HASH_HANDLE hash = nullptr;
    std::string out;
    if (::BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0) == 0) {
        std::vector<char> buf(64 * 1024);
        bool ok = true;
        while (in) {
            in.read(buf.data(), static_cast<std::streamsize>(buf.size()));
            const auto n = in.gcount();
            if (n > 0 && ::BCryptHashData(hash, reinterpret_cast<PUCHAR>(buf.data()), static_cast<ULONG>(n), 0) != 0) {
                ok = false;
                break;
            }
        }
        UCHAR digest[32]{};
        if (ok && ::BCryptFinishHash(hash, digest, sizeof(digest), 0) == 0) {
            static constexpr char kHex[] = "0123456789ABCDEF";
            out.reserve(64);
            for (UCHAR b : digest) {
                out.push_back(kHex[b >> 4]);
                out.push_back(kHex[b & 0x0F]);
            }
        }
        ::BCryptDestroyHash(hash);
    }
    ::BCryptCloseAlgorithmProvider(alg, 0);
    return out;
}

} // namespace cairn::telemetry
