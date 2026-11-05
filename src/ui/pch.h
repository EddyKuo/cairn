// pch.h —— CairnConsole.exe 的預編譯標頭
// ⚠ 頂層 cairn_compile_options 帶入 WIN32_LEAN_AND_MEAN；MFC 需要完整的 windows.h（commdlg、shellapi 等），
//   因此在此先取消定義。NOMINMAX 保留，並為可能被間接引入的 GDI+ 補上 min/max。
#pragma once

#ifdef WIN32_LEAN_AND_MEAN
#undef WIN32_LEAN_AND_MEAN
#endif
#ifndef VC_EXTRALEAN
#define VC_EXTRALEAN
#endif

// winsock：VC_EXTRALEAN 使 MFC 引入的 windows.h 不帶舊版 winsock.h，afxwin.h 會自行引入 WinSock2.h。
// 切勿手動定義 _WINSOCKAPI_——afxwin.h 視之為已引入 winsock v1，觸發 C1189「MFC requires use of Winsock2.h」。

#include <algorithm>
namespace Gdiplus {
using std::max;
using std::min;
} // namespace Gdiplus

#include <afxwin.h>
#include <afxext.h>
#include <afxwinappex.h>
#include <afxframewndex.h>
#include <afxcmn.h>

#include <winsock2.h>
#include <ws2tcpip.h>

#include <dwmapi.h>
#include <shellapi.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <winsvc.h>
#include <wrl.h>

#include <wil/com.h>
#include <wil/resource.h>
#include <wil/result.h>

#include <WebView2.h>
#include <WebView2EnvironmentOptions.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <nlohmann/json.hpp>

#include "resource.h"
