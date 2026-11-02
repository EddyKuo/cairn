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

// 阻止 windows.h 引入舊版 winsock.h，稍後改引入 winsock2.h（DevHttp.cpp 的 --dev-http 需要）
#ifndef _WINSOCKAPI_
#define _WINSOCKAPI_
#endif

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
