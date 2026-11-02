// resource.h —— CairnConsole.exe 的資源與命令 ID
#pragma once

// 自訂視窗訊息（UI 執行緒）
#define WM_APP_API_REPLY        (WM_APP + 1)   // 背景 RPC 完成 → 回到 UI 執行緒組 WebView2 回應
#define WM_APP_HEARTBEAT        (WM_APP + 2)   // 心跳執行緒的健康度結果
#define WM_APP_NEW_ALERTS       (WM_APP + 3)   // 心跳執行緒偵測到新高風險告警（Toast）
#define WM_APP_TRAY             (WM_APP + 4)   // 系統匣回呼訊息
#define WM_APP_WEBVIEW_READY    (WM_APP + 5)
#define WM_APP_WEBVIEW_FAILED   (WM_APP + 6)

// 系統匣選單
#define ID_TRAY_OPEN            40001
#define ID_TRAY_PAUSE           40002
#define ID_TRAY_HEALTH          40003
#define ID_TRAY_START_SERVICE   40004
#define ID_TRAY_EXIT            40005
#define ID_TRAY_RECENT_BASE     40100          // 40100..40104：最近 5 筆告警

// 原生錯誤畫面的控制項
#define IDC_ERR_TITLE           41001
#define IDC_ERR_BODY            41002
#define IDC_ERR_CODE            41003
#define IDC_ERR_SVC             41004
#define IDC_ERR_INSTALL         41005
#define IDC_ERR_COPY            41006
#define IDC_ERR_RETRY           41007

// 計時器
#define TIMER_WEBVIEW_INIT      1
