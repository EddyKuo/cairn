// 與 CairnConsole.exe（MFC 宿主）之間的極薄訊息通道（WebView2 postMessage）。
// 只傳遞 UI 層訊號（主題、導覽、外部連結），絕不承載業務資料——業務資料一律走 /api/v1。
// 在 Vite dev server（一般瀏覽器）下 window.chrome.webview 不存在，所有函式安全退化為 no-op。

interface WebViewBridge {
  postMessage(msg: unknown): void;
  addEventListener(type: 'message', cb: (e: { data: unknown }) => void): void;
  removeEventListener(type: 'message', cb: (e: { data: unknown }) => void): void;
}

function bridge(): WebViewBridge | null {
  const w = window as unknown as { chrome?: { webview?: WebViewBridge } };
  return w.chrome?.webview ?? null;
}

export function isHosted(): boolean {
  return bridge() !== null;
}

// 前端主題切換 → 宿主同步標題列深淺色（DWMWA_USE_IMMERSIVE_DARK_MODE，part3 §3.2.1）。
export function notifyTheme(theme: 'light' | 'dark') {
  bridge()?.postMessage({ type: 'theme', value: theme });
}

// 標題列未讀高風險告警數：「Cairn (3)」。
export function notifyUnread(count: number) {
  bridge()?.postMessage({ type: 'unread', value: count });
}

// 外部連結（ATT&CK 官網）：交給宿主以預設瀏覽器開啟（宿主只允許 https://attack.mitre.org/）。
export function openExternal(url: string): boolean {
  const b = bridge();
  if (!b) {
    window.open(url, '_blank', 'noopener,noreferrer');
    return true;
  }
  b.postMessage({ type: 'openExternal', url });
  return true;
}

// 服務失聯時「嘗試啟動服務」：走宿主提權（UAC）。
export function requestStartService() {
  bridge()?.postMessage({ type: 'startService' });
}

export function requestOpenServices() {
  bridge()?.postMessage({ type: 'openServices' });
}

// 宿主 → 前端：Toast 點擊後導向特定告警、系統匣選單導向 Settings 分頁。
export function onHostMessage(cb: (msg: { type: string; [k: string]: unknown }) => void): () => void {
  const b = bridge();
  if (!b) return () => {};
  const h = (e: { data: unknown }) => {
    const d = e.data as { type?: unknown };
    if (d && typeof d.type === 'string') cb(d as { type: string });
  };
  b.addEventListener('message', h);
  return () => b.removeEventListener('message', h);
}
