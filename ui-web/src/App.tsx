// React SPA 根元件。路由採 HashRouter：
//   CairnConsole.exe 永遠只載入 https://cairn.local/index.html，相對資源路徑（vite base './'）不會因深層路由而解析錯位，
//   且宿主不需實作 SPA fallback。
import { useCallback, useEffect, useState } from 'react';
import { HashRouter, Navigate, Route, Routes, useNavigate } from 'react-router-dom';
import { HealthProvider } from './components/HealthIndicator';
import { Shell } from './components/Shell';
import { ToastProvider } from './components/Toast';
import { onHostMessage } from './lib/host';
import { AlertDetail } from './pages/AlertDetail';
import { AlertQueue } from './pages/AlertQueue';
import { Settings } from './pages/Settings';

// 宿主訊息：Toast 點擊 → 直達 /alerts/{id}；系統匣「服務狀態…」→ Settings 健康度分頁。
function HostNavigation() {
  const navigate = useNavigate();
  useEffect(
    () =>
      onHostMessage((m) => {
        if (m.type === 'navigate' && typeof m.path === 'string' && m.path.startsWith('/')) navigate(m.path);
      }),
    [navigate],
  );
  return null;
}

export function App() {
  const [pending, setPending] = useState(0);
  const onCounts = useCallback((n: number) => setPending(n), []);
  return (
    <HashRouter>
      <ToastProvider>
        <HealthProvider>
          <HostNavigation />
          <Shell alertCount={pending}>
            <Routes>
              <Route path="/" element={<Navigate to="/alerts" replace />} />
              <Route path="/alerts" element={<AlertQueue onCounts={onCounts} />} />
              <Route path="/alerts/:alertId" element={<AlertDetail />} />
              <Route path="/settings" element={<Navigate to="/settings/exclusions" replace />} />
              <Route path="/settings/:tab" element={<Settings />} />
              <Route path="*" element={<Navigate to="/alerts" replace />} />
            </Routes>
          </Shell>
        </HealthProvider>
      </ToastProvider>
    </HashRouter>
  );
}
