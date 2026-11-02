// 全域外框（part3 §3.2.1）：狀態列 + 側欄 + 服務失聯全頁攔截（§3.10.4）。
// MFC 宿主層不提供選單列、工具列——導覽全部由此負責。
import { useEffect, useRef, useState, type ReactNode } from 'react';
import { NavLink } from 'react-router-dom';
import { api, ApiError, errorMessage } from '../lib/api';
import { fmtDuration, fmtTime, relativeTime } from '../lib/format';
import { useInterval, useLink } from '../lib/hooks';
import { notifyTheme, notifyUnread, onHostMessage, requestOpenServices, requestStartService } from '../lib/host';
import { HealthIndicator, overallState, useHealth } from './HealthIndicator';
import { Modal } from './Overlay';
import { useToast } from './Toast';

type ThemePref = 'light' | 'dark' | 'system';

function readTheme(): ThemePref {
  try {
    const v = localStorage.getItem('cairn.theme');
    if (v === 'light' || v === 'dark' || v === 'system') return v;
  } catch {
    /* 偏好儲存不可用時退回預設 */
  }
  return 'system';
}

function applyTheme(pref: ThemePref) {
  const dark = pref === 'dark' || (pref === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches);
  document.documentElement.dataset.theme = dark ? 'dark' : 'light';
  notifyTheme(dark ? 'dark' : 'light');
}

export function Shell({ children, alertCount }: { children: ReactNode; alertCount: number }) {
  const [collapsed, setCollapsed] = useState(false);
  const [theme, setTheme] = useState<ThemePref>(readTheme);
  const health = useHealth();
  const h = health.data;
  const link = useLink();
  const toast = useToast();
  const [, force] = useState(0);
  useInterval(() => force((x) => x + 1), 1000); // 「⟳ 2s前」每秒更新

  useEffect(() => {
    applyTheme(theme);
    try {
      localStorage.setItem('cairn.theme', theme);
    } catch {
      /* ignore */
    }
    if (theme !== 'system') return;
    const mq = window.matchMedia('(prefers-color-scheme: dark)');
    const on = () => applyTheme('system');
    mq.addEventListener('change', on);
    return () => mq.removeEventListener('change', on);
  }, [theme]);

  useEffect(() => {
    notifyUnread(h?.unread_high ?? 0);
  }, [h?.unread_high]);

  // 恢復連線時顯示一次性提示（§3.10.4）
  const goneSinceRef = useRef<number | null>(null);
  useEffect(() => {
    if (link.state === 'gone') goneSinceRef.current = link.goneSince;
    else if (goneSinceRef.current) {
      const dur = Date.now() - goneSinceRef.current;
      goneSinceRef.current = null;
      toast({ type: 'success', message: `已恢復連線（中斷 ${fmtDuration(dur)}）` });
    }
  }, [link.state, link.goneSince, toast]);

  const linkDot = link.state === 'gone' ? 'bad' : health.error ? 'warn' : 'ok';
  const st = overallState(h);

  return (
    <>
      <div className={`shell${collapsed ? ' collapsed' : ''}${link.state === 'gone' ? ' grayscale' : ''}`}>
        <header className="statusbar">
          <span className="brand">
            <span className={`dot ${linkDot}`} aria-label={linkDot === 'ok' ? '連線正常' : linkDot === 'warn' ? '重連中' : 'Agent 無回應'} />
            Cairn
          </span>
          <span className="mono muted">{h?.hostname ?? ''}</span>
          <span className="grow" />
          <ProtectionBadge />
          {h?.learning_mode.active && (
            <a className="badge sev-low" href="#/settings/exclusions" title="學習期內僅記錄不阻擋，期滿將產出建議排除清單">
              學習期 {h.learning_mode.day}/{h.learning_mode.total_days} 天
            </a>
          )}
          {st === 'degraded' && link.state !== 'gone' && (
            <a className="badge" style={{ color: 'var(--semantic-warning)' }} href="#/settings/health">
              ⚠ 能力降級
            </a>
          )}
          <button
            className="btn sm ghost"
            onClick={() => setTheme((t) => (t === 'system' ? 'dark' : t === 'dark' ? 'light' : 'system'))}
            title="切換主題（系統 / 深色 / 淺色）"
          >
            ◐ {theme === 'system' ? '系統' : theme === 'dark' ? '深色' : '淺色'}
          </button>
          <button className="btn sm ghost" onClick={health.reload} title="強制重新整理">
            ⟳ {link.lastOkAt ? relativeTime(link.lastOkAt) : '—'}
          </button>
        </header>
        <nav className="sidebar" aria-label="主導覽">
          <NavLink to="/alerts" className={({ isActive }) => `navlink${isActive ? ' active' : ''}`}>
            <span aria-hidden>⚠</span>
            {!collapsed && (
              <>
                告警 <span className="count">{alertCount}</span>
              </>
            )}
          </NavLink>
          <span className="navlink disabled" title="即時事件流於 M1 提供（M0 以離線報表與 sqlite3 直查替代）">
            <span aria-hidden>≋</span>
            {!collapsed && <>事件流 <span className="xs muted">M1</span></>}
          </span>
          <NavLink to="/settings" className={({ isActive }) => `navlink${isActive ? ' active' : ''}`}>
            <span aria-hidden>⚙</span>
            {!collapsed && '設定'}
          </NavLink>
          <div className="spacer" />
          {!collapsed && <HealthIndicator variant="mini" />}
          <button className="btn sm ghost" onClick={() => setCollapsed((c) => !c)} aria-label={collapsed ? '展開側欄' : '折疊側欄'}>
            {collapsed ? '▶' : '◀ 折疊'}
          </button>
        </nav>
        <main className="main" id="main">
          {children}
        </main>
      </div>
      {link.state === 'gone' && <ServiceGone lastOkAt={link.lastOkAt} onRetry={health.reload} />}
    </>
  );
}

function ProtectionBadge() {
  const health = useHealth();
  const h = health.data;
  const toast = useToast();
  const [menu, setMenu] = useState(false);
  const [confirm, setConfirm] = useState<{ duration: '15m' | '1h' | 'until_reboot'; token: string } | null>(null);
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  // 系統匣選單「暫停防護…」→ 宿主送 openPause，於此展開暫停選單（暫停需二次確認，必須在前端完成）
  useEffect(() => onHostMessage((m) => m.type === 'openPause' && setMenu(true)), []);
  if (!h) return null;

  const label =
    h.protection_state === 'paused'
      ? `⚠ 已暫停${h.paused_until ? ` (至 ${fmtTime(h.paused_until)})` : ''}`
      : h.protection_state === 'learning'
        ? '🛡 僅記錄（學習期）'
        : '🛡 防護中';

  const startPause = async (duration: '15m' | '1h' | 'until_reboot') => {
    setMenu(false);
    try {
      // 暫停防護需 confirmation_token：第一次呼叫不帶 token，伺服器回 403 CONFIRMATION_REQUIRED 並附 token
      await api.pauseProtection(duration, '');
      toast({ type: 'warning', message: '防護已暫停。' });
      health.reload();
    } catch (e) {
      if (e instanceof ApiError && e.code === 'CONFIRMATION_REQUIRED' && typeof e.details?.confirmation_token === 'string') {
        setConfirm({ duration, token: e.details.confirmation_token });
      } else {
        toast({ type: 'error', message: `無法暫停防護：${errorMessage(e)}` });
      }
    }
  };

  const doPause = async () => {
    if (!confirm) return;
    setBusy(true);
    try {
      await api.pauseProtection(confirm.duration, reason, confirm.token);
      toast({ type: 'warning', message: '防護已暫停，已寫入稽核記錄。' });
      setConfirm(null);
      health.reload();
    } catch (e) {
      toast({ type: 'error', message: `暫停失敗：${errorMessage(e)}` });
    } finally {
      setBusy(false);
    }
  };

  return (
    <span style={{ position: 'relative' }}>
      <button
        className={`btn sm${h.protection_state === 'paused' ? ' danger' : ''}`}
        onClick={() => setMenu((m) => !m)}
        aria-haspopup="menu"
        aria-expanded={menu}
      >
        {label}
      </button>
      {menu && (
        <div className="menu" role="menu" style={{ right: 0, top: 32 }}>
          {h.protection_state === 'paused' ? (
            <button
              role="menuitem"
              onClick={async () => {
                setMenu(false);
                try {
                  await api.resumeProtection();
                  toast({ type: 'success', message: '已恢復防護。' });
                  health.reload();
                } catch (e) {
                  toast({ type: 'error', message: `恢復失敗：${errorMessage(e)}` });
                }
              }}
            >
              ▶ 恢復防護
            </button>
          ) : (
            <>
              <button role="menuitem" onClick={() => startPause('15m')}>
                ⏸ 暫停 15 分鐘
              </button>
              <button role="menuitem" onClick={() => startPause('1h')}>
                ⏸ 暫停 1 小時
              </button>
              <button role="menuitem" onClick={() => startPause('until_reboot')}>
                ⏸ 暫停直到重開機
              </button>
            </>
          )}
        </div>
      )}
      {confirm && (
        <Modal title="⏸ 暫停防護" onClose={() => setConfirm(null)}>
          <p>
            暫停期間<strong className="fg-critical">不會執行任何回應動作</strong>
            ，偵測與記錄持續進行。此操作將寫入稽核記錄。
          </p>
          <p className="sm">
            期間：{confirm.duration === '15m' ? '15 分鐘' : confirm.duration === '1h' ? '1 小時' : '直到重開機'}
          </p>
          <label className="col" style={{ gap: 4 }}>
            <span className="sm">原因（將寫入稽核記錄）</span>
            <textarea className="textarea" value={reason} onChange={(e) => setReason(e.target.value)} />
          </label>
          <div className="row" style={{ justifyContent: 'flex-end', marginTop: 16 }}>
            <button className="btn" onClick={() => setConfirm(null)} disabled={busy}>
              取消
            </button>
            <button className="btn danger" onClick={doPause} disabled={busy || !reason.trim()}>
              確認暫停
            </button>
          </div>
        </Modal>
      )}
    </span>
  );
}

// 服務失聯：全頁攔截（唯一允許全頁的錯誤），既有資料灰階保留並疊「資料截止於」浮水印。
function ServiceGone({ lastOkAt, onRetry }: { lastOkAt: number | null; onRetry: () => void }) {
  const [countdown, setCountdown] = useState(5);
  useInterval(() => {
    setCountdown((c) => {
      if (c <= 1) {
        onRetry();
        return 5;
      }
      return c - 1;
    });
  }, 1000);
  return (
    <>
      {lastOkAt && (
        <div className="watermark">資料截止於 {fmtTime(new Date(lastOkAt).toISOString())}</div>
      )}
      <div className="gone-overlay" role="alertdialog" aria-modal="true" aria-labelledby="gone-title">
        <div className="gone-card">
          <h1 className="h1 fg-critical" id="gone-title">
            ⚠ 防護狀態未知
          </h1>
          <p>
            無法連線至 Cairn 服務。這可能是服務已停止、當機、或被終止。<strong>在恢復前，本機不受保護。</strong>
          </p>
          <p className="sm muted">背景每 5 秒自動重試（{countdown} 秒後）。畫面上的資料已灰階保留，僅供參考。</p>
          <div className="row wrap" style={{ marginTop: 16 }}>
            <button className="btn primary" onClick={onRetry}>
              重試連線
            </button>
            <button className="btn" onClick={requestStartService}>
              嘗試啟動服務（需系統管理員）
            </button>
            <button className="btn ghost" onClick={requestOpenServices}>
              開啟服務管理員
            </button>
          </div>
        </div>
      </div>
    </>
  );
}
