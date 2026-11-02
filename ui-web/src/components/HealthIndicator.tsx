// HealthIndicator（元件 #13）：側欄迷你版（常駐於每個畫面）+ Settings 完整版。
// 無驅動架構下 agent 可被 taskkill，這個常駐指示燈是使用者察覺「防護已失效」的唯一途徑（§3.2.1）。
import { createContext, useContext, type ReactNode } from 'react';
import { api } from '../lib/api';
import { fmtShortDateTime, fmtUptime } from '../lib/format';
import { useAsync, useLink, type AsyncState } from '../lib/hooks';
import type { Health } from '../lib/types';

const HealthCtx = createContext<AsyncState<Health> | null>(null);

export function HealthProvider({ children }: { children: ReactNode }) {
  const h = useAsync<Health>((s) => api.health(s), [], { pollMs: 5000 });
  return <HealthCtx.Provider value={h}>{children}</HealthCtx.Provider>;
}

export function useHealth(): AsyncState<Health> {
  const v = useContext(HealthCtx);
  if (!v) throw new Error('HealthProvider missing');
  return v;
}

export function overallState(h: Health | undefined): 'ok' | 'degraded' | 'unknown' {
  if (!h) return 'unknown';
  const degradedProvider = h.providers.some((p) => p.state !== 'ok' && p.state !== 'running');
  if (!h.sysmon.installed || degradedProvider || h.resources.drop_rate > 0.05 || h.protection_state === 'paused')
    return 'degraded';
  return 'ok';
}

export function HealthIndicator({ variant }: { variant: 'mini' | 'full' }) {
  const { data: h } = useHealth();
  const link = useLink();
  if (variant === 'mini') {
    if (link.state === 'gone') {
      return (
        <div className="health-mini down" role="status">
          <div className="fg-critical">⚠ 無法連線至 Agent 服務</div>
          <div>防護狀態未知</div>
        </div>
      );
    }
    const st = overallState(h);
    return (
      <div className="health-mini" role="status" aria-label="Agent 健康度">
        <div className="muted">Agent 健康</div>
        <div className="row">
          <span className={`dot ${st === 'ok' ? 'ok' : st === 'degraded' ? 'warn' : 'bad'}`} />
          {st === 'ok' ? '正常' : st === 'degraded' ? '能力降級' : '讀取中'}
        </div>
        {h && (
          <>
            <div className="mono">事件 {fmtRate(h.resources.events_per_sec)}/s</div>
            <div className="mono">丟包 {(h.resources.drop_rate * 100).toFixed(2)}%</div>
            <div className="mono">CPU {h.resources.cpu_p95.toFixed(1)}%</div>
          </>
        )}
      </div>
    );
  }
  return <HealthFull h={h} />;
}

function fmtRate(n: number): string {
  return n >= 1000 ? `${(n / 1000).toFixed(1)}k` : String(Math.round(n));
}

function Dot({ ok, warn }: { ok: boolean; warn?: boolean }) {
  return <span className={`dot ${ok ? 'ok' : warn ? 'warn' : 'bad'}`} />;
}

function HealthFull({ h }: { h: Health | undefined }) {
  if (!h) return <div className="skel" style={{ height: 120 }} />;
  const ram = h.resources.ram_mb;
  return (
    <div className="col" style={{ gap: 16 }}>
      <div className="two-col">
        <div className="card">
          <div className="h3" style={{ marginBottom: 8 }}>
            服務狀態
          </div>
          <div className="kv">
            <span>核心服務</span>
            <span className="row">
              <Dot ok /> 執行中 {fmtUptime(h.uptime_s)}
            </span>
            <span>防護狀態</span>
            <span className="row">
              <Dot ok={h.protection_state === 'protecting'} warn />
              {h.protection_state === 'protecting'
                ? '防護中'
                : h.protection_state === 'learning'
                  ? `學習期 ${h.learning_mode.day}/${h.learning_mode.total_days} 天（僅記錄不阻擋）`
                  : h.protection_state === 'paused'
                    ? `已暫停${h.paused_until ? `（至 ${fmtShortDateTime(h.paused_until)}）` : ''}`
                    : h.protection_state}
            </span>
            {h.providers.map((p) => (
              <FragmentRow key={p.name} name={p.name} state={p.state} />
            ))}
            <span>Sysmon</span>
            <span className="row">
              <Dot ok={h.sysmon.installed} />
              {h.sysmon.installed ? `已安裝 ${h.sysmon.version ?? ''}` : '未安裝（遠端執行緒與檔案雜湊遙測不可用）'}
            </span>
            <span>LLM 引擎</span>
            <span className="row">
              <Dot ok={h.llm.state === 'ok'} warn />
              {h.llm.state === 'ok' ? `就緒 (${h.llm.device ?? 'cpu'} 模式)` : h.llm.state === 'unavailable' ? '未啟用（不影響偵測）' : h.llm.state}
              {h.llm.model_id && <span className="mono xs muted">{h.llm.model_id}</span>}
            </span>
          </div>
        </div>
        <div className="card">
          <div className="h3" style={{ marginBottom: 8 }}>
            資源用量
          </div>
          <div className="kv">
            <span>CPU P95</span>
            <span className={`mono ${h.resources.cpu_p95 > 2 ? 'fg-warning' : ''}`}>
              {h.resources.cpu_p95.toFixed(1)}%（閒置上限 2%）
            </span>
            <span>常駐記憶體</span>
            <span className={`mono ${ram > 300 ? 'fg-warning' : ''}`}>{ram.toFixed(0)} MB（上限 300 MB）</span>
            <span>資料庫</span>
            <span className="mono">{(h.resources.disk_mb / 1024).toFixed(2)} GB</span>
            <span>事件率</span>
            <span className="mono">{fmtRate(h.resources.events_per_sec)}/s</span>
            <span>丟包率</span>
            <span className={`mono ${h.resources.drop_rate > 0.001 ? 'fg-warning' : ''}`}>
              {(h.resources.drop_rate * 100).toFixed(3)}%
            </span>
          </div>
          <div className="h3" style={{ margin: '12px 0 4px' }}>
            ⚠ 過去 24 小時異常（{h.anomalies_24h.length}）
          </div>
          {h.anomalies_24h.length === 0 ? (
            <div className="sm muted">無</div>
          ) : (
            h.anomalies_24h.map((a, i) => (
              <div key={i} className="sm">
                • <span className="mono">{fmtShortDateTime(a.time)}</span> {a.message}
              </div>
            ))
          )}
        </div>
      </div>
      <div className="card" style={{ borderColor: 'var(--semantic-warning)' }}>
        <div className="h3">⚠ 自我保護能力揭露</div>
        <p className="sm" style={{ margin: '6px 0' }}>
          {h.self_protection.disclosure ||
            '本版本為無驅動架構，不具備核心層自我保護。具備本機管理員權限者可終止本服務。'}
        </p>
        <div className="sm">服務異常終止次數（過去 30 天）：{h.self_protection.unexpected_terminations_30d}</div>
      </div>
    </div>
  );
}

function FragmentRow({ name, state }: { name: string; state: string }) {
  const ok = state === 'ok' || state === 'running' || state === 'healthy';
  return (
    <>
      <span>{name}</span>
      <span className="row">
        <Dot ok={ok} warn /> {state}
      </span>
    </>
  );
}
