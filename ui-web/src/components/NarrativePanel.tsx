// NarrativePanel（元件 #8）：AI 敘事區塊，part3 §3.5。
// 架構誠實性的 UI 落點：
//   - 免責標示由後端組裝（disclaimer），固定置頂、不可折疊、不可關閉，所有狀態都存在
//   - 每種非就緒狀態都必須明說「不影響偵測／阻擋」
//   - LLM 輸出一律當純文字渲染（React 預設跳脫）；實體連結只在後端給的白名單（linkable_entities）上比對
//   - 建議處置明示「系統不會自動執行」，且絕不轉為可一鍵執行的動作（part2 §2.6.4 第 3 道）
import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { api, errorMessage } from '../lib/api';
import { fmtDuration } from '../lib/format';
import { useAsync } from '../lib/hooks';
import type { Disclaimer, NarrativeResponse } from '../lib/types';
import { AttackTag } from './AttackTag';
import { Drawer } from './Overlay';
import { Skeleton, InlineError } from './States';
import { useToast } from './Toast';

interface Props {
  alertId: string;
  fallbackDisclaimer: Disclaimer; // 敘事端點尚未回應時，以告警本身的決策依據組出相同文案
  onEntityClick?: (type: string, ref: string) => void;
}

export function NarrativePanel({ alertId, fallbackDisclaimer, onEntityClick }: Props) {
  const toast = useToast();
  // 僅在 pending（或尚未取得狀態）時 2 秒輪詢（§3.5.3 / SDD-03 §9.6）；就緒後停止。
  const [polling, setPolling] = useState(true);
  const n = useAsync<NarrativeResponse>((s) => api.getNarrative(alertId, s), [alertId], {
    pollMs: polling ? 2000 : undefined,
  });
  const state = n.data?.state;
  useEffect(() => {
    setPolling(!state || state === 'pending');
  }, [state]);

  const [elapsed, setElapsed] = useState(0);
  useEffect(() => {
    if (state !== 'pending') return;
    const base = n.data?.progress?.elapsed_ms ?? 0;
    const start = Date.now() - base;
    const h = window.setInterval(() => setElapsed(Date.now() - start), 100);
    return () => window.clearInterval(h);
  }, [state, n.data?.progress?.elapsed_ms]);

  const [rawOpen, setRawOpen] = useState(false);
  const [fbOpen, setFbOpen] = useState(false);
  const disclaimer = n.data?.disclaimer ?? fallbackDisclaimer;

  const regenerate = async (mode: 'same' | 'reduced_context', count?: number) => {
    try {
      await api.regenerateNarrative(alertId, mode, count);
      n.setData((d) => (d ? { ...d, state: 'pending', progress: { elapsed_ms: 0, expected_ms: 20000, streaming: false } } : d));
      n.reload();
    } catch (e) {
      toast({ type: 'error', message: `無法重新生成：${errorMessage(e)}` });
    }
  };

  const feedback = async (helpful: boolean, reason?: string) => {
    try {
      await api.narrativeFeedback(alertId, helpful, reason);
      toast({ type: 'success', message: '已記錄您的回饋，謝謝。' });
    } catch (e) {
      toast({ type: 'error', message: `回饋送出失敗：${errorMessage(e)}` });
    }
    setFbOpen(false);
  };

  return (
    <section aria-labelledby="ai-title">
      <div className="row" style={{ marginBottom: 8 }}>
        <h2 className="h2 grow" id="ai-title">
          <span aria-hidden>🤖</span> AI 攻擊敘事
        </h2>
        {n.data?.provenance && (
          <span className="xs muted" title={n.data.provenance.model_sha256}>
            模型 {n.data.provenance.model_id}
          </span>
        )}
      </div>
      <DisclaimerBox d={disclaimer} />
      <div style={{ marginTop: 12 }}>
        {n.loading ? (
          <Skeleton lines={5} />
        ) : n.error && !n.data ? (
          <InlineError what="AI 敘事" error={n.error} onRetry={n.reload} />
        ) : n.data ? (
          <Body
            r={n.data}
            elapsed={elapsed}
            onEntityClick={onEntityClick}
            onRegenerate={regenerate}
            onFeedback={(h) => (h ? feedback(true) : setFbOpen(true))}
            onRaw={() => setRawOpen(true)}
          />
        ) : null}
      </div>
      {rawOpen && n.data?.error && (
        <Drawer title="原始模型輸出（未通過驗證）" onClose={() => setRawOpen(false)}>
          <p className="sm secondary">
            以下為未通過 JSON Schema／白名單驗證的原始 LLM 輸出，僅供調校文法使用。此內容<strong>未</strong>顯示給一般使用者，也不參與任何決策。
          </p>
          <pre className="mono card" style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
            {n.data.error.raw_output ?? '（後端未提供原始輸出內容）'}
          </pre>
        </Drawer>
      )}
      {fbOpen && <FeedbackDrawer onClose={() => setFbOpen(false)} onSubmit={(r) => feedback(false, r)} />}
    </section>
  );
}

function DisclaimerBox({ d }: { d: Disclaimer }) {
  return (
    <div className="disclaimer" role="note">
      <span aria-hidden>ⓘ </span>
      {d.text}
      {d.actual_decision_basis?.sentence && <>——{d.actual_decision_basis.sentence}</>}
    </div>
  );
}

function Body({
  r,
  elapsed,
  onEntityClick,
  onRegenerate,
  onFeedback,
  onRaw,
}: {
  r: NarrativeResponse;
  elapsed: number;
  onEntityClick?: (type: string, ref: string) => void;
  onRegenerate: (mode: 'same' | 'reduced_context', count?: number) => void;
  onFeedback: (helpful: boolean) => void;
  onRaw: () => void;
}) {
  const basis = r.disclaimer?.actual_decision_basis;
  const basisText = basis
    ? `本次告警由規則 ${basis.rule_ids.join('、')} 與風險分數 ${basis.risk_score} 觸發`
    : '本次告警由規則引擎觸發';

  switch (r.state) {
    case 'pending': {
      const expected = r.progress?.expected_ms ?? 20000;
      const pct = Math.min(100, (elapsed / expected) * 100);
      const slow = elapsed > 20000;
      return (
        <div className="col" style={{ alignItems: 'stretch' }}>
          <div className="row">
            <span aria-hidden>⏳</span>
            <span>正在生成攻擊敘事… {(elapsed / 1000).toFixed(1)}s</span>
          </div>
          <div className={`progress${slow ? ' slow' : ''}`}>
            <span style={{ width: `${pct}%` }} />
          </div>
          <div className="xs muted">
            {slow ? '較預期慢，可能因為模型正在載入。' : `預計 ${Math.round(expected / 1000)} 秒內完成`}
          </div>
          <Skeleton lines={3} />
          <p className="sm secondary">
            ⓘ {r.hint ?? '左欄的程序樹與事件時間軸已完整可用，您可以先開始判讀，不需等待此區塊。'}
          </p>
        </div>
      );
    }
    case 'failed':
      return (
        <div className="col">
          <div className="row">
            <span className="fg-warning" aria-hidden>
              ⚠
            </span>
            <strong>無法生成攻擊敘事</strong>
          </div>
          <div className="sm">
            原因：{r.error?.message ?? '模型輸出未通過驗證'}
            {r.error?.retry_count !== undefined && `（已重試 ${r.error.retry_count} 次）`}
          </div>
          <div className="xs mono muted">錯誤碼：{r.error?.code ?? 'SCHEMA_VIOLATION'}</div>
          <p className="sm secondary">
            ⓘ 這不影響偵測結果。{r.error?.user_note ?? `${basisText}，回應動作已依規則正常執行。左欄的完整證據不受影響。`}
          </p>
          <div className="row">
            {r.retryable !== false && (
              <button className="btn" onClick={() => onRegenerate('same')}>
                ↻ 重試
              </button>
            )}
            {r.error?.raw_output_available && (
              <button className="btn" onClick={onRaw}>
                檢視原始輸出
              </button>
            )}
          </div>
        </div>
      );
    case 'timeout':
      return (
        <div className="col">
          <div className="row">
            <span aria-hidden>⏱</span>
            <strong>
              敘事生成逾時
              {r.error?.elapsed_ms !== undefined &&
                `（${(r.error.elapsed_ms / 1000).toFixed(1)}s > 上限 ${((r.error.limit_ms ?? 30000) / 1000).toFixed(1)}s）`}
            </strong>
          </div>
          <div className="sm">已取消以避免佔用分析佇列。</div>
          <div className="sm secondary">
            常見原因：{(r.error?.likely_causes ?? ['模型首次載入', 'CPU 模式下的長事件序列', '系統正處於高負載']).join('、')}。
          </div>
          <p className="sm secondary">ⓘ 偵測與阻擋完全不受影響。</p>
          <div className="row wrap">
            {(r.retry_options ?? [
              { mode: 'same', label: '重試' },
              { mode: 'reduced_context', label: '以較短脈絡重試', event_count: 5 },
            ]).map((o) => (
              <button key={o.mode} className="btn" onClick={() => onRegenerate(o.mode, o.event_count)}>
                ↻ {o.label}
              </button>
            ))}
          </div>
        </div>
      );
    case 'unavailable':
      return (
        <div className="col">
          <div className="row">
            <span aria-hidden>💤</span>
            <strong>本機 AI 目前未啟用</strong>
          </div>
          <p className="sm secondary">
            推論引擎未啟動、模型尚未下載，或閒置卸載中。ⓘ 偵測與回應能力完全不受影響；{basisText}。
          </p>
          <div className="row">
            <button className="btn" onClick={() => onRegenerate('same')}>
              ↻ 嘗試生成
            </button>
            <a className="btn ghost" href="#/settings/health">
              檢視 AI 引擎狀態
            </a>
          </div>
        </div>
      );
    case 'skipped':
      return (
        <div className="col">
          <div className="row">
            <span aria-hidden>—</span>
            <strong>未生成 AI 敘事</strong>
          </div>
          <p className="sm secondary">
            風險分數未達敘事生成門檻（80），或因負載過高而略過。ⓘ 這不影響偵測結果。
          </p>
          <div className="row">
            <button className="btn" onClick={() => onRegenerate('same')}>
              ↻ 手動生成
            </button>
          </div>
        </div>
      );
    case 'ready':
    default:
      return <Ready r={r} onEntityClick={onEntityClick} onRegenerate={onRegenerate} onFeedback={onFeedback} />;
  }
}

function Ready({
  r,
  onEntityClick,
  onRegenerate,
  onFeedback,
}: {
  r: NarrativeResponse;
  onEntityClick?: (type: string, ref: string) => void;
  onRegenerate: (mode: 'same' | 'reduced_context') => void;
  onFeedback: (helpful: boolean) => void;
}) {
  const linkify = useLinkifier(r.linkable_entities ?? [], onEntityClick);
  const conf = r.confidence ?? 0;
  const confLabel = r.confidence_label ?? (conf >= 0.8 ? 'high' : conf >= 0.5 ? 'medium' : 'low');
  const confText = confLabel === 'high' ? '高' : confLabel === 'medium' ? '中' : '低';
  const confColor = confLabel === 'high' ? 'var(--text-primary)' : 'var(--semantic-warning)';
  const text = [r.narrative?.what_happened, r.narrative?.why_suspicious, r.narrative?.what_it_means]
    .filter(Boolean)
    .join('\n\n');

  return (
    <div className="col" style={{ gap: 12 }}>
      {r.narrative && (
        <div className="col" style={{ gap: 10 }}>
          <Para title="發生了什麼">{linkify(r.narrative.what_happened)}</Para>
          <Para title="為什麼可疑">{linkify(r.narrative.why_suspicious)}</Para>
          <Para title="這意味著什麼">{linkify(r.narrative.what_it_means)}</Para>
        </div>
      )}
      {r.recommendations && r.recommendations.length > 0 && (
        <div>
          <div className="h3">建議處置</div>
          <ul style={{ margin: '4px 0', paddingLeft: 20 }}>
            {r.recommendations.map((x, i) => (
              <li key={i}>{x}</li>
            ))}
          </ul>
          <div className="xs muted">ⓘ {r.recommendations_note ?? '以上為建議，系統不會自動執行。'}</div>
        </div>
      )}
      {r.attack_mapping && r.attack_mapping.length > 0 && (
        <div>
          <div className="h3">MITRE ATT&amp;CK 映射</div>
          <div className="col" style={{ gap: 4, marginTop: 4 }}>
            {r.attack_mapping.map((a) => (
              <AttackTag key={a.id} techniqueId={a.id} name={a.name} offlineDescription={a.offline_description} showName />
            ))}
          </div>
        </div>
      )}
      <div className="row">
        <span className="sm">信心分數</span>
        <span className="confidence-bar" aria-hidden>
          <span style={{ display: 'block', height: '100%', width: `${conf * 100}%`, background: confColor }} />
        </span>
        <span className="mono">{conf.toFixed(2)}</span>
        <span className="sm" style={{ color: confColor }}>
          {confText}
        </span>
      </div>
      {confLabel === 'low' && <div className="xs fg-warning">模型對此判斷信心偏低，請以左欄證據為準。</div>}
      {r.provenance && (
        <div className="xs muted mono">
          生成耗時 {fmtDuration(r.provenance.duration_ms)} · {r.provenance.model_id} · sha256:
          {r.provenance.model_sha256.slice(0, 4)}…{r.provenance.model_sha256.slice(-4)} · {r.provenance.device}
        </div>
      )}
      <div className="row wrap">
        <button className="btn" onClick={() => onFeedback(true)}>
          👍 有幫助
        </button>
        <button className="btn" onClick={() => onFeedback(false)}>
          👎 沒幫助
        </button>
        <button className="btn" onClick={() => onRegenerate('same')}>
          ↻ 重新生成
        </button>
        <button className="btn" onClick={() => void navigator.clipboard?.writeText(text)}>
          ⧉ 複製
        </button>
      </div>
    </div>
  );
}

function Para({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div>
      <div className="xs fg-ai">{title}</div>
      <div style={{ lineHeight: '22px', whiteSpace: 'pre-wrap' }}>{children}</div>
    </div>
  );
}

// 僅在後端提供的實體白名單上做字串比對，產生可點擊連結；其餘內容一律為純文字節點。
function useLinkifier(
  entities: { text: string; type: string; ref: string }[],
  onClick?: (type: string, ref: string) => void,
) {
  return useMemo(() => {
    const list = entities.filter((e) => e.text.length >= 3).sort((a, b) => b.text.length - a.text.length);
    return (s: string | undefined): ReactNode => {
      if (!s) return null;
      if (list.length === 0 || !onClick) return s;
      const out: ReactNode[] = [];
      let rest = s;
      let key = 0;
      while (rest.length > 0) {
        let best: { i: number; e: (typeof list)[number] } | null = null;
        for (const e of list) {
          const i = rest.indexOf(e.text);
          if (i >= 0 && (best === null || i < best.i)) best = { i, e };
        }
        if (!best) {
          out.push(rest);
          break;
        }
        if (best.i > 0) out.push(rest.slice(0, best.i));
        const e = best.e;
        out.push(
          <button
            key={key++}
            className="btn ghost sm"
            style={{ padding: 0, color: 'var(--semantic-info)', textDecoration: 'underline' }}
            onClick={() => onClick(e.type, e.ref)}
          >
            {e.text}
          </button>,
        );
        rest = rest.slice(best.i + e.text.length);
      }
      return out;
    };
  }, [entities, onClick]);
}

function FeedbackDrawer({ onClose, onSubmit }: { onClose: () => void; onSubmit: (reason: string) => void }) {
  const reasons = ['不正確', '太籠統', '與證據矛盾', '看不懂'];
  const [r, setR] = useState(reasons[0]);
  return (
    <Drawer title="這段敘事哪裡沒幫助？" onClose={onClose}>
      <div className="col">
        {reasons.map((x) => (
          <label key={x} className="row">
            <input type="radio" name="fb" checked={r === x} onChange={() => setR(x)} /> {x}
          </label>
        ))}
        <div className="row" style={{ justifyContent: 'flex-end', marginTop: 12 }}>
          <button className="btn" onClick={onClose}>
            取消
          </button>
          <button className="btn primary" onClick={() => onSubmit(r)}>
            送出
          </button>
        </div>
      </div>
    </Drawer>
  );
}
