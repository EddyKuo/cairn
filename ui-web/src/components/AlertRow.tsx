// AlertRow（元件 #3）：告警列表的雙行列（part3 §3.2.2）。
// 第一行 = 機器可掃描的結構化欄位；第二行 = 規則 title（非 LLM，永遠即時可得）。
// 可展開程序樹摘要（part4 W2-13：不需登入端點就能判斷告警真偽，不可強迫多次跳頁）。
import { fmtTime, timeTitle } from '../lib/format';
import type { AlertSummary } from '../lib/types';
import { RiskScore, SeverityBlock, StatusBadge } from './ScoreBadge';
import { SEVERITY_LABEL } from '../lib/format';

interface Props {
  alert: AlertSummary;
  selected: boolean;
  checked: boolean;
  expanded: boolean;
  fresh: boolean;
  onCheck: (v: boolean) => void;
  onSelect: () => void;
  onOpen: () => void;
  onToggleExpand: () => void;
}

export function AlertRow({ alert: a, selected, checked, expanded, fresh, onCheck, onSelect, onOpen, onToggleExpand }: Props) {
  const ai =
    a.narrative_state === 'ready'
      ? { icon: '✓', title: a.narrative_preview ? a.narrative_preview.slice(0, 100) : 'AI 敘事已就緒' }
      : a.narrative_state === 'pending'
        ? { icon: '⏳', title: '生成中' }
        : a.narrative_state === 'failed' || a.narrative_state === 'timeout'
          ? { icon: '⚠', title: a.narrative_state === 'timeout' ? '生成逾時' : '未通過驗證' }
          : { icon: '—', title: '未觸發（風險分數未達 80）或 AI 未啟用' };
  const [primary, ...others] = a.rule_hits;
  return (
    <div
      className={`alert-row${selected ? ' selected' : ''}${fresh ? ' fresh' : ''}`}
      style={{ borderLeftColor: `var(--sev-${a.severity}-border)` }}
      role="row"
      aria-selected={selected}
      onClick={onSelect}
      onDoubleClick={onOpen}
      data-alert-id={a.alert_id}
    >
      <span onClick={(e) => e.stopPropagation()}>
        <input type="checkbox" checked={checked} onChange={(e) => onCheck(e.target.checked)} aria-label={`選取 ${a.alert_id}`} />
      </span>
      <span className={`xs fg-${a.severity}`}>
        <SeverityBlock level={a.severity} />
        {SEVERITY_LABEL[a.severity]}
      </span>
      <span className="mono xs" title={timeTitle(a.time)}>
        {fmtTime(a.time)}
      </span>
      <span className="ellipsis" style={{ fontWeight: 500 }} title={a.image_path}>
        <button
          className="btn ghost sm"
          style={{ padding: 0, marginRight: 4 }}
          onClick={(e) => {
            e.stopPropagation();
            onToggleExpand();
          }}
          aria-label={expanded ? '收合程序樹摘要' : '展開程序樹摘要'}
          aria-expanded={expanded}
        >
          {expanded ? '▾' : '▸'}
        </button>
        {a.process_name}
      </span>
      <span className="mono xs ellipsis" title={a.rule_hits.join('\n')}>
        {primary ?? '—'}
        {others.length > 0 && <span className="muted"> +{others.length}</span>}
      </span>
      <RiskScore score={a.risk_score} />
      <StatusBadge status={a.analyst_verdict === 'false_positive' ? 'false_positive' : a.status} />
      <span title={ai.title} className={a.narrative_state === 'ready' ? 'fg-ai' : 'muted'}>
        {ai.icon}
      </span>
      <span>
        <button
          className="btn sm"
          onClick={(e) => {
            e.stopPropagation();
            onOpen();
          }}
        >
          檢視
        </button>
      </span>
      <div className="line2">
        <div className="mono ellipsis muted">
          └ ← {a.parent_name ?? '—'} &nbsp; {a.image_path}
          {a.exclusion_created && <span className="fg-dryrun"> 🔖 已建立排除規則</span>}
        </div>
        <div className="ellipsis" style={{ color: 'var(--text-primary)' }}>
          {a.title}
        </div>
      </div>
      {expanded && (
        <div className="chain" onClick={(e) => e.stopPropagation()}>
          {a.process_chain && a.process_chain.length > 0 ? (
            a.process_chain.map((p, i) => (
              <div key={i} className="row sm" style={{ paddingLeft: p.depth * 18 }}>
                <span className="muted">{i === 0 ? '○' : '└'}</span>
                <span style={{ fontWeight: p.risk_score >= 80 ? 700 : 400 }}>{p.name}</span>
                <span className="mono muted">{p.pid}</span>
                <RiskScore score={p.risk_score} />
              </div>
            ))
          ) : (
            <div className="sm muted">此告警未提供程序鏈摘要，請開啟詳情檢視完整程序樹。</div>
          )}
        </div>
      )}
    </div>
  );
}
