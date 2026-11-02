// SeverityBadge（元件 #1）、RiskScore（#2）與狀態標記。
// 顏色永不單獨承載資訊：嚴重度 = 色塊 + 文字 + 圖示三重編碼（part3 §3.6.1 規則 1）。
import { SEVERITY_LABEL, severityOfScore, statusLabel } from '../lib/format';
import type { Severity } from '../lib/types';

const SEV_ICON: Record<Severity, string> = { critical: '▲', high: '▲', medium: '●', low: '○' };

export function SeverityBadge({
  level,
  score,
  variant = 'subtle',
}: {
  level: Severity;
  score?: number;
  variant?: 'solid' | 'subtle';
}) {
  return (
    <span
      className={`badge sev-${level}`}
      style={variant === 'solid' ? { fontWeight: 600 } : undefined}
      aria-label={`${SEVERITY_LABEL[level]}風險${score !== undefined ? `，分數 ${score}` : ''}`}
    >
      <span aria-hidden>{SEV_ICON[level]}</span>
      {SEVERITY_LABEL[level]}
      {score !== undefined && <span className="mono">{score}</span>}
    </span>
  );
}

export function SeverityBlock({ level }: { level: Severity }) {
  return <span className="sev-block" style={{ background: `var(--sev-${level}-fg)` }} aria-hidden />;
}

// 分數而非布林：直接反映 Tier-2 的加權計分（§3.4.1）。
export function RiskScore({ score, showBar = false }: { score: number; showBar?: boolean }) {
  const sev = severityOfScore(score);
  const cls = sev ? `fg-${sev}` : 'muted';
  return (
    <span className="row" style={{ gap: 6 }} aria-label={`風險分數 ${score}`}>
      <span className={`mono ${cls}`} style={{ fontWeight: 600 }}>
        {score > 0 ? score : '—'}
      </span>
      {showBar && (
        <span className="risk-bar" aria-hidden>
          <span style={{ width: `${Math.min(100, score)}%`, background: sev ? `var(--sev-${sev}-fg)` : 'var(--text-muted)' }} />
        </span>
      )}
    </span>
  );
}

export const ScoreBadge = RiskScore;

export function StatusBadge({ status }: { status: string }) {
  const s = statusLabel(status);
  const cls =
    status === 'auto_blocked' || status === 'blocked'
      ? 'fg-blocked'
      : status === 'false_positive'
        ? 'fg-dryrun'
        : status === 'resolved'
          ? 'fg-success'
          : '';
  return (
    <span className={`xs ${cls}`}>
      <span aria-hidden>{s.icon}</span> {s.label}
    </span>
  );
}

export function SignatureStatus({ signer, status }: { signer: string | null; status: string }) {
  if (status === 'valid')
    return <span className="xs fg-success">✓ 已簽章{signer ? ` (${signer})` : ''}</span>;
  if (status === 'invalid') return <span className="xs fg-critical">✗ 簽章無效{signer ? ` (${signer})` : ''}</span>;
  if (status === 'unsigned') return <span className="xs fg-warning">⚠ 未簽章</span>;
  return (
    <span className="xs muted" title="需安裝 Sysmon 才能取得">
      — 簽章未知
    </span>
  );
}

export function RuleStatusTag({ status }: { status: string }) {
  if (status === 'enabled') return <span className="xs fg-success">✅ 啟用</span>;
  if (status === 'dryrun') return <span className="xs fg-dryrun">🧪 Dry-run</span>;
  return <span className="xs muted">⏹ 停用</span>;
}
