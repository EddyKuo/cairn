// 資料驅動元件的五種狀態共用片段（part3 §3.7.2）：Loading / Empty / Error / Partial / Ready。
import type { ReactNode } from 'react';
import { ApiError, errorMessage } from '../lib/api';

export function Skeleton({ lines = 3, shape = 'rows' }: { lines?: number; shape?: 'rows' | 'tree' | 'alert' }) {
  return (
    <div className="col" aria-busy="true" aria-label="載入中">
      {Array.from({ length: lines }).map((_, i) => {
        if (shape === 'alert')
          return (
            <div key={i} className="col" style={{ gap: 6, padding: '8px 0' }}>
              <div className="skel" style={{ width: '70%' }} />
              <div className="skel" style={{ width: '45%', height: 10 }} />
            </div>
          );
        if (shape === 'tree')
          return <div key={i} className="skel" style={{ width: `${60 - i * 6}%`, marginLeft: i * 18 }} />;
        return <div key={i} className="skel" style={{ width: `${90 - (i % 3) * 15}%` }} />;
      })}
    </div>
  );
}

export function SlowHint({ show, onCancel }: { show: boolean; onCancel?: () => void }) {
  if (!show) return null;
  return (
    <div className="row sm muted" style={{ marginTop: 8 }}>
      載入時間較長…
      {onCancel && (
        <button className="btn sm ghost" onClick={onCancel}>
          取消
        </button>
      )}
    </div>
  );
}

export function EmptyState({
  icon,
  title,
  subtitle,
  action,
}: {
  icon: string;
  title: string;
  subtitle?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="empty">
      <div className="icon" aria-hidden>
        {icon}
      </div>
      <div className="title">{title}</div>
      {subtitle && <div className="secondary sm">{subtitle}</div>}
      {action && <div style={{ marginTop: 16 }}>{action}</div>}
    </div>
  );
}

// 單一 API 失敗：區塊內聯錯誤卡片，不影響其他區塊。
export function InlineError({ what, error, onRetry }: { what: string; error: unknown; onRetry?: () => void }) {
  const status = error instanceof ApiError ? `HTTP ${error.status}` : '錯誤';
  return (
    <div className="card inline-error" role="alert">
      <div className="row">
        <span className="fg-critical">⚠</span>
        <span className="grow">
          無法載入{what}（{status}）。其他區塊資料正常。
        </span>
        {onRetry && (
          <button className="btn sm" onClick={onRetry}>
            重試
          </button>
        )}
      </div>
      <div className="xs muted" style={{ marginTop: 4 }}>
        {errorMessage(error)}
      </div>
    </div>
  );
}
