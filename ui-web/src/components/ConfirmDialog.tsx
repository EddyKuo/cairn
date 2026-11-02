// ConfirmDialog（元件 #10）：分級確認對話框（part3 §3.3.3）。
//   L1 suspend_process            —— 不經此對話框，直接執行 + Toast [復原]
//   L2 quarantine_file / firewall —— 影響清單 + 單次點擊確認（需 token）
//   L3 terminate_process_tree     —— 完整影響清單 + 輸入根程序名確認（token + typed_confirmation）
// 確認強度必須與破壞力匹配；token 由 prepare 取得、TTL 60 秒，對話框顯示倒數。
import { useEffect, useState } from 'react';
import { ACTION_ICON, ACTION_LABEL } from '../lib/format';
import type { PrepareResponse } from '../lib/types';
import { Modal } from './Overlay';

interface Props {
  prep: PrepareResponse;
  busy: boolean;
  notice?: string | null; // 例如「程序樹已變化，已重新取得影響清單」
  fieldError?: string | null; // 例如打字確認不符
  onConfirm: (typed: string, reason: string) => void;
  onCancel: () => void;
  onExpired: () => void;
}

export function ConfirmDialog({ prep, busy, notice, fieldError, onConfirm, onCancel, onExpired }: Props) {
  const [typed, setTyped] = useState('');
  const [reason, setReason] = useState('');
  const [left, setLeft] = useState<number | null>(null);
  const isL3 = prep.risk_level === 'L3' || prep.require_typed_confirmation;
  const expected = prep.typed_confirmation_expected ?? '';
  const typedOk = !isL3 || typed.trim().toLowerCase() === expected.toLowerCase();
  const reasonOk = !isL3 || reason.trim().length > 0;

  useEffect(() => {
    if (!prep.expires_at) return;
    const exp = new Date(prep.expires_at).getTime();
    let fired = false;
    const tick = () => {
      const s = Math.max(0, Math.round((exp - Date.now()) / 1000));
      setLeft(s);
      if (s === 0 && !fired) {
        fired = true;
        onExpired();
      }
    };
    tick();
    const h = window.setInterval(tick, 1000);
    return () => window.clearInterval(h);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [prep.expires_at, prep.confirmation_token]);

  const procs = prep.impact.processes ?? [];
  const files = prep.impact.files ?? [];
  const ips = prep.impact.ips ?? [];
  const warnings = procs.filter((p) => p.warning);
  const title = `${ACTION_ICON[prep.action]} ${ACTION_LABEL[prep.action]}`;
  const count = prep.impact.total_count;

  return (
    <Modal title={title} onClose={busy ? () => {} : onCancel}>
      {notice && <div className="banner warning" style={{ borderRadius: 6, marginBottom: 8 }}>{notice}</div>}
      <p>
        此動作將影響以下 {count} 個目標
        {prep.reversible ? '，可於「已執行動作」中還原。' : <>，且 <strong className="fg-critical">無法復原</strong>：</>}
      </p>
      <div className="impact-list">
        {procs.map((p) => (
          <div key={p.process_guid} className="row sm">
            <span>•</span>
            <span className="grow">
              {p.name} <span className="mono muted">({p.pid})</span>
            </span>
            {p.warning && <span className={p.warning_level === 'high' ? 'fg-critical' : 'fg-warning'}>⚠</span>}
          </div>
        ))}
        {files.map((f) => (
          <div key={f.path} className="sm">
            • <span className="mono">{f.path}</span>
            {f.sha256 && <div className="xs mono muted">sha256:{f.sha256}</div>}
            {f.warning && <div className="xs fg-warning">⚠ {f.warning}</div>}
          </div>
        ))}
        {ips.map((i) => (
          <div key={i.ip} className="sm">
            • <span className="mono">{i.ip}{i.port ? `:${i.port}` : ''}</span>
            {i.warning && <span className="xs fg-warning"> ⚠ {i.warning}</span>}
          </div>
        ))}
      </div>
      {(prep.impact.protected_process_count ?? 0) > 0 && (
        <p className="sm fg-warning">⚠ 其中 {prep.impact.protected_process_count} 個為受保護程序（PPL），動作可能失敗並將誠實記錄。</p>
      )}
      {warnings.map((w) => (
        <p key={w.process_guid} className="sm fg-warning">
          ⚠ {w.name}：{w.warning}
        </p>
      ))}
      {isL3 && (
        <label className="col" style={{ gap: 4, marginTop: 8 }}>
          <span className="sm">
            請輸入根程序名稱以確認：<span className="mono">{expected}</span>
          </span>
          <div className="row">
            <input
              className="input grow mono"
              value={typed}
              onChange={(e) => setTyped(e.target.value)}
              aria-invalid={!typedOk}
              autoComplete="off"
              spellCheck={false}
            />
            {typed && (typedOk ? <span className="fg-success">✓</span> : <span className="fg-critical">✗</span>)}
          </div>
          {fieldError && <span className="field-error">{fieldError}</span>}
        </label>
      )}
      <label className="col" style={{ gap: 4, marginTop: 8 }}>
        <span className="sm">執行原因（將寫入稽核記錄）{isL3 ? '' : '（選填）'}</span>
        <textarea className="textarea" value={reason} onChange={(e) => setReason(e.target.value)} />
      </label>
      <div className="row" style={{ justifyContent: 'space-between', marginTop: 16 }}>
        <span className="xs muted">{left !== null && `確認 token 剩餘 ${left} 秒`}</span>
        <div className="row">
          <button className="btn" onClick={onCancel} disabled={busy}>
            取消
          </button>
          <button
            className={`btn ${prep.reversible ? 'primary' : 'danger'}`}
            disabled={busy || !typedOk || !reasonOk || left === 0}
            onClick={() => onConfirm(typed.trim(), reason.trim())}
          >
            {busy ? '執行中…' : isL3 ? `⛔ 確認終止 (${count})` : `確認${ACTION_LABEL[prep.action]}`}
          </button>
        </div>
      </div>
    </Modal>
  );
}
