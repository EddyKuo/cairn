// ExclusionBuilder（元件 #11）：標記誤報 → 產生排除規則（part3 §3.3.2）。
// - 依據預設選「簽章者」（最穩健）；無有效簽章時禁用並說明原因
// - 影響預覽是防止安全黑洞的核心防呆：曾判為真陽性者 > 0 時轉紅並要求額外確認
// - 送出：POST /alerts/{id}/verdict（含 create_exclusion）→ 回應 undo_token 供 10 秒復原
import { useEffect, useMemo, useState } from 'react';
import { api, errorMessage } from '../lib/api';
import { basename } from '../lib/format';
import type { AlertDetail, ExclusionKind, ExclusionPreview } from '../lib/types';
import { Drawer } from './Overlay';

const REASONS = ['合法軟體的正常行為', '內部自製工具', '備份 / 同步軟體', '開發 / 編譯工具', '系統管理作業'];

interface Basis {
  kind: ExclusionKind;
  value: string;
  label: string;
  tag: string;
  hint: string;
  disabled?: string;
}

export function ExclusionBuilder({
  alert,
  onClose,
  onDone,
}: {
  alert: AlertDetail;
  onClose: () => void;
  onDone: (res: { undoToken?: string; affected: number; exclusionCreated: boolean }) => void;
}) {
  const focus = alert.process_tree.find((p) => p.process_guid === alert.focus_process_guid) ?? alert.process_tree[0];
  const primaryRule = alert.matched_rules.find((r) => r.status === 'enabled')?.rule_id ?? alert.matched_rules[0]?.rule_id ?? '';

  const bases: Basis[] = useMemo(() => {
    const dir = focus?.image_path ? focus.image_path.slice(0, focus.image_path.length - basename(focus.image_path).length) : '';
    return [
      {
        kind: 'signer',
        value: focus?.signer ?? '',
        label: `簽章者 ${focus?.signer ?? '—'}`,
        tag: '🛡 最穩健',
        hint: '涵蓋該廠商所有已簽章檔案，不受版本更新或路徑變動影響',
        disabled: focus?.signature_status === 'valid' && focus.signer ? undefined : '此檔案無有效簽章，無法以簽章者排除',
      },
      {
        kind: 'sha256',
        value: focus?.image_sha256 ?? '',
        label: `檔案雜湊 ${focus?.image_sha256 ? `${focus.image_sha256.slice(0, 6)}…${focus.image_sha256.slice(-4)}` : '—'}`,
        tag: '🎯 最精確',
        hint: '僅此一個檔案版本；軟體更新後排除將失效，需重新標記',
        disabled: focus?.image_sha256 ? undefined : '無檔案雜湊（需安裝 Sysmon 才能取得）',
      },
      {
        kind: 'path_glob',
        value: dir ? `${dir}**` : '',
        label: `路徑 ${dir ? `${dir}**` : '—'}`,
        tag: '⚠ 較寬鬆',
        hint: '攻擊者若能寫入此目錄即可繞過防護',
        disabled: dir ? undefined : '無映像路徑',
      },
    ];
  }, [focus]);

  const [reason, setReason] = useState(REASONS[0]);
  const [other, setOther] = useState('');
  const [create, setCreate] = useState(true);
  const [basisIdx, setBasisIdx] = useState(() => Math.max(0, bases.findIndex((b) => !b.disabled)));
  const [scope, setScope] = useState<'rule' | 'all'>('rule');
  const [preview, setPreview] = useState<ExclusionPreview | null>(null);
  const [previewErr, setPreviewErr] = useState<string | null>(null);
  const [ackRisk, setAckRisk] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const basis = bases[basisIdx];
  const scopeValue = scope === 'rule' ? primaryRule : '';

  useEffect(() => {
    if (!create || !basis || basis.disabled) {
      setPreview(null);
      return;
    }
    let alive = true;
    setPreview(null);
    setPreviewErr(null);
    setAckRisk(false);
    api
      .previewExclusion(basis.kind, basis.value, scopeValue)
      .then((p) => alive && setPreview(p))
      .catch((e) => alive && setPreviewErr(errorMessage(e)));
    return () => {
      alive = false;
    };
  }, [create, basis, scopeValue]);

  const risky = (preview?.previously_true_positive_count ?? 0) > 0;
  const canSubmit = !busy && (!create || (basis && !basis.disabled && preview !== null && (!risky || ackRisk)));

  const submit = async () => {
    setBusy(true);
    setErr(null);
    try {
      const r = await api.setVerdict(alert.alert_id, {
        verdict: 'false_positive',
        fp_reason: reason === '其他' ? other : reason,
        create_exclusion: create && basis ? { type: basis.kind, value: basis.value, scope: scopeValue } : undefined,
      });
      onDone({ undoToken: r.undo_token, affected: r.affected_alerts?.length ?? 0, exclusionCreated: create });
    } catch (e) {
      setErr(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Drawer title="標記為誤報" onClose={onClose}>
      <div className="xs muted mono" style={{ marginBottom: 12 }}>
        {alert.alert_id} · {focus?.name} · {primaryRule}
      </div>
      <fieldset style={{ border: 'none', padding: 0, margin: 0 }}>
        <legend className="sm" style={{ marginBottom: 6 }}>
          誤報原因（選填，用於改善規則）
        </legend>
        <div className="two-col" style={{ gap: 4 }}>
          {[...REASONS, '其他'].map((r) => (
            <label key={r} className="row sm">
              <input type="radio" name="fp-reason" checked={reason === r} onChange={() => setReason(r)} /> {r}
            </label>
          ))}
        </div>
        {reason === '其他' && (
          <input className="input" style={{ width: '100%', marginTop: 6 }} value={other} onChange={(e) => setOther(e.target.value)} />
        )}
      </fieldset>
      <hr style={{ border: 'none', borderTop: '1px solid var(--border-default)', margin: '16px 0' }} />
      <label className="row">
        <input type="checkbox" checked={create} onChange={(e) => setCreate(e.target.checked)} /> 同時建立排除規則，避免再次告警
      </label>
      {create && (
        <div style={{ paddingLeft: 24 }}>
          <div className="sm" style={{ margin: '12px 0 6px' }}>
            建議依據（系統依訊號強度排序，預設選最穩健者）
          </div>
          {bases.map((b, i) => (
            <label key={b.kind} className="col" style={{ gap: 0, marginBottom: 8, opacity: b.disabled ? 0.55 : 1 }}>
              <span className="row sm">
                <input type="radio" name="basis" disabled={!!b.disabled} checked={basisIdx === i} onChange={() => setBasisIdx(i)} />
                <span className="grow mono ellipsis" title={b.value}>
                  {b.label}
                </span>
                <span className="xs">{b.tag}</span>
              </span>
              <span className="xs muted" style={{ paddingLeft: 22 }}>
                ⓘ {b.disabled ?? b.hint}
              </span>
            </label>
          ))}
          <div className="sm" style={{ margin: '12px 0 6px' }}>
            適用範圍
          </div>
          <div className="row sm">
            <label className="row">
              <input type="radio" name="scope" checked={scope === 'rule'} onChange={() => setScope('rule')} disabled={!primaryRule} /> 僅此規則{' '}
              <span className="mono">{primaryRule}</span>
            </label>
            <label className="row">
              <input type="radio" name="scope" checked={scope === 'all'} onChange={() => setScope('all')} /> 所有規則 <span className="fg-warning">⚠</span>
            </label>
          </div>
          <hr style={{ border: 'none', borderTop: '1px solid var(--border-default)', margin: '16px 0' }} />
          <div className="h3">📊 影響預覽</div>
          {previewErr ? (
            <div className="field-error">無法取得影響預覽：{previewErr}（未取得預覽前不可建立排除）</div>
          ) : !preview ? (
            <div className="skel" style={{ width: '60%', marginTop: 8 }} />
          ) : (
            <div className="sm" style={{ marginTop: 6 }}>
              此排除規則將抑制過去 30 天的 {preview.would_suppress_count} 筆告警
              <br />
              {risky ? (
                <span className="fg-critical">
                  ⚠ 其中 {preview.previously_true_positive_count} 筆曾被標記為真陽性
                </span>
              ) : (
                <span className="fg-success">其中 0 筆曾被標記為真陽性 ✓ 安全</span>
              )}
              {preview.sample_alerts.length > 0 && (
                <details style={{ marginTop: 6 }}>
                  <summary className="xs">檢視這 {preview.would_suppress_count} 筆</summary>
                  {preview.sample_alerts.map((a) => (
                    <div key={a.alert_id} className="xs mono">
                      {a.alert_id} · {a.title}
                    </div>
                  ))}
                </details>
              )}
              {risky && (
                <label className="row sm fg-critical" style={{ marginTop: 6 }}>
                  <input type="checkbox" checked={ackRisk} onChange={(e) => setAckRisk(e.target.checked)} /> 我了解此排除會抑制曾判為真陽性的告警
                </label>
              )}
            </div>
          )}
        </div>
      )}
      {err && (
        <div className="field-error" style={{ marginTop: 12 }}>
          {err}
        </div>
      )}
      <div className="row" style={{ justifyContent: 'flex-end', marginTop: 20 }}>
        <button className="btn" onClick={onClose} disabled={busy}>
          取消
        </button>
        <button className="btn primary" disabled={!canSubmit} onClick={submit}>
          {busy ? '處理中…' : create ? '確認並建立排除規則' : '確認標記為誤報'}
        </button>
      </div>
    </Drawer>
  );
}
