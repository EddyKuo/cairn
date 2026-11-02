// Settings（/settings/:tab，part3 §3.2.5；part4 W4-7）。
// 分頁：排除清單 / 規則（唯讀 + dry-run 切換）/ Agent 健康度 / 稽核記錄（含隔離區還原入口）。
// ⚠ M0 偏差：路由採 HashRouter，分頁以 /settings/<tab> 表達（原規格為 #exclusions 等 hash）。
import { useEffect, useMemo, useState } from 'react';
import { NavLink, useParams } from 'react-router-dom';
import { HealthIndicator, useHealth } from '../components/HealthIndicator';
import { Modal } from '../components/Overlay';
import { RuleStatusTag, SeverityBadge } from '../components/ScoreBadge';
import { EmptyState, InlineError, Skeleton } from '../components/States';
import { AttackTag } from '../components/AttackTag';
import { useToast } from '../components/Toast';
import { api, errorMessage } from '../lib/api';
import { actionLabel, fmtShortDateTime, initiatorLabel, timeTitle } from '../lib/format';
import { useAsync } from '../lib/hooks';
import type { ExclusionKind, ExclusionPreview, RuleStatus } from '../lib/types';

const TABS = [
  { id: 'exclusions', label: '排除清單' },
  { id: 'rules', label: '規則' },
  { id: 'health', label: 'Agent 健康度' },
  { id: 'audit', label: '稽核記錄' },
] as const;

export function Settings() {
  const { tab = 'exclusions' } = useParams();
  return (
    <div className="page">
      <h1 className="h1" style={{ marginBottom: 12 }}>
        設定
      </h1>
      <nav className="tabs" role="tablist">
        {TABS.map((t) => (
          <NavLink key={t.id} to={`/settings/${t.id}`} role="tab" className={() => `tab${tab === t.id ? ' active' : ''}`} aria-selected={tab === t.id}>
            {t.label}
          </NavLink>
        ))}
      </nav>
      {tab === 'exclusions' && <ExclusionsTab />}
      {tab === 'rules' && <RulesTab />}
      {tab === 'health' && <HealthIndicator variant="full" />}
      {tab === 'audit' && <AuditTab />}
    </div>
  );
}

const KIND_LABEL: Record<ExclusionKind, string> = {
  path: '路徑',
  path_glob: '路徑',
  sha256: '雜湊',
  signer: '簽章者',
  rule_id: '規則',
  cmdline_glob: '命令列',
};

const CREATED_BY: Record<string, string> = { user: '誤報標記', learning_mode: '學習期建議', builtin: '內建範本' };

function ExclusionsTab() {
  const toast = useToast();
  const health = useHealth();
  const ex = useAsync((s) => {
    void s;
    return api.listExclusions();
  }, []);
  const sug = useAsync((s) => {
    void s;
    return api.listSuggestions();
  }, []);
  const [adding, setAdding] = useState(false);
  const learning = health.data?.learning_mode;

  const finish = async () => {
    try {
      await api.finishLearning();
      toast({ type: 'success', message: '已結束學習期，系統將開始執行回應動作。' });
      health.reload();
      sug.reload();
    } catch (e) {
      toast({ type: 'error', message: `無法結束學習期：${errorMessage(e)}` });
    }
  };

  const adopt = async (s: { suggestion_id: string | number; type: ExclusionKind; value: string; affected_rule_ids: string[] }) => {
    try {
      // 建議涵蓋多條規則時以全域排除建立；單一規則則限縮範圍
      await api.addExclusion({ type: s.type, value: s.value, scope: s.affected_rule_ids.length === 1 ? s.affected_rule_ids[0] : '', reason: '採納學習期建議' });
      await api.dismissSuggestion(s.suggestion_id).catch(() => undefined);
      toast({ type: 'success', message: '✓ 已採納建議排除。' });
      ex.reload();
      sug.reload();
    } catch (e) {
      toast({ type: 'error', message: `採納失敗：${errorMessage(e)}` });
    }
  };

  const remove = async (id: number | string) => {
    try {
      await api.removeExclusion(id);
      toast({ type: 'success', message: '已刪除排除規則（已寫入稽核記錄）。' });
      ex.reload();
    } catch (e) {
      toast({ type: 'error', message: `刪除失敗：${errorMessage(e)}` });
    }
  };

  return (
    <div className="col" style={{ gap: 16 }}>
      {learning?.active && (
        <div className="banner info row" style={{ borderRadius: 6 }}>
          <span className="grow">
            ⓘ 學習期進度 {learning.day}/{learning.total_days} 天。期滿後系統將依觀察結果產出建議排除清單。
          </span>
          <button className="btn sm" onClick={finish}>
            提前結束學習期
          </button>
        </div>
      )}
      <section>
        <div className="row">
          <h2 className="h2 grow">💡 建議排除（{sug.data?.items.length ?? 0}）</h2>
          {(sug.data?.items.length ?? 0) > 0 && (
            <button
              className="btn sm"
              onClick={async () => {
                await api.dismissSuggestion('all', true).catch((e) => toast({ type: 'error', message: errorMessage(e) }));
                sug.reload();
              }}
            >
              全部忽略
            </button>
          )}
        </div>
        {sug.loading ? (
          <Skeleton lines={2} />
        ) : sug.error && !sug.data ? (
          <InlineError what="建議排除" error={sug.error} onRetry={sug.reload} />
        ) : (sug.data?.items.length ?? 0) === 0 ? (
          <div className="sm muted">目前沒有建議。</div>
        ) : (
          sug.data!.items.map((s) => (
            <div key={s.suggestion_id} className="card" style={{ marginTop: 8 }}>
              <div className="row">
                <span className="grow">
                  {KIND_LABEL[s.type]} <span className="mono">{s.value}</span>
                </span>
                <span className="sm secondary">
                  觸發 {s.triggered_count} 次 · {s.rationale}
                </span>
              </div>
              <div className="row sm" style={{ marginTop: 6 }}>
                <span className="grow">
                  影響規則：<span className="mono">{s.affected_rule_ids.join(', ')}</span>
                </span>
                <details>
                  <summary className="xs">檢視觸發記錄</summary>
                  {s.sample_alert_ids.map((id) => (
                    <div key={id}>
                      <a className="mono xs" href={`#/alerts/${encodeURIComponent(id)}`}>
                        {id}
                      </a>
                    </div>
                  ))}
                </details>
                <button className="btn sm primary" onClick={() => adopt(s)}>
                  ✓ 採納
                </button>
                <button
                  className="btn sm"
                  onClick={async () => {
                    await api.dismissSuggestion(s.suggestion_id).catch((e) => toast({ type: 'error', message: errorMessage(e) }));
                    sug.reload();
                  }}
                  aria-label="忽略此建議"
                >
                  ✗
                </button>
              </div>
            </div>
          ))
        )}
      </section>
      <section>
        <div className="row" style={{ marginBottom: 8 }}>
          <h2 className="h2 grow">已生效排除（{ex.data?.items.length ?? 0}）</h2>
          <button className="btn sm" onClick={() => setAdding(true)}>
            + 新增排除
          </button>
        </div>
        {ex.loading ? (
          <Skeleton lines={4} />
        ) : ex.error && !ex.data ? (
          <InlineError what="排除清單" error={ex.error} onRetry={ex.reload} />
        ) : (ex.data?.items.length ?? 0) === 0 ? (
          <EmptyState
            icon="✓"
            title="尚未建立任何排除規則"
            subtitle="標記告警為誤報時可一併建立排除規則，或直接手動新增。"
            action={
              <button className="btn" onClick={() => setAdding(true)}>
                + 新增排除
              </button>
            }
          />
        ) : (
          <>
            <table className="grid">
              <thead>
                <tr>
                  <th>類型</th>
                  <th>條件</th>
                  <th>適用規則</th>
                  <th>建立來源</th>
                  <th>到期</th>
                  <th>抑制</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                {ex.data!.items.map((x) => (
                  <tr key={x.exclusion_id}>
                    <td>{KIND_LABEL[x.kind] ?? x.kind}</td>
                    <td className="mono" style={{ wordBreak: 'break-all' }}>
                      {x.value}
                    </td>
                    <td className="mono">{x.scope_rule_id || '全部'}</td>
                    <td>
                      {CREATED_BY[x.created_by] ?? x.created_by} <span className="xs muted">{fmtShortDateTime(x.created_at)}</span>
                      {x.created_from_alert_id && (
                        <div>
                          <a className="xs mono" href={`#/alerts/${encodeURIComponent(x.created_from_alert_id)}`}>
                            {x.created_from_alert_id}
                          </a>
                        </div>
                      )}
                    </td>
                    <td className="xs">{x.expires_at ? fmtShortDateTime(x.expires_at) : '永久'}</td>
                    <td className={`mono ${x.suppressed_count_30d > 50 ? 'fg-warning' : ''}`}>{x.suppressed_count_30d}</td>
                    <td>
                      <button className="btn sm danger" onClick={() => remove(x.exclusion_id)} aria-label="刪除排除規則">
                        🗑
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p className="xs muted">⚠「抑制」欄為該排除規則過去 30 天抑制掉的告警數。數字異常高者請檢視是否範圍過寬。</p>
          </>
        )}
      </section>
      {adding && <AddExclusionModal onClose={() => setAdding(false)} onAdded={() => (setAdding(false), ex.reload())} />}
    </div>
  );
}

function AddExclusionModal({ onClose, onAdded }: { onClose: () => void; onAdded: () => void }) {
  const toast = useToast();
  const [kind, setKind] = useState<ExclusionKind>('signer');
  const [value, setValue] = useState('');
  const [scope, setScope] = useState('');
  const [reason, setReason] = useState('');
  const [preview, setPreview] = useState<ExclusionPreview | null>(null);
  const [ack, setAck] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    setPreview(null);
    setAck(false);
    if (!value.trim()) return;
    const h = window.setTimeout(() => {
      api
        .previewExclusion(kind, value.trim(), scope.trim())
        .then(setPreview)
        .catch((e) => setErr(errorMessage(e)));
    }, 400);
    return () => window.clearTimeout(h);
  }, [kind, value, scope]);

  const risky = (preview?.previously_true_positive_count ?? 0) > 0;
  const submit = async () => {
    try {
      await api.addExclusion({ type: kind, value: value.trim(), scope: scope.trim(), reason });
      toast({ type: 'success', message: '✓ 已建立排除規則（已寫入稽核記錄）。' });
      onAdded();
    } catch (e) {
      setErr(errorMessage(e));
    }
  };

  return (
    <Modal title="新增排除規則" onClose={onClose}>
      <div className="col">
        <label className="row sm">
          <span style={{ width: 72 }}>類型</span>
          <select className="select grow" value={kind} onChange={(e) => setKind(e.target.value as ExclusionKind)}>
            <option value="signer">簽章者（最穩健）</option>
            <option value="sha256">檔案雜湊（最精確）</option>
            <option value="path">路徑（完全相符）</option>
            <option value="path_glob">路徑萬用字元（較寬鬆）</option>
            <option value="cmdline_glob">命令列萬用字元</option>
            <option value="rule_id">整條規則</option>
          </select>
        </label>
        <label className="row sm">
          <span style={{ width: 72 }}>條件</span>
          <input className="input grow mono" value={value} onChange={(e) => setValue(e.target.value)} />
        </label>
        <label className="row sm">
          <span style={{ width: 72 }}>適用規則</span>
          <input className="input grow mono" placeholder="留空 = 所有規則" value={scope} onChange={(e) => setScope(e.target.value)} />
        </label>
        <label className="col sm" style={{ gap: 4 }}>
          原因
          <textarea className="textarea" value={reason} onChange={(e) => setReason(e.target.value)} />
        </label>
        <div className="card sm">
          📊 影響預覽：
          {!value.trim() ? (
            <span className="muted"> 請先輸入條件</span>
          ) : !preview ? (
            <span className="muted"> 計算中…</span>
          ) : (
            <>
              {' '}將抑制過去 30 天的 {preview.would_suppress_count} 筆告警；
              {risky ? (
                <span className="fg-critical"> 其中 {preview.previously_true_positive_count} 筆曾被標記為真陽性</span>
              ) : (
                <span className="fg-success"> 0 筆曾被標記為真陽性 ✓</span>
              )}
              {risky && (
                <label className="row fg-critical" style={{ marginTop: 6 }}>
                  <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} /> 我了解此風險
                </label>
              )}
            </>
          )}
        </div>
        {err && <div className="field-error">{err}</div>}
        <div className="row" style={{ justifyContent: 'flex-end' }}>
          <button className="btn" onClick={onClose}>
            取消
          </button>
          <button className="btn primary" disabled={!preview || (risky && !ack)} onClick={submit}>
            建立
          </button>
        </div>
      </div>
    </Modal>
  );
}

function RulesTab() {
  const toast = useToast();
  const rules = useAsync((s) => {
    void s;
    return api.listRules();
  }, []);
  const setStatus = async (id: string, status: RuleStatus) => {
    try {
      await api.setRuleStatus(id, status);
      toast({ type: 'success', message: `${id} 已切換為 ${status === 'enabled' ? '啟用' : 'dry-run'}（已寫入稽核記錄）。` });
      rules.reload();
    } catch (e) {
      toast({ type: 'error', message: `切換失敗：${errorMessage(e)}` });
    }
  };
  if (rules.loading) return <Skeleton lines={6} />;
  if (rules.error && !rules.data) return <InlineError what="規則清單" error={rules.error} onRetry={rules.reload} />;
  const d = rules.data!;
  return (
    <div>
      <p className="sm secondary">
        規則包版本 <span className="mono">{d.pack_version}</span> ·{' '}
        {d.pack_signature_valid ? <span className="fg-success">✓ 簽章有效</span> : <span className="fg-warning">⚠ 未簽章（M0 內部使用）</span>}
        。M0 規則以 YAML 檔維護，此處僅提供唯讀檢視與 dry-run 切換。dry-run 規則的命中只計入「影子分數」，不參與告警與回應。
      </p>
      <table className="grid">
        <thead>
          <tr>
            <th>規則</th>
            <th>嚴重度</th>
            <th>分數</th>
            <th>ATT&amp;CK</th>
            <th>30 天命中 / 誤報率</th>
            <th>若啟用（影子告警 / 誤報率）</th>
            <th>狀態</th>
          </tr>
        </thead>
        <tbody>
          {d.items.map((r) => (
            <tr key={r.rule_id}>
              <td>
                <div className="mono" style={{ fontWeight: 600 }}>
                  {r.rule_id}
                </div>
                <div className="sm">{r.title}</div>
                {r.load_error && <div className="xs fg-critical">⚠ 載入失敗：{r.load_error}</div>}
              </td>
              <td>
                <SeverityBadge level={r.severity} />
              </td>
              <td className="mono">{r.score}</td>
              <td>
                <div className="col" style={{ gap: 2 }}>
                  {r.attack_ids.map((a) => (
                    <AttackTag key={a} techniqueId={a} />
                  ))}
                </div>
              </td>
              <td className="mono">
                {r.hits_30d} / {(r.fp_rate_30d * 100).toFixed(0)}%
              </td>
              <td className="mono">
                {r.status === 'dryrun' ? `${r.shadow_alerts_30d} / ${(r.shadow_fp_rate_30d * 100).toFixed(0)}%` : '—'}
              </td>
              <td>
                {r.status === 'disabled' ? (
                  <RuleStatusTag status="disabled" />
                ) : (
                  <div className="row">
                    <RuleStatusTag status={r.status} />
                    <button className="btn sm" onClick={() => setStatus(r.rule_id, r.status === 'enabled' ? 'dryrun' : 'enabled')}>
                      {r.status === 'enabled' ? '改為 dry-run' : '啟用'}
                    </button>
                  </div>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

type AuditRange = '24h' | '7d' | '30d' | '90d';

function AuditTab() {
  const [range, setRange] = useState<AuditRange>('30d');
  const [q, setQ] = useState('');
  const from = useMemo(() => {
    const d = { '24h': 1, '7d': 7, '30d': 30, '90d': 90 }[range];
    return new Date(Date.now() - d * 86_400_000).toISOString();
  }, [range]);
  const audit = useAsync((s) => {
    void s;
    return api.listAudit({ from, q: q || undefined });
  }, [from, q]);
  const quarantine = useAsync((s) => {
    void s;
    return api.listQuarantine();
  }, []);

  return (
    <div className="col" style={{ gap: 16 }}>
      <div className="toolbar">
        <input className="input" placeholder="🔍 搜尋" value={q} onChange={(e) => setQ(e.target.value)} />
        <select className="select" value={range} onChange={(e) => setRange(e.target.value as AuditRange)}>
          <option value="24h">24 小時</option>
          <option value="7d">7 天</option>
          <option value="30d">30 天</option>
          <option value="90d">90 天</option>
        </select>
      </div>
      {audit.data && !audit.data.chain_valid && (
        <div className="banner danger" style={{ borderRadius: 6 }}>
          ⚠ 稽核記錄完整性校驗鏈驗證失敗：至少一筆記錄可能已被竄改。請保留資料庫檔案並通報資安人員。
        </div>
      )}
      {audit.loading ? (
        <Skeleton lines={6} />
      ) : audit.error && !audit.data ? (
        <InlineError what="稽核記錄" error={audit.error} onRetry={audit.reload} />
      ) : audit.data!.items.length === 0 ? (
        <EmptyState
          icon="📋"
          title="此期間內沒有稽核記錄"
          subtitle="所有回應動作與設定變更都會記錄於此。"
          action={
            <button className="btn" onClick={() => setRange('90d')}>
              擴大時間範圍
            </button>
          }
        />
      ) : (
        <table className="grid">
          <thead>
            <tr>
              <th>時間</th>
              <th>動作</th>
              <th>目標</th>
              <th>發起者</th>
              <th>結果</th>
              <th>關聯</th>
              <th>鏈雜湊</th>
            </tr>
          </thead>
          <tbody>
            {audit.data!.items.map((x) => (
              <tr key={x.audit_id}>
                <td className="mono xs" title={timeTitle(x.time)}>
                  {fmtShortDateTime(x.time)}
                </td>
                <td>
                  {x.event_kind === 'reverted' ? '還原：' : ''}
                  {actionLabel(x.action)}
                  {x.reason && <div className="xs muted">{x.reason}</div>}
                </td>
                <td className="mono xs" style={{ wordBreak: 'break-all' }}>
                  {x.target ?? '—'}
                </td>
                <td className="xs">{initiatorLabel(x.initiator)}</td>
                <td className={`xs ${x.result === 'ok' || x.result === 'success' ? 'fg-success' : x.result === 'failed' ? 'fg-critical' : 'fg-warning'}`}>
                  {x.result === 'ok' || x.result === 'success' ? '成功' : x.result === 'failed' ? '失敗' : '部分成功'}
                </td>
                <td>
                  {x.related_alert_id ? (
                    <a className="mono xs" href={`#/alerts/${encodeURIComponent(x.related_alert_id)}`}>
                      {x.related_alert_id}
                    </a>
                  ) : (
                    '—'
                  )}
                </td>
                <td className="mono xs muted" title={[x.chain_hash, x.confirmation_token_sha256 && `token:${x.confirmation_token_sha256}`, x.impact_snapshot_sha256 && `impact:${x.impact_snapshot_sha256}`].filter(Boolean).join('\n')}>
                  {x.chain_hash.slice(0, 10)}…
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <p className="xs muted">🔒 稽核記錄為僅可新增（append-only）且具完整性校驗鏈，無法由 UI 刪除或修改。</p>

      <section>
        <h2 className="h2" style={{ marginBottom: 8 }}>
          隔離區
        </h2>
        {quarantine.loading ? (
          <Skeleton lines={2} />
        ) : quarantine.error && !quarantine.data ? (
          <InlineError what="隔離區清單" error={quarantine.error} onRetry={quarantine.reload} />
        ) : quarantine.data!.items.length === 0 ? (
          <div className="sm muted">隔離區內沒有檔案。</div>
        ) : (
          <table className="grid">
            <thead>
              <tr>
                <th>原始路徑</th>
                <th>SHA256</th>
                <th>隔離時間</th>
                <th>關聯告警</th>
                <th>狀態</th>
              </tr>
            </thead>
            <tbody>
              {quarantine.data!.items.map((qi) => (
                <tr key={qi.quarantine_id}>
                  <td className="mono xs" style={{ wordBreak: 'break-all' }}>
                    {qi.original_path}
                  </td>
                  <td className="mono xs">{qi.sha256.slice(0, 12)}…</td>
                  <td className="xs">{fmtShortDateTime(qi.quarantined_at)}</td>
                  <td>
                    {qi.alert_id ? (
                      <a className="mono xs" href={`#/alerts/${encodeURIComponent(qi.alert_id)}`} title="至告警詳情的「已執行動作」還原">
                        {qi.alert_id}
                      </a>
                    ) : (
                      '—'
                    )}
                  </td>
                  <td className="xs">{qi.restored ? '已還原' : '隔離中'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <p className="xs muted">還原請至關聯告警的「已執行動作」區操作（需二次確認與打字確認）。</p>
      </section>
    </div>
  );
}
