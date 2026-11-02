// Alert Detail（/alerts/:alertId，part3 §3.2.3；part4 W3-12）。
// 版面：左欄（60%）＝ 確定性證據（程序樹、時間軸、已執行動作），右欄（40%）＝ AI 解釋 + 命中規則。
// 左欄不等 AI：告警詳情（端點 3）與敘事（端點 4）是兩個獨立請求，右欄的任何狀態都不影響左欄（§3.5.3 規則 3）。
import { useCallback, useMemo, useRef, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { AttackTag } from '../components/AttackTag';
import { ExclusionBuilder } from '../components/ExclusionBuilder';
import { NarrativePanel } from '../components/NarrativePanel';
import { Modal } from '../components/Overlay';
import { ProcessTreeView } from '../components/ProcessTreeView';
import { ResponseMenu } from '../components/ResponseMenu';
import { RiskScore, RuleStatusTag, SeverityBadge, StatusBadge } from '../components/ScoreBadge';
import { InlineError, Skeleton, SlowHint } from '../components/States';
import { EventList, EventTimeline, type Lane } from '../components/TimelineView';
import { useToast } from '../components/Toast';
import { api, ApiError, errorMessage, isNonIdempotentError } from '../lib/api';
import { ACTION_ICON, actionLabel, copyText, fmtDateTime, fmtTime, initiatorLabel, timeTitle } from '../lib/format';
import { useAsync, useHotkeys } from '../lib/hooks';
import type { ActionTaken, AlertDetail as AlertDetailT, Disclaimer, InjectionEdge, TimelineEvent } from '../lib/types';

export function AlertDetail() {
  const { alertId = '' } = useParams();
  const navigate = useNavigate();
  const toast = useToast();
  const detail = useAsync<AlertDetailT>((s) => api.getAlert(alertId, s), [alertId]);
  // j/k 切換相鄰告警（與佇列預設排序一致）
  const neighbors = useAsync((s) => api.listAlerts({ sort: 'risk_desc', limit: 100 }, s), []);

  const [hoverGuid, setHoverGuid] = useState<string | null>(null);
  const [hoverEvent, setHoverEvent] = useState<TimelineEvent | null>(null);
  const [activeEvent, setActiveEvent] = useState<number | null>(null);
  const [expandedEv, setExpandedEv] = useState<Set<number>>(new Set());
  const [brush, setBrush] = useState<[number, number] | null>(null);
  const [collapseMode, setCollapseMode] = useState<'default' | 'attack_path' | 'all'>('default');
  const [fpOpen, setFpOpen] = useState(false);
  const [highlightRule, setHighlightRule] = useState<string | null>(null);
  const actionsRef = useRef<HTMLDivElement>(null);

  const a = detail.data;

  const go = (delta: number) => {
    const items = neighbors.data?.items ?? [];
    const i = items.findIndex((x) => x.alert_id === alertId);
    const next = items[i + delta];
    if (next) navigate(`/alerts/${encodeURIComponent(next.alert_id)}`);
  };

  useHotkeys(
    {
      j: () => go(1),
      k: () => go(-1),
      Escape: () => navigate('/alerts'),
      f: () => a && setFpOpen(true),
    },
    !fpOpen,
  );

  // 時間軸 lane 順序與程序樹可見順序一致（以樹的深度優先順序近似）
  const lanes: Lane[] = useMemo(() => {
    if (!a) return [];
    const withEvents = new Set(a.timeline.map((e) => e.process_guid));
    const order: Lane[] = [];
    const kids = new Map<string | null, typeof a.process_tree>();
    for (const p of a.process_tree) {
      const k = p.parent_guid && a.process_tree.some((x) => x.process_guid === p.parent_guid) ? p.parent_guid : null;
      kids.set(k, [...(kids.get(k) ?? []), p]);
    }
    const walk = (k: string | null) => {
      for (const p of kids.get(k) ?? []) {
        if (withEvents.has(p.process_guid) || p.is_focus) order.push({ guid: p.process_guid, label: p.name });
        walk(p.process_guid);
      }
    };
    walk(null);
    return order;
  }, [a]);

  const highlighted = useMemo(() => {
    const s = new Set<string>();
    if (hoverGuid) s.add(hoverGuid);
    if (hoverEvent) s.add(hoverEvent.process_guid);
    return s;
  }, [hoverGuid, hoverEvent]);

  const dimmed = useMemo(() => {
    if (!brush || !a) return null;
    return new Set(
      a.timeline
        .filter((e) => {
          const t = new Date(e.time).getTime();
          return t >= brush[0] && t <= brush[1];
        })
        .map((e) => e.process_guid),
    );
  }, [brush, a]);

  const selectEvent = useCallback((ev: TimelineEvent) => {
    setActiveEvent(ev.event_id);
    setExpandedEv((s) => new Set(s).add(ev.event_id));
    window.setTimeout(() => document.getElementById(`ev-${ev.event_id}`)?.scrollIntoView({ block: 'nearest', behavior: 'smooth' }), 0);
  }, []);

  const onEdgeClick = (e: InjectionEdge) => {
    setHoverGuid(e.target_guid);
    const ev = a?.timeline.find((t) => t.process_guid === e.source_guid && t.time === e.occurred_at);
    if (ev) selectEvent(ev);
  };

  const onEntityClick = useCallback(
    (type: string, ref: string) => {
      if (!a) return;
      if (type === 'process') {
        setHoverGuid(ref);
        document.querySelector(`[data-guid="${CSS.escape(ref)}"]`)?.scrollIntoView({ block: 'center', behavior: 'smooth' });
        return;
      }
      const ev = a.timeline.find((e) => (e.target ?? '').includes(ref) || e.summary.includes(ref) || e.remote_addr === ref);
      if (ev) selectEvent(ev);
    },
    [a, selectEvent],
  );

  const markResolved = async () => {
    if (!a) return;
    try {
      const r = await api.setVerdict(a.alert_id, { workflow_status: 'resolved', verdict: a.analyst_verdict ?? 'true_positive' });
      toast({
        type: 'success',
        message: '✓ 已標記為已處理',
        undoAction: r.undo_token ? async () => void (await api.undo(r.undo_token!).catch(() => undefined), detail.reload()) : undefined,
      });
      detail.reload();
    } catch (e) {
      toast({
        type: 'error',
        message: isNonIdempotentError(e) ? '連線中斷，無法確認是否已更新，請稍後重新整理確認。' : `更新失敗：${errorMessage(e)}`,
      });
    }
  };

  if (detail.loading) {
    return (
      <div className="page">
        <Skeleton lines={2} />
        <div className="detail-grid" style={{ marginTop: 24 }}>
          <Skeleton lines={8} shape="tree" />
          <Skeleton lines={6} />
        </div>
        <SlowHint show={detail.slow} />
      </div>
    );
  }
  if (!a) {
    if (detail.error instanceof ApiError && detail.error.status === 404)
      return (
        <div className="page">
          <button className="btn" onClick={() => navigate('/alerts')}>
            ◀ 返回佇列
          </button>
          <p>找不到告警 {alertId}（可能已超過 90 天保留期）。</p>
        </div>
      );
    return (
      <div className="page">
        <InlineError what="告警詳情" error={detail.error} onRetry={detail.reload} />
      </div>
    );
  }

  const enabledRules = a.matched_rules.filter((r) => r.status === 'enabled');
  const fallbackDisclaimer: Disclaimer = {
    text: '本敘事由本機 LLM 生成，僅供理解與分流參考。它未參與、也無權參與任何偵測或阻擋決策。',
    actual_decision_basis: {
      rule_ids: enabledRules.map((r) => r.rule_id),
      risk_score: a.risk_score,
      threshold: 80,
      sentence: `本次${a.status === 'auto_blocked' ? '阻擋' : '告警'}由規則 ${enabledRules.map((r) => r.rule_id).join('、') || '—'} 與風險分數 ${a.risk_score}（門檻 80）觸發。`,
    },
  };
  const autoBlocked = a.status === 'auto_blocked';

  return (
    <div className="page">
      <div className="row" style={{ marginBottom: 12 }}>
        <button className="btn" onClick={() => navigate('/alerts')}>
          ◀ 返回佇列
        </button>
        <span className="grow" />
        <span className="mono muted">{a.alert_id}</span>
        <button className="btn sm" onClick={() => go(-1)} title="上一筆 (k)">
          ↑ k
        </button>
        <button className="btn sm" onClick={() => go(1)} title="下一筆 (j)">
          ↓ j
        </button>
      </div>
      <div className="detail-head">
        <div className="row wrap">
          <SeverityBadge level={a.severity} variant="solid" />
          <span className="sm">風險分數</span>
          <RiskScore score={a.risk_score} showBar />
          {a.shadow_risk_score !== undefined && a.shadow_risk_score > a.risk_score && (
            <span className="xs fg-dryrun" title="含所有 dry-run 規則的假設分數（未計入回應決策）">
              （含 dry-run：{a.shadow_risk_score}）
            </span>
          )}
          <h1 className="h3" style={{ marginLeft: 8 }}>
            {a.title}
          </h1>
        </div>
        <div className="sm secondary" style={{ marginTop: 4 }}>
          <span title={timeTitle(a.created_at)}>{fmtDateTime(a.created_at, true)}</span> · {a.hostname}
          {a.user_name && <> · 使用者 {a.user_name}</>} · <StatusBadge status={a.analyst_verdict === 'false_positive' ? 'false_positive' : a.status} />
          {autoBlocked && <span className="fg-blocked">（分數 {a.risk_score} ≥ 95，不等 LLM）</span>}
        </div>
        {a.summary && <div className="sm" style={{ marginTop: 4 }}>{a.summary}</div>}
        <div className="row wrap" style={{ marginTop: 12 }}>
          <button className="btn" onClick={() => setFpOpen(true)} disabled={a.analyst_verdict === 'false_positive'}>
            ⚑ 標記為誤報
          </button>
          <button className="btn" onClick={markResolved} disabled={a.status === 'resolved'}>
            ✓ 標記為已處理
          </button>
          <ResponseMenu
            alert={a}
            onChanged={detail.reload}
            onShowActions={() => actionsRef.current?.scrollIntoView({ behavior: 'smooth' })}
          />
          <button
            className="btn"
            onClick={async () => toast({ type: (await copyText(JSON.stringify(a, null, 2))) ? 'success' : 'error', message: '已複製告警 JSON' })}
          >
            ⧉ 複製 JSON
          </button>
        </div>
      </div>

      <div className="detail-grid">
        {/* ---------------- 左欄：證據 ---------------- */}
        <div className="col" style={{ gap: 16, minWidth: 0 }}>
          <section className="card">
            <div className="row" style={{ marginBottom: 8 }}>
              <h2 className="h2 grow">程序樹</h2>
              <button className={`btn sm toggle${collapseMode === 'all' ? ' on' : ''}`} onClick={() => setCollapseMode(collapseMode === 'all' ? 'default' : 'all')}>
                展開全部
              </button>
              <button
                className={`btn sm toggle${collapseMode === 'attack_path' ? ' on' : ''}`}
                onClick={() => setCollapseMode(collapseMode === 'attack_path' ? 'default' : 'attack_path')}
              >
                僅顯示攻擊路徑
              </button>
            </div>
            <ProcessTreeView
              nodes={a.process_tree}
              edges={a.injection_edges}
              focusGuid={a.focus_process_guid}
              highlightedGuids={highlighted}
              dimmedGuids={dimmed}
              onHoverNode={setHoverGuid}
              onRuleClick={(id) => {
                setHighlightRule(id);
                document.getElementById(`rule-${id}`)?.scrollIntoView({ behavior: 'smooth', block: 'center' });
              }}
              onEdgeClick={onEdgeClick}
              collapseMode={collapseMode}
            />
          </section>

          <section className="card">
            <h2 className="h2" style={{ marginBottom: 8 }}>
              行為時間軸
            </h2>
            <EventTimeline
              events={a.timeline}
              lanes={lanes}
              gaps={a.telemetry_gaps}
              anchorTime={a.created_at}
              highlightedGuid={hoverGuid ?? hoverEvent?.process_guid ?? null}
              activeEventId={activeEvent}
              onHoverEvent={setHoverEvent}
              onClickEvent={selectEvent}
              onBrush={setBrush}
            />
            <div style={{ marginTop: 12 }}>
              <EventList
                events={a.timeline}
                gaps={a.telemetry_gaps}
                expandedIds={expandedEv}
                activeEventId={activeEvent}
                filterRange={brush}
                onHoverEvent={setHoverEvent}
                onToggle={(id) =>
                  setExpandedEv((s) => {
                    const t = new Set(s);
                    if (t.has(id)) t.delete(id);
                    else t.add(id);
                    return t;
                  })
                }
              />
            </div>
          </section>

          <section className="card" ref={actionsRef}>
            <h2 className="h2" style={{ marginBottom: 8 }}>
              已執行動作（{a.actions_taken.length}）
            </h2>
            {a.actions_taken.length === 0 ? (
              <div className="sm muted">尚未執行任何回應動作。</div>
            ) : (
              a.actions_taken.map((x) => <ActionRow key={x.action_id} alertId={a.alert_id} x={x} onChanged={detail.reload} />)
            )}
          </section>
        </div>

        {/* ---------------- 右欄：AI 解釋 + 命中規則 ---------------- */}
        <div className="col" style={{ gap: 16, minWidth: 0 }}>
          <div className="card ai-column">
            <NarrativePanel alertId={a.alert_id} fallbackDisclaimer={fallbackDisclaimer} onEntityClick={onEntityClick} />
          </div>
          <section className="card">
            <h2 className="h2" style={{ marginBottom: 8 }}>
              命中規則（{a.matched_rules.length}）
            </h2>
            {a.matched_rules.map((r) => (
              <div
                key={r.rule_id}
                id={`rule-${r.rule_id}`}
                className="card"
                style={{
                  padding: 10,
                  marginBottom: 8,
                  borderColor: highlightRule === r.rule_id ? 'var(--semantic-info)' : undefined,
                }}
              >
                <div className="row">
                  <span className="mono" style={{ fontWeight: 600 }}>
                    {r.rule_id}
                  </span>
                  <SeverityBadge level={r.severity} />
                  <span className="mono">+{r.score}</span>
                  <span className="grow" />
                  <RuleStatusTag status={r.status} />
                </div>
                <div className="sm">{r.title}</div>
                <div className="xs muted">
                  {r.steps_total !== undefined && `步驟 ${r.steps_matched ?? 0}/${r.steps_total}${r.steps_matched === r.steps_total ? ' 全數命中' : ''}`}
                  {r.window_seconds !== undefined && ` · 視窗 ${r.window_seconds}s`}
                  {r.status === 'dryrun' && '（觀察中，未計入回應）'}
                </div>
                <div className="row wrap" style={{ marginTop: 4 }}>
                  {r.attack_ids.map((id) => (
                    <AttackTag key={id} techniqueId={id} />
                  ))}
                </div>
              </div>
            ))}
          </section>
        </div>
      </div>

      {fpOpen && (
        <ExclusionBuilder
          alert={a}
          onClose={() => setFpOpen(false)}
          onDone={({ undoToken, affected, exclusionCreated }) => {
            setFpOpen(false);
            toast({
              type: 'success',
              message: exclusionCreated
                ? `✓ 已標記為誤報並建立排除規則。${affected > 1 ? `過去 ${affected - 1} 筆相似告警已一併關閉。` : ''}`
                : '✓ 已標記為誤報。',
              undoAction: undoToken
                ? async () => {
                    try {
                      await api.undo(undoToken);
                      toast({ type: 'success', message: '已復原誤報標記與排除規則。' });
                    } catch (e) {
                      toast({ type: 'error', message: `復原失敗：${errorMessage(e)}` });
                    }
                    detail.reload();
                  }
                : undefined,
            });
            detail.reload();
          }}
        />
      )}
    </div>
  );
}

// 已執行動作列 + 還原（端點 8b）。還原需 token：先不帶 token 呼叫，伺服器回 403 CONFIRMATION_REQUIRED
// 並在 details 附 confirmation_token（quarantine_file 另附 typed_confirmation_expected，需打字確認——還原的是惡意檔案）。
function ActionRow({ alertId, x, onChanged }: { alertId: string; x: ActionTaken; onChanged: () => void }) {
  const toast = useToast();
  const [confirm, setConfirm] = useState<{ token: string; expected?: string } | null>(null);
  const [typed, setTyped] = useState('');
  const [busy, setBusy] = useState(false);
  const auditId = x.audit_id ?? x.action_id;

  const doRevert = async (token?: string, typedConfirm?: string) => {
    setBusy(true);
    try {
      await api.revertAction(alertId, auditId, { confirmation_token: token, typed_confirmation: typedConfirm });
      setConfirm(null);
      toast({ type: 'success', message: `✓ 已還原：${actionLabel(x.action)} ${x.target}` });
      onChanged();
    } catch (e) {
      if (e instanceof ApiError && e.code === 'CONFIRMATION_REQUIRED' && typeof e.details?.confirmation_token === 'string') {
        setConfirm({
          token: e.details.confirmation_token,
          expected: typeof e.details.typed_confirmation_expected === 'string' ? e.details.typed_confirmation_expected : undefined,
        });
      } else if (e instanceof ApiError && e.code === 'NOT_REVERSIBLE') {
        toast({ type: 'error', message: '此動作不可逆，無法還原。' });
      } else {
        toast({
          type: 'error',
          message: isNonIdempotentError(e) ? '連線中斷，無法確認是否已還原，請至稽核記錄確認。' : `還原失敗：${errorMessage(e)}`,
        });
      }
    } finally {
      setBusy(false);
    }
  };

  const resultCls = x.result === 'success' ? 'fg-success' : x.result === 'failed' ? 'fg-critical' : 'fg-warning';
  return (
    <div className="row sm" style={{ padding: '4px 0', borderBottom: '1px solid var(--border-default)' }}>
      <span className="mono xs" title={timeTitle(x.time)}>
        {fmtTime(x.time, true)}
      </span>
      <span>{ACTION_ICON[x.action] ?? '•'}</span>
      <span className="grow ellipsis" title={x.target}>
        {actionLabel(x.action)} <span className="mono">{x.target}</span>
      </span>
      <span className="xs muted">{initiatorLabel(x.initiator)}</span>
      <span className={`xs ${resultCls}`}>{x.reverted ? '已還原' : x.result === 'success' ? '成功' : x.result === 'failed' ? '失敗' : '部分成功'}</span>
      {x.reversible && !x.reverted && x.result !== 'failed' && (
        <button className="btn sm" disabled={busy} onClick={() => doRevert()} title="還原此動作">
          ↩
        </button>
      )}
      {confirm && (
        <Modal title={`↩ 還原：${actionLabel(x.action)}`} onClose={() => setConfirm(null)}>
          <p>
            將還原 <span className="mono">{x.target}</span>。
            {x.action === 'quarantine_file' && <strong className="fg-warning"> 還原的是被判定可疑的檔案，請確認為誤判。</strong>}
          </p>
          {confirm.expected && (
            <label className="col" style={{ gap: 4 }}>
              <span className="sm">
                請輸入 <span className="mono">{confirm.expected}</span> 以確認：
              </span>
              <input className="input mono" value={typed} onChange={(e) => setTyped(e.target.value)} />
            </label>
          )}
          <div className="row" style={{ justifyContent: 'flex-end', marginTop: 16 }}>
            <button className="btn" onClick={() => setConfirm(null)} disabled={busy}>
              取消
            </button>
            <button
              className="btn primary"
              disabled={busy || (!!confirm.expected && typed.trim().toLowerCase() !== confirm.expected.toLowerCase())}
              onClick={() => doRevert(confirm.token, confirm.expected ? typed.trim() : undefined)}
            >
              確認還原
            </button>
          </div>
        </Modal>
      )}
    </div>
  );
}
