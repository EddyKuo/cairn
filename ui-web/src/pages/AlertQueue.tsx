// Alerts 告警佇列（/alerts，part3 §3.2.2；part4 W2-13）。
// - 2 秒輪詢（part4 W2-13；視窗隱藏時暫停）
// - 預設排序：風險分數降冪 → 時間降冪
// - 鍵盤：j/k 上下、Enter 開啟、f 標記誤報、/ 聚焦搜尋、Esc 清除選取
// - 批次僅「標記為誤報」「標記為已處理」——不可逆動作不支援批次
import { useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { AlertRow } from '../components/AlertRow';
import { EmptyState, InlineError, Skeleton, SlowHint } from '../components/States';
import { useToast } from '../components/Toast';
import { api, errorMessage, isNonIdempotentError } from '../lib/api';
import { useAsync, useHotkeys } from '../lib/hooks';
import type { AlertListQuery, AlertListResponse, AlertSummary, Severity } from '../lib/types';

type TimeRange = '1h' | '24h' | '7d' | '30d' | 'all';
const RANGE_MS: Record<TimeRange, number | null> = {
  '1h': 3_600_000,
  '24h': 86_400_000,
  '7d': 7 * 86_400_000,
  '30d': 30 * 86_400_000,
  all: null,
};

export function AlertQueue({ onCounts }: { onCounts: (pending: number) => void }) {
  const navigate = useNavigate();
  const toast = useToast();
  const searchRef = useRef<HTMLInputElement>(null);

  const [q, setQ] = useState('');
  const [qDebounced, setQDebounced] = useState('');
  const [severity, setSeverity] = useState<Severity | ''>('');
  const [status, setStatus] = useState<string>('');
  const [range, setRange] = useState<TimeRange>('24h');
  const [blockedOnly, setBlockedOnly] = useState(false);
  const [hasNarrative, setHasNarrative] = useState(false);
  const [sort, setSort] = useState<'risk_desc' | 'time_desc'>('risk_desc');
  const [selected, setSelected] = useState(0);
  const [checked, setChecked] = useState<Set<string>>(new Set());
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [extra, setExtra] = useState<AlertSummary[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const seen = useRef<Set<string> | null>(null);
  const [fresh, setFresh] = useState<Set<string>>(new Set());

  useEffect(() => {
    const h = window.setTimeout(() => setQDebounced(q), 250);
    return () => window.clearTimeout(h);
  }, [q]);

  const query: AlertListQuery = useMemo(() => {
    const ms = RANGE_MS[range];
    return {
      q: qDebounced || undefined,
      severity: severity ? [severity] : undefined,
      status: status ? [status] : undefined,
      since: ms ? new Date(Date.now() - ms).toISOString() : undefined,
      blocked_only: blockedOnly,
      has_narrative: hasNarrative,
      sort,
      limit: 20,
    };
    // since 以篩選變更時刻為準；輪詢不重算以免 cursor 漂移
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [qDebounced, severity, status, range, blockedOnly, hasNarrative, sort]);

  const list = useAsync<AlertListResponse>((s) => api.listAlerts(query, s), [query], { pollMs: 2000 });

  useEffect(() => {
    setExtra([]);
    setCursor(null);
    setSelected(0);
    setChecked(new Set());
    seen.current = null;
  }, [query]);

  // 新告警高亮 1.5 秒（§3.3.1 步驟 1）
  useEffect(() => {
    const items = list.data?.items;
    if (!items) return;
    if (seen.current === null) {
      seen.current = new Set(items.map((i) => i.alert_id));
      setCursor(list.data?.next_cursor ?? null);
      return;
    }
    const newIds = items.filter((i) => !seen.current!.has(i.alert_id)).map((i) => i.alert_id);
    newIds.forEach((id) => seen.current!.add(id));
    if (newIds.length) {
      setFresh(new Set(newIds));
      window.setTimeout(() => setFresh(new Set()), 1600);
    }
    if (extra.length === 0) setCursor(list.data?.next_cursor ?? null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [list.data]);

  useEffect(() => {
    if (list.data) onCounts(list.data.stats.pending);
  }, [list.data, onCounts]);

  const items = useMemo(() => {
    const first = list.data?.items ?? [];
    const ids = new Set(first.map((i) => i.alert_id));
    return [...first, ...extra.filter((e) => !ids.has(e.alert_id))];
  }, [list.data, extra]);

  const loadMore = async () => {
    if (!cursor) return;
    setLoadingMore(true);
    try {
      const r = await api.listAlerts({ ...query, cursor });
      setExtra((x) => [...x, ...r.items]);
      setCursor(r.next_cursor);
    } catch (e) {
      toast({ type: 'error', message: `載入更多失敗：${errorMessage(e)}` });
    } finally {
      setLoadingMore(false);
    }
  };

  const open = (a: AlertSummary | undefined) => a && navigate(`/alerts/${encodeURIComponent(a.alert_id)}`);

  const batch = async (kind: 'false_positive' | 'resolved', ids: string[]) => {
    if (ids.length === 0) return;
    let ok = 0;
    const undo: string[] = [];
    for (const id of ids) {
      try {
        const r = await api.setVerdict(
          id,
          kind === 'false_positive' ? { verdict: 'false_positive' } : { workflow_status: 'resolved' },
        );
        ok++;
        if (r.undo_token) undo.push(r.undo_token);
      } catch (e) {
        toast({
          type: 'error',
          message: isNonIdempotentError(e)
            ? `與服務的連線中斷，無法確認 ${id} 是否已更新，請至稽核記錄確認結果。`
            : `${id} 更新失敗：${errorMessage(e)}`,
        });
      }
    }
    setChecked(new Set());
    list.reload();
    if (ok > 0)
      toast({
        type: 'success',
        message: `已將 ${ok} 則告警${kind === 'false_positive' ? '標記為誤報' : '標記為已處理'}。`,
        undoAction: undo.length
          ? async () => {
              for (const t of undo) await api.undo(t).catch(() => undefined);
              list.reload();
            }
          : undefined,
      });
  };

  useHotkeys({
    j: () => setSelected((s) => Math.min(items.length - 1, s + 1)),
    k: () => setSelected((s) => Math.max(0, s - 1)),
    Enter: () => open(items[selected]),
    f: () => items[selected] && batch('false_positive', [items[selected].alert_id]),
    '/': (e) => {
      e.preventDefault();
      searchRef.current?.focus();
    },
    Escape: () => {
      setChecked(new Set());
      searchRef.current?.blur();
    },
  });

  useEffect(() => {
    const id = items[selected]?.alert_id;
    if (id) document.querySelector(`[data-alert-id="${CSS.escape(id)}"]`)?.scrollIntoView({ block: 'nearest' });
  }, [selected, items]);

  const stats = list.data?.stats;
  const filtered = !!(qDebounced || severity || status || blockedOnly || hasNarrative || range !== '24h');
  const clearFilters = () => {
    setQ('');
    setSeverity('');
    setStatus('');
    setRange('24h');
    setBlockedOnly(false);
    setHasNarrative(false);
  };

  return (
    <div className="page">
      <h1 className="h1">告警佇列</h1>
      <div className="stats" role="group" aria-label="統計">
        <Stat label="待處理" v={stats?.pending} active={status === 'pending'} onClick={() => setStatus(status === 'pending' ? '' : 'pending')} />
        <Stat label="觀察中" v={stats?.observing} active={status === 'observing'} onClick={() => setStatus(status === 'observing' ? '' : 'observing')} />
        <Stat label="嚴重" v={stats?.critical} active={severity === 'critical'} onClick={() => setSeverity(severity === 'critical' ? '' : 'critical')} />
        <Stat label="今日新增" v={stats?.today} active={range === '24h' && !status && !severity} onClick={() => setRange('24h')} />
        <Stat label="誤報率" v={stats ? `${(stats.false_positive_rate * 100).toFixed(1)}%` : undefined} />
      </div>
      <div className="toolbar">
        <input
          ref={searchRef}
          className="input"
          style={{ minWidth: 340 }}
          placeholder="🔍 搜尋程序名 / 路徑 / 規則 ID / ATT&CK ID（按 / 聚焦）"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          aria-label="搜尋告警"
        />
        <label className="row sm">
          嚴重度
          <select className="select" value={severity} onChange={(e) => setSeverity(e.target.value as Severity | '')}>
            <option value="">全部</option>
            <option value="critical">嚴重</option>
            <option value="high">高</option>
            <option value="medium">中</option>
            <option value="low">低</option>
          </select>
        </label>
        <label className="row sm">
          狀態
          <select className="select" value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="">全部</option>
            <option value="pending">待處理</option>
            <option value="observing">觀察中</option>
            <option value="auto_blocked">已阻擋</option>
            <option value="resolved">已處理</option>
            <option value="false_positive">已標記誤報</option>
          </select>
        </label>
        <label className="row sm">
          時間
          <select className="select" value={range} onChange={(e) => setRange(e.target.value as TimeRange)}>
            <option value="1h">1 小時</option>
            <option value="24h">24 小時</option>
            <option value="7d">7 天</option>
            <option value="30d">30 天</option>
            <option value="all">全部</option>
          </select>
        </label>
        <button className={`btn sm toggle${blockedOnly ? ' on' : ''}`} aria-pressed={blockedOnly} onClick={() => setBlockedOnly((v) => !v)}>
          ⚑ 只看已阻擋
        </button>
        <button className={`btn sm toggle${hasNarrative ? ' on' : ''}`} aria-pressed={hasNarrative} onClick={() => setHasNarrative((v) => !v)}>
          🤖 只看有 AI 敘事
        </button>
        <span className="grow" />
        <span className="sm muted">已選 {checked.size} 項</span>
        <button className="btn sm" disabled={checked.size === 0} onClick={() => batch('false_positive', [...checked])}>
          批次標記誤報
        </button>
        <button className="btn sm" disabled={checked.size === 0} onClick={() => batch('resolved', [...checked])}>
          批次標記已處理
        </button>
      </div>

      <div className="alert-table" role="grid" aria-label="告警列表">
        <div className="alert-head" role="row">
          <span>
            <input
              type="checkbox"
              aria-label="全選"
              checked={items.length > 0 && checked.size === items.length}
              onChange={(e) => setChecked(e.target.checked ? new Set(items.map((i) => i.alert_id)) : new Set())}
            />
          </span>
          <span>嚴重度</span>
          <button onClick={() => setSort('time_desc')} aria-pressed={sort === 'time_desc'}>
            時間{sort === 'time_desc' ? ' ▾' : ''}
          </button>
          <span>程序</span>
          <span>規則命中</span>
          <button onClick={() => setSort('risk_desc')} aria-pressed={sort === 'risk_desc'}>
            風險{sort === 'risk_desc' ? ' ▾' : ''}
          </button>
          <span>狀態</span>
          <span>AI</span>
          <span>動作</span>
        </div>
        {list.loading ? (
          <>
            <Skeleton lines={6} shape="alert" />
            <SlowHint show={list.slow} />
          </>
        ) : list.error && !list.data ? (
          <div style={{ marginTop: 12 }}>
            <InlineError what="告警列表" error={list.error} onRetry={list.reload} />
          </div>
        ) : items.length === 0 ? (
          filtered ? (
            <EmptyState
              icon="🔍"
              title="沒有符合條件的告警"
              subtitle="請調整或清除目前的篩選條件。"
              action={
                <button className="btn" onClick={clearFilters}>
                  清除篩選
                </button>
              }
            />
          ) : (
            <EmptyState
              icon="🛡"
              title="目前沒有待處理的告警"
              subtitle="防護持續運作中。"
              action={
                <button className="btn" onClick={() => setRange('all')}>
                  檢視已處理告警
                </button>
              }
            />
          )
        ) : (
          items.map((a, i) => (
            <AlertRow
              key={a.alert_id}
              alert={a}
              selected={i === selected}
              checked={checked.has(a.alert_id)}
              expanded={expanded.has(a.alert_id)}
              fresh={fresh.has(a.alert_id)}
              onCheck={(v) =>
                setChecked((s) => {
                  const t = new Set(s);
                  if (v) t.add(a.alert_id);
                  else t.delete(a.alert_id);
                  return t;
                })
              }
              onSelect={() => setSelected(i)}
              onOpen={() => open(a)}
              onToggleExpand={() =>
                setExpanded((s) => {
                  const t = new Set(s);
                  if (t.has(a.alert_id)) t.delete(a.alert_id);
                  else t.add(a.alert_id);
                  return t;
                })
              }
            />
          ))
        )}
      </div>
      {items.length > 0 && (
        <div className="row" style={{ justifyContent: 'center', margin: '16px 0' }}>
          <span className="sm muted">
            顯示 {items.length} 筆 · 共 {stats?.total_matched ?? items.length} 筆
          </span>
          {cursor && (
            <button className="btn" onClick={loadMore} disabled={loadingMore}>
              {loadingMore ? '載入中…' : '載入更多 ▼'}
            </button>
          )}
        </div>
      )}
    </div>
  );
}

function Stat({ label, v, active, onClick }: { label: string; v: number | string | undefined; active?: boolean; onClick?: () => void }) {
  return (
    <button className={`stat${active ? ' active' : ''}`} onClick={onClick} disabled={!onClick} aria-pressed={active}>
      <div className="xs muted">{label}</div>
      <div className="v">{v ?? '—'}</div>
    </button>
  );
}
