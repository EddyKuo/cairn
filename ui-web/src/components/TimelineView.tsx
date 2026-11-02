// EventTimeline（元件 #6）+ EventList（#7）：part3 §3.4.4。
// - X 軸時間，預設視窗 = 告警觸發時刻 ±30 秒，可延伸前／後 60 秒
// - Y 軸 process lane，順序與程序樹一致；lane 色以 process_guid 雜湊決定（與程序樹同色）
// - 標記：● 一般事件、▲ 規則命中、⛔ 我方回應動作；同一像素 > 5 個一般事件聚合為密度條
// - 關鍵事件（規則命中、回應動作）永不聚合
// - 遙測缺口以斜線紋理標示（絕不可讓不完整的資料看起來完整，§3.7.2 ④）
// - 拖曳選取區間 → onBrush（程序樹據此降低區間外節點不透明度）
import { useMemo, useRef, useState, type MouseEvent } from 'react';
import { actionLabel, fmtTime, laneColor, timeTitle } from '../lib/format';
import type { TelemetryGap, TimelineEvent } from '../lib/types';

export interface Lane {
  guid: string;
  label: string;
}

interface TimelineProps {
  events: TimelineEvent[];
  lanes: Lane[];
  gaps: TelemetryGap[];
  anchorTime: string; // 告警觸發時刻
  highlightedGuid?: string | null;
  activeEventId?: number | null;
  onHoverEvent?: (ev: TimelineEvent | null) => void;
  onClickEvent?: (ev: TimelineEvent) => void;
  onBrush?: (range: [number, number] | null) => void;
}

const LANE_H = 26;
const LABEL_W = 96;
const AXIS_H = 20;
const WIDTH = 720;

export function EventTimeline({
  events,
  lanes,
  gaps,
  anchorTime,
  highlightedGuid,
  activeEventId,
  onHoverEvent,
  onClickEvent,
  onBrush,
}: TimelineProps) {
  const anchor = new Date(anchorTime).getTime();
  const [before, setBefore] = useState(30_000);
  const [after, setAfter] = useState(30_000);
  const [tip, setTip] = useState<{ x: number; y: number; ev: TimelineEvent } | null>(null);
  const [brush, setBrush] = useState<{ x0: number; x1: number } | null>(null);
  const dragging = useRef<number | null>(null);
  const svgRef = useRef<SVGSVGElement>(null);

  const t0 = anchor - before;
  const t1 = anchor + after;
  const plotW = WIDTH - LABEL_W - 8;
  const xOf = (t: number) => LABEL_W + ((t - t0) / (t1 - t0)) * plotW;
  const tOf = (x: number) => t0 + ((x - LABEL_W) / plotW) * (t1 - t0);
  const laneIdx = useMemo(() => new Map(lanes.map((l, i) => [l.guid, i])), [lanes]);
  const height = AXIS_H + lanes.length * LANE_H + 6;

  // 一般事件依像素聚合；關鍵事件獨立
  const { singles, density } = useMemo(() => {
    const singles: { ev: TimelineEvent; x: number; lane: number; kind: 'normal' | 'hit' | 'action' }[] = [];
    const buckets = new Map<string, { x: number; lane: number; evs: TimelineEvent[] }>();
    for (const ev of events) {
      const t = new Date(ev.time).getTime();
      if (t < t0 || t > t1) continue;
      const lane = laneIdx.get(ev.process_guid);
      if (lane === undefined) continue;
      const x = xOf(t);
      const kind = ev.action_taken ? 'action' : ev.rule_hits.length ? 'hit' : 'normal';
      if (kind !== 'normal') {
        singles.push({ ev, x, lane, kind });
        continue;
      }
      const key = `${lane}:${Math.round(x)}`;
      const b = buckets.get(key) ?? { x, lane, evs: [] };
      b.evs.push(ev);
      buckets.set(key, b);
    }
    const density: { x: number; lane: number; count: number }[] = [];
    for (const b of buckets.values()) {
      if (b.evs.length > 5) density.push({ x: b.x, lane: b.lane, count: b.evs.length });
      else for (const ev of b.evs) singles.push({ ev, x: b.x, lane: b.lane, kind: 'normal' });
    }
    return { singles, density };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [events, t0, t1, laneIdx]);

  const ticks = useMemo(() => {
    const span = t1 - t0;
    const step = span <= 30_000 ? 5_000 : span <= 90_000 ? 10_000 : span <= 200_000 ? 30_000 : 60_000;
    const out: number[] = [];
    for (let t = Math.ceil(t0 / step) * step; t <= t1; t += step) out.push(t);
    return out;
  }, [t0, t1]);

  const svgX = (e: MouseEvent) => {
    const r = svgRef.current!.getBoundingClientRect();
    return ((e.clientX - r.left) / r.width) * WIDTH;
  };

  const onDown = (e: MouseEvent) => {
    const x = svgX(e);
    if (x < LABEL_W) return;
    dragging.current = x;
    setBrush({ x0: x, x1: x });
  };
  const onMove = (e: MouseEvent) => {
    if (dragging.current === null) return;
    setBrush({ x0: dragging.current, x1: svgX(e) });
  };
  const onUp = () => {
    if (dragging.current === null || !brush) return;
    dragging.current = null;
    const a = Math.min(brush.x0, brush.x1);
    const b = Math.max(brush.x0, brush.x1);
    if (b - a < 4) {
      setBrush(null);
      onBrush?.(null);
    } else {
      onBrush?.([tOf(a), tOf(b)]);
    }
  };

  return (
    <div style={{ position: 'relative' }}>
      <div className="row" style={{ marginBottom: 6 }}>
        <span className="xs muted grow">
          視窗 {Math.round((before + after) / 1000)}s · 拖曳可選取區間
        </span>
        {brush && (
          <button
            className="btn sm ghost"
            onClick={() => {
              setBrush(null);
              onBrush?.(null);
            }}
          >
            清除選取
          </button>
        )}
      </div>
      <svg
        ref={svgRef}
        className="timeline-svg"
        viewBox={`0 0 ${WIDTH} ${height}`}
        role="img"
        aria-label="行為時間軸"
        onMouseDown={onDown}
        onMouseMove={onMove}
        onMouseUp={onUp}
        onMouseLeave={() => {
          if (dragging.current !== null) onUp();
          setTip(null);
        }}
      >
        <defs>
          <pattern id="gap-hatch" width="6" height="6" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
            <line x1="0" y1="0" x2="0" y2="6" stroke="var(--semantic-warning)" strokeWidth="2" opacity="0.6" />
          </pattern>
        </defs>
        {ticks.map((t) => (
          <g key={t}>
            <line x1={xOf(t)} x2={xOf(t)} y1={AXIS_H - 4} y2={height} stroke="var(--border-default)" />
            <text className="axis" x={xOf(t) + 2} y={12}>
              {fmtTime(new Date(t).toISOString()).slice(3)}
            </text>
          </g>
        ))}
        <line x1={xOf(anchor)} x2={xOf(anchor)} y1={AXIS_H - 4} y2={height} stroke="var(--sev-critical-fg)" strokeDasharray="3 3" />
        {gaps.map((g, i) => {
          const a = Math.max(t0, new Date(g.from).getTime());
          const b = Math.min(t1, new Date(g.to).getTime());
          if (b <= a) return null;
          return (
            <rect key={i} className="gap" x={xOf(a)} width={Math.max(2, xOf(b) - xOf(a))} y={AXIS_H} height={height - AXIS_H}>
              <title>此區間有 {g.dropped_count} 筆事件因緩衝滿而遺失</title>
            </rect>
          );
        })}
        {lanes.map((l, i) => {
          const y = AXIS_H + i * LANE_H + LANE_H / 2;
          const dim = highlightedGuid && highlightedGuid !== l.guid;
          return (
            <g key={l.guid} opacity={dim ? 0.3 : 1}>
              <text className="lane-label" x={4} y={y + 4}>
                {l.label.length > 12 ? `${l.label.slice(0, 11)}…` : l.label}
              </text>
              <line x1={LABEL_W} x2={WIDTH - 8} y1={y} y2={y} stroke={laneColor(l.guid)} strokeWidth={highlightedGuid === l.guid ? 3 : 1.5} opacity={0.5} />
            </g>
          );
        })}
        {density.map((d, i) => (
          <rect
            key={`d${i}`}
            x={d.x - 2}
            y={AXIS_H + d.lane * LANE_H + 5}
            width={4}
            height={LANE_H - 10}
            fill="var(--text-muted)"
          >
            <title>此處有 {d.count} 個事件</title>
          </rect>
        ))}
        {singles.map(({ ev, x, lane, kind }) => {
          const y = AXIS_H + lane * LANE_H + LANE_H / 2;
          const dim = highlightedGuid && highlightedGuid !== ev.process_guid;
          const delta = ev.rule_hits.reduce((s, h) => s + h.score_delta, 0);
          const r = kind === 'normal' ? 3.5 : Math.min(9, 5 + delta / 10);
          const active = activeEventId === ev.event_id;
          const color = kind === 'action' ? 'var(--semantic-blocked)' : kind === 'hit' ? 'var(--sev-high-fg)' : laneColor(ev.process_guid);
          return (
            <g
              key={ev.event_id}
              opacity={dim ? 0.3 : 1}
              style={{ cursor: 'pointer' }}
              onMouseDown={(e) => e.stopPropagation()}
              onMouseEnter={(e) => {
                const r2 = svgRef.current!.getBoundingClientRect();
                setTip({ x: e.clientX - r2.left, y: e.clientY - r2.top, ev });
                onHoverEvent?.(ev);
              }}
              onMouseLeave={() => {
                setTip(null);
                onHoverEvent?.(null);
              }}
              onClick={() => onClickEvent?.(ev)}
            >
              {kind === 'hit' ? (
                <polygon points={`${x},${y - r} ${x - r},${y + r * 0.8} ${x + r},${y + r * 0.8}`} fill={color} stroke={active ? 'var(--text-primary)' : 'none'} strokeWidth={2} />
              ) : kind === 'action' ? (
                <rect x={x - r} y={y - r} width={r * 2} height={r * 2} rx={2} fill={color} stroke={active ? 'var(--text-primary)' : 'none'} strokeWidth={2} />
              ) : (
                <circle cx={x} cy={y} r={active ? r + 2 : r} fill={color} />
              )}
            </g>
          );
        })}
        {brush && (
          <rect
            x={Math.min(brush.x0, brush.x1)}
            width={Math.abs(brush.x1 - brush.x0)}
            y={AXIS_H}
            height={height - AXIS_H}
            fill="var(--semantic-info)"
            opacity={0.15}
          />
        )}
      </svg>
      {tip && (
        <div className="popover" style={{ left: Math.min(tip.x + 8, 420), top: tip.y + 12, pointerEvents: 'none' }}>
          <div className="mono xs" title={timeTitle(tip.ev.time)}>
            {fmtTime(tip.ev.time, true)} · {tip.ev.event_type}
          </div>
          <div>{tip.ev.summary}</div>
          {tip.ev.target && <div className="mono xs muted">{tip.ev.target}</div>}
          {tip.ev.rule_hits.map((h) => (
            <div key={h.rule_id + (h.step ?? '')} className="xs fg-high">
              🎯 {h.rule_id}
              {h.step ? ` 步驟 ${h.step}` : ''} +{h.score_delta}
            </div>
          ))}
          {tip.ev.action_taken && <div className="xs fg-blocked">⛔ {actionLabel(tip.ev.action_taken)}</div>}
        </div>
      )}
      <div className="row" style={{ justifyContent: 'center', marginTop: 6 }}>
        <button className="btn sm" onClick={() => setBefore((b) => b + 60_000)}>
          載入前 60 秒
        </button>
        <button className="btn sm" onClick={() => setAfter((a) => a + 60_000)}>
          載入後 60 秒
        </button>
      </div>
    </div>
  );
}

const CIRCLED = '①②③④⑤⑥⑦⑧⑨⑩⑪⑫⑬⑭⑮⑯⑰⑱⑲⑳';

export function EventList({
  events,
  expandedIds,
  onToggle,
  filterRange,
  activeEventId,
  onHoverEvent,
  gaps,
}: {
  events: TimelineEvent[];
  expandedIds: Set<number>;
  onToggle: (id: number) => void;
  filterRange?: [number, number] | null;
  activeEventId?: number | null;
  onHoverEvent?: (ev: TimelineEvent | null) => void;
  gaps: TelemetryGap[];
}) {
  const list = filterRange
    ? events.filter((e) => {
        const t = new Date(e.time).getTime();
        return t >= filterRange[0] && t <= filterRange[1];
      })
    : events;
  return (
    <div className="evlist">
      {gaps.length > 0 && (
        <div className="banner warning" style={{ borderRadius: 6 }}>
          ⚠ 此告警期間有 {gaps.reduce((s, g) => s + g.dropped_count, 0)} 筆事件因緩衝滿而遺失，時間軸以斜線標示缺口。
        </div>
      )}
      {list.map((ev, i) => {
        const open = expandedIds.has(ev.event_id);
        return (
          <div
            key={ev.event_id}
            id={`ev-${ev.event_id}`}
            className={`ev${activeEventId === ev.event_id ? ' active' : ''}`}
            onClick={() => onToggle(ev.event_id)}
            onMouseEnter={() => onHoverEvent?.(ev)}
            onMouseLeave={() => onHoverEvent?.(null)}
          >
            <div className="row">
              <span className="mono" style={{ color: laneColor(ev.process_guid) }}>
                {CIRCLED[i] ?? `#${i + 1}`}
              </span>
              <span className="mono xs" title={timeTitle(ev.time)}>
                {fmtTime(ev.time, true)}
              </span>
              <span className="mono xs" style={{ fontWeight: 600 }}>
                {ev.event_type}
              </span>
              {ev.action_taken && <span className="xs fg-blocked">⛔ {actionLabel(ev.action_taken)}</span>}
            </div>
            <div className="sm" style={{ paddingLeft: 22 }}>
              {ev.summary}
            </div>
            {ev.rule_hits.map((h) => (
              <div key={h.rule_id + (h.step ?? '')} className="xs fg-high" style={{ paddingLeft: 22 }}>
                🎯 規則 {h.rule_id}
                {h.step ? ` 步驟 ${h.step}` : ''} 命中 +{h.score_delta}
                {ev.score_after !== undefined && ` → ${ev.score_after}`}
              </div>
            ))}
            {open && (
              <div className="detail mono" style={{ marginLeft: 22 }}>
                {JSON.stringify(
                  {
                    event_id: ev.event_id,
                    source: ev.source,
                    process_guid: ev.process_guid,
                    target: ev.target,
                    remote: ev.remote_addr ? `${ev.remote_addr}:${ev.remote_port ?? ''}` : undefined,
                    ...ev.details,
                  },
                  null,
                  2,
                )}
              </div>
            )}
          </div>
        );
      })}
      {list.length === 0 && <div className="sm muted" style={{ padding: 8 }}>選取區間內沒有事件。</div>}
    </div>
  );
}
