// ProcessTree（元件 #4）+ ProcessNode（#5）：縮排樹（非節點圖），part3 §3.4。
// 預設可見集合 =「攻擊路徑 + 一層脈絡」（§3.4.2）：
//   1. 根 → 焦點程序的祖先鏈必定展開
//   2. 焦點程序風險 > 0 或有規則命中的後代必定展開
//   3. 焦點程序的直接子程序展開一層
//   4. 其餘同層節點合併為「⋯ 另有 N 個低風險子程序 [展開]」
//   5. 預設渲染上限 200 節點
// ⚠ M0 偏差：未引入 @tanstack/react-virtual（依賴精簡），「顯示全部」為直接渲染。
import { useMemo, useRef, useState, type KeyboardEvent } from 'react';
import {
  basename,
  copyText,
  fmtDuration,
  fmtTime,
  laneColor,
  looksEncoded,
  middleEllipsis,
  severityOfScore,
  timeTitle,
  truncate,
} from '../lib/format';
import type { InjectionEdge, ProcessNodeDto } from '../lib/types';
import { RiskScore, SignatureStatus } from './ScoreBadge';

const NOISE = new Set(['svchost.exe', 'conhost.exe', 'runtimebroker.exe', 'backgroundtaskhost.exe', 'dllhost.exe']);
const RENDER_CAP = 200;

interface Props {
  nodes: ProcessNodeDto[];
  edges: InjectionEdge[];
  focusGuid: string;
  highlightedGuids?: Set<string>;
  dimmedGuids?: Set<string> | null;
  onHoverNode?: (guid: string | null) => void;
  onSelectNode?: (guid: string) => void;
  onRuleClick?: (ruleId: string) => void;
  onEdgeClick?: (edge: InjectionEdge) => void;
  collapseMode?: 'default' | 'attack_path' | 'all';
}

function riskIcon(n: ProcessNodeDto): { icon: string; cls: string; label: string } {
  if (n.excluded) return { icon: '⊘', cls: 'fg-dryrun', label: '已排除' };
  if (n.risk_score >= 80) return { icon: '▲', cls: `fg-${severityOfScore(n.risk_score)}`, label: '高風險' };
  if (n.risk_score >= 40) return { icon: '●', cls: 'fg-medium', label: '可疑' };
  return { icon: '○', cls: 'muted', label: '正常' };
}

function stateBadge(n: ProcessNodeDto) {
  switch (n.state) {
    case 'terminated_by_cairn':
      return <span className="xs fg-blocked">⛔ 已終止</span>;
    case 'suspended':
      return <span className="xs fg-warning">⏸ 已暫停</span>;
    case 'blocked':
      return <span className="xs fg-blocked">⛔ 已阻擋</span>;
    case 'running':
      return <span className="xs fg-success">● 執行中</span>;
    default:
      return <span className="xs muted">✓ 已結束</span>;
  }
}

export function ProcessTreeView({
  nodes,
  edges,
  focusGuid,
  highlightedGuids,
  dimmedGuids,
  onHoverNode,
  onSelectNode,
  onRuleClick,
  onEdgeClick,
  collapseMode = 'default',
}: Props) {
  const [expanded, setExpanded] = useState<Set<string>>(new Set()); // 使用者手動展開摘要列的父節點
  const [details, setDetails] = useState<Set<string>>(new Set()); // 已展開詳情（完整命令列 / 解碼）
  const [showAll, setShowAll] = useState(false);
  const [cursor, setCursor] = useState<string>(focusGuid);
  const containerRef = useRef<HTMLDivElement>(null);

  const { byGuid, children, roots } = useMemo(() => {
    const byGuid = new Map(nodes.map((n) => [n.process_guid, n]));
    const children = new Map<string, ProcessNodeDto[]>();
    const roots: ProcessNodeDto[] = [];
    for (const n of nodes) {
      if (n.parent_guid && byGuid.has(n.parent_guid)) {
        const arr = children.get(n.parent_guid) ?? [];
        arr.push(n);
        children.set(n.parent_guid, arr);
      } else {
        roots.push(n);
      }
    }
    for (const arr of children.values()) arr.sort((a, b) => a.created_at.localeCompare(b.created_at));
    return { byGuid, children, roots };
  }, [nodes]);

  // 祖先鏈（含焦點）
  const pathSet = useMemo(() => {
    const s = new Set<string>();
    let g: string | null | undefined = focusGuid;
    while (g && byGuid.has(g) && !s.has(g)) {
      s.add(g);
      g = byGuid.get(g)?.parent_guid;
    }
    return s;
  }, [focusGuid, byGuid]);

  // 焦點的後代中「重要」者（風險 > 0 或命中規則）及其祖先
  const importantSet = useMemo(() => {
    const s = new Set<string>(pathSet);
    const visit = (g: string, underFocus: boolean): boolean => {
      const n = byGuid.get(g);
      if (!n) return false;
      let keep = underFocus && (n.risk_score > 0 || n.rule_hits.length > 0);
      for (const c of children.get(g) ?? []) {
        if (visit(c.process_guid, underFocus || g === focusGuid)) keep = true;
      }
      if (keep) s.add(g);
      return keep;
    };
    for (const r of roots) visit(r.process_guid, r.process_guid === focusGuid);
    for (const e of edges) {
      s.add(e.source_guid);
      s.add(e.target_guid);
    }
    return s;
  }, [pathSet, byGuid, children, roots, focusGuid, edges]);

  type Row =
    | { kind: 'node'; node: ProcessNodeDto; level: number }
    | { kind: 'summary'; parent: string; count: number; level: number }
    | { kind: 'edge'; edge: InjectionEdge; level: number };

  const { rows, total, truncated } = useMemo(() => {
    const out: Row[] = [];
    let count = 0;
    let truncated = false;
    const isVisibleChild = (parent: ProcessNodeDto, c: ProcessNodeDto): boolean => {
      if (collapseMode === 'all' || expanded.has(parent.process_guid)) return true;
      if (importantSet.has(c.process_guid)) return true;
      if (collapseMode === 'attack_path') return false;
      // 焦點的直接子程序展開一層（噪音程序除外）
      if (parent.process_guid === focusGuid) {
        return !(NOISE.has(c.name.toLowerCase()) && c.risk_score === 0 && c.rule_hits.length === 0);
      }
      return false;
    };
    const walk = (n: ProcessNodeDto, level: number, seen: Set<string>) => {
      if (seen.has(n.process_guid)) return;
      seen.add(n.process_guid);
      if (!showAll && count >= RENDER_CAP) {
        truncated = true;
        return;
      }
      out.push({ kind: 'node', node: n, level });
      count++;
      for (const e of edges.filter((e) => e.source_guid === n.process_guid)) {
        out.push({ kind: 'edge', edge: e, level: level + 1 });
      }
      const kids = children.get(n.process_guid) ?? [];
      let hidden = 0;
      for (const c of kids) {
        if (isVisibleChild(n, c)) walk(c, level + 1, seen);
        else hidden++;
      }
      hidden += n.hidden_low_risk_children ?? 0;
      if (hidden > 0 && !expanded.has(n.process_guid) && collapseMode !== 'all') {
        out.push({ kind: 'summary', parent: n.process_guid, count: hidden, level: level + 1 });
      }
    };
    const seen = new Set<string>();
    for (const r of roots) walk(r, 0, seen);
    return { rows: out, total: nodes.length, truncated };
  }, [roots, children, edges, expanded, importantSet, collapseMode, focusGuid, showAll, nodes.length]);

  const visibleGuids = rows.filter((r) => r.kind === 'node').map((r) => (r as { node: ProcessNodeDto }).node.process_guid);

  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    const i = visibleGuids.indexOf(cursor);
    let next: string | undefined;
    switch (e.key) {
      case 'ArrowDown':
        next = visibleGuids[Math.min(visibleGuids.length - 1, i + 1)];
        break;
      case 'ArrowUp':
        next = visibleGuids[Math.max(0, i - 1)];
        break;
      case 'Home':
        next = visibleGuids[0];
        break;
      case 'End':
        next = visibleGuids[visibleGuids.length - 1];
        break;
      case 'ArrowLeft': {
        const n = byGuid.get(cursor);
        if (n && expanded.has(cursor)) {
          setExpanded((s) => {
            const t = new Set(s);
            t.delete(cursor);
            return t;
          });
        } else if (n?.parent_guid && byGuid.has(n.parent_guid)) next = n.parent_guid;
        break;
      }
      case 'ArrowRight': {
        const kids = children.get(cursor) ?? [];
        if (!expanded.has(cursor) && kids.length > 0) {
          setExpanded((s) => new Set(s).add(cursor));
        } else if (kids[0]) next = kids[0].process_guid;
        break;
      }
      case 'Enter':
        toggleDetails(cursor);
        onSelectNode?.(cursor);
        break;
      default:
        return;
    }
    e.preventDefault();
    if (next) {
      setCursor(next);
      onHoverNode?.(next);
      containerRef.current?.querySelector<HTMLElement>(`[data-guid="${next}"]`)?.focus();
    }
  };

  const toggleDetails = (g: string) =>
    setDetails((s) => {
      const t = new Set(s);
      if (t.has(g)) t.delete(g);
      else t.add(g);
      return t;
    });

  return (
    <div>
      {truncated && (
        <div className="banner info" style={{ borderRadius: 6, marginBottom: 8 }}>
          此程序樹共 {total.toLocaleString()} 個節點，已依風險摺疊顯示 {RENDER_CAP} 個{' '}
          <button className="btn sm" onClick={() => setShowAll(true)}>
            顯示全部（可能較慢）
          </button>
        </div>
      )}
      <div className="ptree" role="tree" aria-label="程序樹" ref={containerRef} onKeyDown={onKeyDown}>
        {rows.map((r) => {
          if (r.kind === 'summary') {
            return (
              <div key={`s-${r.parent}`} className="collapsed-row muted" style={{ paddingLeft: r.level * 20 + 22 }}>
                ⋯ 另有 {r.count} 個低風險子程序{' '}
                <button className="btn sm ghost" onClick={() => setExpanded((s) => new Set(s).add(r.parent))}>
                  展開
                </button>
              </div>
            );
          }
          if (r.kind === 'edge') {
            const tgt = byGuid.get(r.edge.target_guid);
            return (
              <div
                key={`e-${r.edge.edge_id}`}
                className="inj-edge"
                style={{ paddingLeft: r.level * 20 + 22 }}
                onClick={() => onEdgeClick?.(r.edge)}
                onMouseEnter={() => onHoverNode?.(r.edge.target_guid)}
                onMouseLeave={() => onHoverNode?.(null)}
                title={`${r.edge.evidence_source} · ${r.edge.outcome}`}
              >
                ├ ╌╌▶ [遠端執行緒注入] → {tgt ? `${tgt.name} (${tgt.pid})` : r.edge.target_guid}{' '}
                <span className="muted mono">{fmtTime(r.edge.occurred_at, true)}</span>
                {r.edge.outcome === 'detected_post_hoc' && <span className="xs muted"> · 事後偵測</span>}
              </div>
            );
          }
          const n = r.node;
          const ri = riskIcon(n);
          const isFocus = n.process_guid === focusGuid;
          const hl = highlightedGuids?.has(n.process_guid);
          const dim = dimmedGuids ? !dimmedGuids.has(n.process_guid) : false;
          const lifetime =
            n.terminated_at && n.created_at
              ? fmtDuration(new Date(n.terminated_at).getTime() - new Date(n.created_at).getTime())
              : null;
          const showDetails = details.has(n.process_guid);
          return (
            <div
              key={n.process_guid}
              data-guid={n.process_guid}
              role="treeitem"
              aria-level={r.level + 1}
              aria-expanded={(children.get(n.process_guid)?.length ?? 0) > 0 ? true : undefined}
              aria-selected={cursor === n.process_guid}
              aria-label={`${n.name}，${ri.label}，分數 ${n.risk_score}`}
              tabIndex={cursor === n.process_guid ? 0 : -1}
              className={`pnode${isFocus ? ' focus' : ''}${hl ? ' hl' : ''}${dim ? ' dim' : ''}`}
              style={{ marginLeft: r.level * 20 }}
              onMouseEnter={() => onHoverNode?.(n.process_guid)}
              onMouseLeave={() => onHoverNode?.(null)}
              onClick={() => {
                setCursor(n.process_guid);
                onSelectNode?.(n.process_guid);
              }}
            >
              <div className="l1">
                <span className="lane-swatch" style={{ background: laneColor(n.process_guid) }} aria-hidden />
                <span className={ri.cls} aria-hidden>
                  {ri.icon}
                </span>
                <span className={`name grow ellipsis${n.rule_hits.length ? ' hit' : ''}`}>{n.name}</span>
                <span className="mono muted" title={n.process_guid}>
                  {n.pid}
                </span>
                <RiskScore score={n.risk_score} />
                {stateBadge(n)}
              </div>
              {n.preexisting && (
                <div className="sub xs muted">⊙ agent 啟動前既有程序（無建立事件）</div>
              )}
              {n.command_line && (
                <div className="sub">
                  <span className="mono secondary grow ellipsis" title={n.command_line}>
                    {truncate(n.command_line, 120)}
                  </span>
                  <button
                    className="btn sm ghost"
                    title="複製完整命令列"
                    onClick={(e) => {
                      e.stopPropagation();
                      void copyText(n.command_line);
                    }}
                  >
                    ⧉
                  </button>
                  {(n.command_line_decoded || looksEncoded(n.command_line)) && (
                    <button
                      className="btn sm"
                      onClick={(e) => {
                        e.stopPropagation();
                        toggleDetails(n.process_guid);
                      }}
                    >
                      🔓 解碼
                    </button>
                  )}
                  <button
                    className="btn sm ghost"
                    onClick={(e) => {
                      e.stopPropagation();
                      toggleDetails(n.process_guid);
                    }}
                    aria-label="展開詳情"
                  >
                    {showDetails ? '▾' : '▸'}
                  </button>
                </div>
              )}
              <div className="sub">
                {n.rule_hits.map((id) => (
                  <button
                    key={id}
                    className="pill"
                    onClick={(e) => {
                      e.stopPropagation();
                      onRuleClick?.(id);
                    }}
                  >
                    🎯 {id}
                  </button>
                ))}
                <span className="grow" />
                <span className="mono muted" title={n.image_path}>
                  {middleEllipsis(n.image_path || basename(n.name))}
                </span>
              </div>
              <div className="sub">
                <SignatureStatus signer={n.signer} status={n.signature_status} />
                <span className="grow" />
                <span className="mono muted xs" title={timeTitle(n.created_at)}>
                  {fmtTime(n.created_at, true)}
                  {lifetime && ` 存活 ${lifetime}`}
                </span>
              </div>
              {showDetails && (
                <div className="sub" style={{ display: 'block' }}>
                  <div className="card" style={{ padding: 8, marginTop: 4 }}>
                    <div className="xs muted">完整命令列</div>
                    <div className="mono" style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                      {n.command_line}
                    </div>
                    {n.command_line_decoded ? (
                      <>
                        <div className="xs muted" style={{ marginTop: 6 }}>
                          解碼結果（來源：{n.decode_source === 'powershell_4104' ? 'PowerShell 4104 ScriptBlock' : n.decode_source ?? '—'}）
                        </div>
                        <div className="mono" style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                          {n.command_line_decoded}
                        </div>
                      </>
                    ) : (
                      looksEncoded(n.command_line) && (
                        <div className="xs muted" style={{ marginTop: 6 }}>
                          無 PowerShell 4104 解混淆原文（ScriptBlockLogging 未啟用或事件尚未到達）。
                        </div>
                      )
                    )}
                    <div className="kv" style={{ marginTop: 6 }}>
                      <span className="muted">process_guid</span>
                      <span className="mono">{n.process_guid}</span>
                      <span className="muted">SHA256</span>
                      <span className="mono" title={n.image_sha256 ? undefined : '需安裝 Sysmon 才能取得'}>
                        {n.image_sha256 ?? '—'}
                      </span>
                    </div>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
