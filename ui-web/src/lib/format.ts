import type { ActionName, Severity } from './types';

const pad = (n: number, w = 2) => String(n).padStart(w, '0');

// 所有時間顯示為本地時區（part3 §3.7.2 全域規範），hover 顯示 UTC 與相對時間。
export function fmtTime(iso: string | null | undefined, withMs = false): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const base = `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  return withMs ? `${base}.${pad(d.getMilliseconds(), 3)}` : base;
}

export function fmtDateTime(iso: string | null | undefined, withMs = false): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${fmtTime(iso, withMs)}`;
}

export function fmtShortDateTime(iso: string | null | undefined): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return `${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${fmtTime(iso)}`;
}

export function relativeTime(iso: string | number | null | undefined): string {
  if (iso === null || iso === undefined) return '—';
  const t = typeof iso === 'number' ? iso : new Date(iso).getTime();
  const s = Math.round((Date.now() - t) / 1000);
  if (s < 5) return '剛剛';
  if (s < 60) return `${s} 秒前`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m} 分鐘前`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h} 小時前`;
  return `${Math.round(h / 24)} 天前`;
}

export function timeTitle(iso: string | null | undefined): string {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return `UTC ${d.toISOString()} · ${relativeTime(iso)}`;
}

export function fmtDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(s < 10 ? 2 : 1)}s`;
  const m = Math.floor(s / 60);
  const rs = Math.round(s % 60);
  if (m < 60) return `${m} 分 ${rs} 秒`;
  return `${Math.floor(m / 60)} 小時 ${m % 60} 分`;
}

export function fmtUptime(sec: number): string {
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  return d > 0 ? `${d}d ${pad(h)}h` : `${h}h ${pad(m)}m`;
}

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: '嚴重',
  high: '高',
  medium: '中',
  low: '低',
};

// 分數 → 顯示用 severity（part3 §3.6.1 的分數區間）
export function severityOfScore(score: number): Severity | null {
  if (score >= 95) return 'critical';
  if (score >= 80) return 'high';
  if (score >= 40) return 'medium';
  if (score >= 1) return 'low';
  return null;
}

export const ACTION_LABEL: Record<ActionName, string> = {
  suspend_process: '暫停程序',
  terminate_process_tree: '終止程序樹',
  quarantine_file: '隔離檔案',
  firewall_block: '封鎖網路連線',
};

export const ACTION_ICON: Record<ActionName, string> = {
  suspend_process: '⏸',
  terminate_process_tree: '⛔',
  quarantine_file: '📦',
  firewall_block: '🚫',
};

export function actionLabel(a: string): string {
  return (ACTION_LABEL as Record<string, string>)[a] ?? a;
}

export const STATUS_LABEL: Record<string, { icon: string; label: string }> = {
  pending: { icon: '○', label: '待處理' },
  observing: { icon: '◔', label: '觀察中' },
  auto_blocked: { icon: '●', label: '已阻擋' },
  blocked: { icon: '●', label: '已阻擋' },
  resolved: { icon: '✓', label: '已處理' },
  false_positive: { icon: '⊘', label: '已標記誤報' },
};

export function statusLabel(s: string): { icon: string; label: string } {
  return STATUS_LABEL[s] ?? { icon: '·', label: s };
}

export function initiatorLabel(i: string): string {
  if (i === 'system_auto' || i === 'rule_engine' || i === 'system') return '系統(自動)';
  if (i.startsWith('user:')) return `使用者 ${i.slice(5)}`;
  if (i === 'analyst' || i === 'user') return '使用者';
  return i;
}

export function basename(p: string | null | undefined): string {
  if (!p) return '';
  const i = Math.max(p.lastIndexOf('\\'), p.lastIndexOf('/'));
  return i >= 0 ? p.slice(i + 1) : p;
}

// 中段省略：C:\Windows\…\powershell.exe
export function middleEllipsis(p: string, max = 48): string {
  if (p.length <= max) return p;
  const name = basename(p);
  const head = p.slice(0, Math.max(3, max - name.length - 2));
  return `${head}…\\${name}`;
}

export function truncate(s: string, n: number): string {
  return s.length > n ? `${s.slice(0, n)}…` : s;
}

// process_guid 雜湊 → lane 色（同一程序在樹與時間軸永遠同色，part3 §3.4.4）
const LANE_HUES = [210, 280, 30, 160, 330, 100, 190, 250, 0, 60];
export function laneColor(guid: string): string {
  let h = 2166136261;
  for (let i = 0; i < guid.length; i++) {
    h ^= guid.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  const hue = LANE_HUES[Math.abs(h) % LANE_HUES.length];
  return `hsl(${hue} 70% 62%)`;
}

export function looksEncoded(cmd: string): boolean {
  return /\s-(e|en|enc|enco|encod|encode|encodedcommand)\s/i.test(` ${cmd} `) || /[A-Za-z0-9+/]{60,}={0,2}/.test(cmd);
}

export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand('copy');
    ta.remove();
    return ok;
  }
}
