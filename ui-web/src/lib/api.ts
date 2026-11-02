// 單一 apiClient 模組（part3 附註 3：所有 API 呼叫收斂於此，R1.0 改 HTTP+mTLS 時為單檔改動）。
// 前端只認 fetch('/api/v1/...')，完全不知道背後是 WebView2 攔截 → Named Pipe JSON-RPC。
import type {
  AlertDetail,
  AlertListQuery,
  AlertListResponse,
  ApiErrorBody,
  AuditEntry,
  ExecuteRequest,
  ExecuteResponse,
  Exclusion,
  ExclusionKind,
  ExclusionPreview,
  ExclusionSuggestion,
  Health,
  NarrativeResponse,
  PrepareRequest,
  PrepareResponse,
  QuarantineItem,
  RevertResponse,
  RuleInfo,
  RuleStatus,
  VerdictRequest,
  VerdictResponse,
} from './types';

const BASE = '/api/v1';

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly details?: Record<string, unknown>;
  constructor(status: number, code: string, message: string, details?: Record<string, unknown>) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

// ---------------------------------------------------------------------------
// 服務連線狀態（part3 §3.10.4）：任一 API 連續 3 次 503 → 全頁「防護狀態未知」攔截。
// ---------------------------------------------------------------------------
export type LinkState = 'ok' | 'gone';
type LinkListener = (s: LinkSnapshot) => void;
export interface LinkSnapshot {
  state: LinkState;
  lastOkAt: number | null; // 最後一次成功取數的時間（毫秒），用於「資料截止於 HH:MM:SS」
  goneSince: number | null;
}

let consecutive503 = 0;
let link: LinkSnapshot = { state: 'ok', lastOkAt: null, goneSince: null };
const listeners = new Set<LinkListener>();

function setLink(next: LinkSnapshot) {
  link = next;
  listeners.forEach((l) => l(link));
}

function noteSuccess() {
  consecutive503 = 0;
  if (link.state !== 'ok') {
    setLink({ state: 'ok', lastOkAt: Date.now(), goneSince: null });
  } else {
    link = { ...link, lastOkAt: Date.now() };
  }
}

function note503() {
  consecutive503 += 1;
  if (consecutive503 >= 3 && link.state !== 'gone') {
    setLink({ state: 'gone', lastOkAt: link.lastOkAt, goneSince: Date.now() });
  }
}

export function subscribeLink(l: LinkListener): () => void {
  listeners.add(l);
  return () => listeners.delete(l);
}
export function getLink(): LinkSnapshot {
  return link;
}

// 非冪等方法（SDD-03 §9.3.4）：遇 503 一律不自動重試，提示使用者查閱稽核頁。
export function isNonIdempotentError(e: unknown): boolean {
  return e instanceof ApiError && e.status === 503;
}

// ---------------------------------------------------------------------------
// 底層請求
// ---------------------------------------------------------------------------
type Query = Record<string, string | number | boolean | string[] | null | undefined>;

function buildQuery(q?: Query): string {
  if (!q) return '';
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(q)) {
    if (v === undefined || v === null || v === '') continue;
    if (Array.isArray(v)) {
      for (const item of v) p.append(`${k}[]`, item);
    } else {
      p.append(k, String(v));
    }
  }
  const s = p.toString();
  return s ? `?${s}` : '';
}

export interface ApiResult<T> {
  status: number;
  data: T;
}

async function request<T>(
  method: 'GET' | 'POST' | 'PATCH' | 'DELETE',
  path: string,
  opts: { query?: Query; body?: unknown; signal?: AbortSignal } = {},
): Promise<ApiResult<T>> {
  let res: Response;
  try {
    res = await fetch(`${BASE}${path}${buildQuery(opts.query)}`, {
      method,
      headers: opts.body !== undefined ? { 'Content-Type': 'application/json; charset=utf-8' } : undefined,
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
      signal: opts.signal,
    });
  } catch (e) {
    if ((e as Error).name === 'AbortError') throw e;
    // 攔截層本身失敗（極少見）：視同服務不可用
    note503();
    throw new ApiError(503, 'SERVICE_UNAVAILABLE', '無法連線至 Cairn 服務');
  }

  const text = await res.text();
  let json: unknown = null;
  if (text) {
    try {
      json = JSON.parse(text);
    } catch {
      json = null;
    }
  }

  if (res.status === 503) {
    note503();
  } else {
    noteSuccess();
  }

  if (res.status >= 200 && res.status < 300) {
    return { status: res.status, data: json as T };
  }
  const err = (json as ApiErrorBody | null)?.error;
  throw new ApiError(
    res.status,
    err?.code ?? `HTTP_${res.status}`,
    err?.message ?? `請求失敗（HTTP ${res.status}）`,
    err?.details,
  );
}

const enc = encodeURIComponent;

// ---------------------------------------------------------------------------
// 端點（part3 §3.8.1 / SDD-03 §9.3.2）
// ---------------------------------------------------------------------------
export const api = {
  // 1
  health: (signal?: AbortSignal) => request<Health>('GET', '/health', { signal }).then((r) => r.data),

  // 2
  listAlerts: (q: AlertListQuery, signal?: AbortSignal) =>
    request<AlertListResponse>('GET', '/alerts', {
      signal,
      query: {
        severity: q.severity,
        status: q.status,
        since: q.since,
        until: q.until,
        q: q.q,
        has_narrative: q.has_narrative || undefined,
        blocked_only: q.blocked_only || undefined,
        sort: q.sort,
        limit: q.limit,
        cursor: q.cursor ?? undefined,
      },
    }).then((r) => r.data),

  // 3
  getAlert: (id: string, signal?: AbortSignal) =>
    request<AlertDetail>('GET', `/alerts/${enc(id)}`, { signal }).then((r) => r.data),

  // 4
  getNarrative: (id: string, signal?: AbortSignal) =>
    request<NarrativeResponse>('GET', `/alerts/${enc(id)}/narrative`, { signal }).then((r) => r.data),

  // 5
  regenerateNarrative: (id: string, mode: 'same' | 'reduced_context', eventCount?: number) =>
    request<{ state: string }>('POST', `/alerts/${enc(id)}/narrative/regenerate`, {
      body: { mode, event_count: eventCount },
    }).then((r) => r.data),

  // 23
  narrativeFeedback: (id: string, helpful: boolean, reason?: string) =>
    request<{ ok: boolean }>('POST', `/alerts/${enc(id)}/narrative/feedback`, {
      body: { helpful, reason },
    }).then((r) => r.data),

  // 6
  setVerdict: (id: string, body: VerdictRequest) =>
    request<VerdictResponse>('POST', `/alerts/${enc(id)}/verdict`, { body }).then((r) => r.data),

  // 7
  prepareAction: (id: string, body: PrepareRequest) =>
    request<PrepareResponse>('POST', `/alerts/${enc(id)}/actions/prepare`, { body }).then((r) => r.data),

  // 8（回傳 status 以區分 200 / 207 部分成功）
  executeAction: (id: string, body: ExecuteRequest) =>
    request<ExecuteResponse>('POST', `/alerts/${enc(id)}/actions`, { body }),

  // 8b
  revertAction: (
    id: string,
    auditId: string | number,
    body: { confirmation_token?: string | null; typed_confirmation?: string; reason?: string },
  ) =>
    request<RevertResponse>('POST', `/alerts/${enc(id)}/actions/${enc(String(auditId))}/revert`, { body }).then(
      (r) => r.data,
    ),

  // 11a/b/c
  listExclusions: () => request<{ items: Exclusion[] }>('GET', '/exclusions').then((r) => r.data),
  addExclusion: (body: {
    type: ExclusionKind;
    value: string;
    scope: string;
    source_alert_id?: string;
    reason?: string;
  }) => request<{ exclusion_id: number | string; undo_token?: string }>('POST', '/exclusions', { body }).then((r) => r.data),
  removeExclusion: (id: number | string) =>
    request<{ ok: boolean }>('DELETE', `/exclusions/${enc(String(id))}`).then((r) => r.data),

  // 12
  previewExclusion: (type: ExclusionKind, value: string, scope: string) =>
    request<ExclusionPreview>('GET', '/exclusions/preview', { query: { type, value, scope } }).then((r) => r.data),

  // 13 / 22
  listSuggestions: () =>
    request<{ items: ExclusionSuggestion[]; learning_mode: { day: number; total_days: number } }>(
      'GET',
      '/exclusions/suggestions',
    ).then((r) => r.data),
  dismissSuggestion: (id: string | number, all = false) =>
    request<{ ok: boolean }>('DELETE', `/exclusions/suggestions/${enc(String(id))}`, {
      query: { all: all || undefined },
    }).then((r) => r.data),

  // 14 / 18
  listRules: () =>
    request<{ items: RuleInfo[]; pack_version: string; pack_signature_valid: boolean }>('GET', '/rules').then(
      (r) => r.data,
    ),
  setRuleStatus: (id: string, status: RuleStatus) =>
    request<{ ok: boolean; rule_id: string; status: RuleStatus }>('PATCH', `/rules/${enc(id)}`, {
      body: { status },
    }).then((r) => r.data),

  // 15
  listAudit: (q: { from?: string; to?: string; action?: string[]; initiator?: string; q?: string }) =>
    request<{ items: AuditEntry[]; chain_valid: boolean }>('GET', '/audit', { query: q }).then((r) => r.data),

  // 16
  listQuarantine: () => request<{ items: QuarantineItem[] }>('GET', '/quarantine').then((r) => r.data),

  // 17
  undo: (token: string) => request<{ ok: boolean }>('POST', `/undo/${enc(token)}`).then((r) => r.data),

  // 19 / 20 / 21（pause 需 confirmation_token：先不帶 token 呼叫取得 403 + details.confirmation_token）
  pauseProtection: (duration: '15m' | '1h' | 'until_reboot', reason: string, token?: string | null) =>
    request<{ ok: boolean; paused_until: string | null; confirmation_token?: string }>('POST', '/protection/pause', {
      body: { duration, reason, confirmation_token: token ?? undefined },
    }).then((r) => r.data),
  resumeProtection: () => request<{ ok: boolean }>('POST', '/protection/resume').then((r) => r.data),
  finishLearning: () => request<{ ok: boolean }>('POST', '/learning-mode/finish').then((r) => r.data),
};

export function errorMessage(e: unknown): string {
  if (e instanceof ApiError) return `${e.message}（${e.code}）`;
  if (e instanceof Error) return e.message;
  return String(e);
}
