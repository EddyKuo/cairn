// API 契約型別（docs/part3_uiux.md §3.8）。
// 分數一律為 0–100 的顯示分（整數），由 CairnAgent 自 milli-point 換算；前端不做分數運算。
// 時間一律為 RFC3339 UTC 毫秒精度字串。

export type Severity = 'low' | 'medium' | 'high' | 'critical';
export type RuleStatus = 'enabled' | 'dryrun' | 'disabled';
export type Verdict = 'true_positive' | 'false_positive' | 'benign';
export type WorkflowStatus = 'pending' | 'resolved';
export type ActionName = 'suspend_process' | 'terminate_process_tree' | 'quarantine_file' | 'firewall_block';
export type RiskLevel = 'L1' | 'L2' | 'L3';
export type NarrativeState = 'ready' | 'pending' | 'failed' | 'timeout' | 'unavailable' | 'skipped';
export type AlertStatus =
  | 'pending'
  | 'observing'
  | 'auto_blocked'
  | 'resolved'
  | 'false_positive'
  | string; // 後端可擴充，未知值以原字串顯示
export type ExclusionKind = 'path' | 'path_glob' | 'sha256' | 'signer' | 'rule_id' | 'cmdline_glob';

// ---- 1. GET /health ----
export interface Health {
  service: string;
  hostname?: string;
  uptime_s: number;
  protection_state: 'protecting' | 'learning' | 'paused' | string;
  paused_until?: string | null;
  learning_mode: { active: boolean; day: number; total_days: number };
  providers: { name: string; state: string }[];
  sysmon: { installed: boolean; version?: string | null; state?: string };
  llm: { state: string; device?: string; model_id?: string | null };
  resources: {
    cpu_p95: number;
    ram_mb: number;
    disk_mb: number;
    events_per_sec: number;
    drop_rate: number;
  };
  anomalies_24h: { time: string; message: string }[];
  self_protection: { level: string; disclosure: string; unexpected_terminations_30d: number };
  alerts_today?: number;
  unread_high?: number;
}

// ---- 2. GET /alerts ----
export interface AlertSummary {
  alert_id: string;
  severity: Severity;
  risk_score: number;
  title: string;
  time: string;
  process_name: string;
  parent_name: string | null;
  image_path: string;
  rule_hits: string[];
  status: AlertStatus;
  narrative_state: NarrativeState;
  narrative_preview?: string | null;
  analyst_verdict?: Verdict | null;
  exclusion_created?: boolean;
  process_chain?: { name: string; pid: number; risk_score: number; depth: number }[];
}

export interface AlertListResponse {
  items: AlertSummary[];
  next_cursor: string | null;
  stats: {
    pending: number;
    observing: number;
    critical: number;
    today: number;
    total_matched: number;
    false_positive_rate: number;
  };
}

export interface AlertListQuery {
  severity?: Severity[];
  status?: string[];
  since?: string;
  until?: string;
  q?: string;
  has_narrative?: boolean;
  blocked_only?: boolean;
  sort?: 'risk_desc' | 'time_desc';
  limit?: number;
  cursor?: string | null;
}

// ---- 3. GET /alerts/{id} ----
export interface ProcessNodeDto {
  process_guid: string;
  parent_guid: string | null;
  pid: number;
  name: string;
  image_path: string;
  image_sha256: string | null;
  command_line: string;
  command_line_decoded?: string | null;
  decode_source?: string | null;
  signer: string | null;
  signature_status: 'valid' | 'invalid' | 'unsigned' | 'unknown' | string;
  created_at: string;
  terminated_at: string | null;
  state: 'running' | 'exited' | 'terminated_by_cairn' | 'suspended' | 'blocked' | string;
  risk_score: number;
  rule_hits: string[];
  depth: number;
  is_focus: boolean;
  preexisting: boolean;
  child_count: number;
  hidden_low_risk_children: number;
  excluded?: boolean;
}

export interface InjectionEdge {
  edge_id: string;
  source_guid: string;
  target_guid: string;
  technique: string;
  occurred_at: string;
  outcome: string;
  evidence_source: string;
}

export interface TimelineRuleHit {
  rule_id: string;
  step: string | null;
  score_delta: number;
}

export interface TimelineEvent {
  seq: number;
  event_id: number;
  time: string;
  process_guid: string;
  event_type: string;
  summary: string;
  target?: string | null;
  remote_addr?: string;
  remote_port?: number;
  rule_hits: TimelineRuleHit[];
  score_after?: number;
  action_taken?: ActionName | null;
  source: string;
  details?: Record<string, unknown>;
}

export interface MatchedRule {
  rule_id: string;
  title: string;
  severity: Severity;
  status: RuleStatus;
  score: number;
  attack_ids: string[];
  steps_matched?: number;
  steps_total?: number;
  window_seconds?: number;
  counted_toward_score?: boolean;
}

export interface ActionTaken {
  action_id: string;
  audit_id?: string | number;
  time: string;
  action: ActionName;
  target: string;
  initiator: string;
  result: 'success' | 'failed' | 'partial_success' | 'reverted' | string;
  reversible: boolean;
  reverted?: boolean;
  quarantine_id?: string;
}

export interface TelemetryGap {
  from: string;
  to: string;
  dropped_count: number;
}

export interface AlertDetail {
  alert_id: string;
  created_at: string;
  hostname: string;
  agent_id?: string;
  severity: Severity;
  risk_score: number;
  shadow_risk_score?: number;
  title: string;
  summary?: string | null;
  status: AlertStatus;
  analyst_verdict: Verdict | null;
  user_sid?: string | null;
  user_name?: string | null;
  focus_process_guid: string;
  root_process_guid: string;
  process_tree: ProcessNodeDto[];
  injection_edges: InjectionEdge[];
  timeline: TimelineEvent[];
  matched_rules: MatchedRule[];
  actions_taken: ActionTaken[];
  telemetry_gaps: TelemetryGap[];
  narrative_state: NarrativeState;
  available_targets?: {
    files?: { path: string; label?: string }[];
    ips?: { ip: string; port?: number }[];
  };
}

// ---- 4. GET /alerts/{id}/narrative ----
export interface Disclaimer {
  text: string;
  actual_decision_basis: {
    rule_ids: string[];
    risk_score: number;
    threshold: number;
    sentence: string;
  };
}

export interface AttackMapping {
  id: string;
  name: string;
  url: string;
  offline_description: string;
}

export interface NarrativeResponse {
  alert_id: string;
  state: NarrativeState;
  disclaimer: Disclaimer;
  narrative?: { what_happened: string; why_suspicious: string; what_it_means: string };
  recommendations?: string[];
  recommendations_note?: string;
  attack_mapping?: AttackMapping[];
  confidence?: number;
  confidence_label?: 'high' | 'medium' | 'low';
  linkable_entities?: { text: string; type: 'file' | 'ip' | 'process' | string; ref: string }[];
  provenance?: {
    model_id: string;
    model_sha256: string;
    generated_at: string;
    duration_ms: number;
    backend: string;
    device: string;
    schema_validated: boolean;
    attack_ids_whitelisted: boolean;
  };
  progress?: { elapsed_ms: number; expected_ms: number; streaming: boolean };
  hint?: string;
  error?: {
    code: string;
    message: string;
    retry_count?: number;
    raw_output_available?: boolean;
    raw_output?: string | null;
    detection_unaffected?: boolean;
    user_note?: string;
    elapsed_ms?: number;
    limit_ms?: number;
    likely_causes?: string[];
  };
  retryable?: boolean;
  retry_options?: { mode: 'same' | 'reduced_context'; label: string; event_count?: number }[];
}

// ---- 6. POST /alerts/{id}/verdict ----
export interface VerdictRequest {
  verdict?: Verdict | null;
  workflow_status?: WorkflowStatus;
  fp_reason?: string;
  note?: string;
  create_exclusion?: { type: ExclusionKind; value: string; scope: string };
}
export interface VerdictResponse {
  ok: boolean;
  affected_alerts: string[];
  exclusion_id?: string | number;
  undo_token?: string;
  undo_expires_at?: string;
}

// ---- 7/8. 回應動作 ----
export interface PrepareRequest {
  action: ActionName;
  target_guid?: string;
  target_path?: string;
  target_ip?: string;
}
export interface ImpactProcess {
  process_guid: string;
  pid: number;
  name: string;
  warning: string | null;
  warning_level?: 'high' | 'medium' | 'low';
}
export interface PrepareResponse {
  confirmation_token: string | null;
  expires_at: string | null;
  action: ActionName;
  risk_level: RiskLevel;
  reversible: boolean;
  require_typed_confirmation: boolean;
  typed_confirmation_expected?: string | null;
  impact: {
    processes?: ImpactProcess[];
    files?: { path: string; size_bytes?: number; sha256?: string; warning?: string | null }[];
    ips?: { ip: string; port?: number; warning?: string | null }[];
    total_count: number;
    protected_process_count?: number;
  };
}
export interface ExecuteRequest {
  action: ActionName;
  confirmation_token?: string | null;
  typed_confirmation?: string;
  reason: string;
  target_guid?: string;
  target_path?: string;
  target_ip?: string;
}
export interface ExecuteResponse {
  action_id: string;
  action: ActionName;
  overall_result: 'success' | 'partial_success' | 'failed';
  executed_at: string;
  initiator: { type: string; name: string };
  reason: string;
  results: {
    pid?: number;
    name?: string;
    target?: string;
    result: 'success' | 'failed';
    error_code?: string;
    error_message?: string;
  }[];
  audit_entry_id: string | number;
  reversible: boolean;
  undo_token?: string | null;
}
export interface RevertResponse {
  action_id: string;
  reverted_at: string;
  result: string;
  audit_entry_id: string | number;
}

// ---- 11/12/13. 排除清單 ----
export interface Exclusion {
  exclusion_id: number | string;
  kind: ExclusionKind;
  value: string;
  scope_rule_id: string;
  created_by: string;
  created_from_alert_id: string | null;
  created_at: string;
  expires_at: string | null;
  suppressed_count_30d: number;
  reason?: string | null;
  enabled?: boolean;
}
export interface ExclusionPreview {
  would_suppress_count: number;
  previously_true_positive_count: number;
  sample_alerts: { alert_id: string; title: string; time: string }[];
}
export interface ExclusionSuggestion {
  suggestion_id: string | number;
  type: ExclusionKind;
  value: string;
  rationale: string;
  triggered_count: number;
  affected_rule_ids: string[];
  sample_alert_ids: string[];
}

// ---- 14. 規則 ----
export interface RuleInfo {
  rule_id: string;
  title: string;
  severity: Severity;
  status: RuleStatus;
  score: number;
  attack_ids: string[];
  hits_30d: number;
  fp_rate_30d: number;
  shadow_alerts_30d: number;
  shadow_fp_rate_30d: number;
  load_error?: string | null;
}

// ---- 15. 稽核 ----
export interface AuditEntry {
  audit_id: number | string;
  time: string;
  action: string;
  target: string | null;
  initiator: string;
  reason?: string | null;
  result: string;
  related_alert_id?: string | null;
  chain_hash: string;
  confirmation_token_sha256?: string | null;
  impact_snapshot_sha256?: string | null;
  event_kind?: string | null;
}

// ---- 16. 隔離區 ----
export interface QuarantineItem {
  quarantine_id: string;
  original_path: string;
  sha256: string;
  size_bytes: number;
  quarantined_at: string;
  alert_id: string | null;
  audit_id: string | number | null;
  restored: boolean;
}

// ---- 錯誤 ----
export interface ApiErrorBody {
  error: { code: string; message?: string; details?: Record<string, unknown> };
}
