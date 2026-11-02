-- ============================================================
-- Cairn M0 端點儲存 schema v2（SQLite 3.4x, WAL, STRICT）
-- 權威來源：part2 §2.3.2（已含 SDD-02 §6.1.1 的 S-1 ~ S-13）
--           + SDD-03 §8.6.1 的 audit_log 擴充欄位（event_kind / targets_json / reason / impact_hash）與 append-only 觸發器
--
-- ⚠ 連線層 PRAGMA（journal_mode / synchronous / auto_vacuum / ...）不在此檔，由 SqliteDb::Open 在建表之前設定：
--   auto_vacuum = INCREMENTAL 必須在第一次 CREATE TABLE 之前生效（SDD-02 §6.6、必測項 T-09）。
-- ⚠ events.id 與 alerts.id 由 AnalysisThread 顯式指定（SDD-02 §5.4「events.id 從哪裡來」）。
-- ⚠ 本檔一經發布永不修改；變更一律新增 NNN_*.sql（SDD-03 §10.4 遷移鐵則）。
-- ============================================================

-- 1. events : 高頻原始事件（保留 7 天）
CREATE TABLE IF NOT EXISTS events (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    ts                  INTEGER NOT NULL,
    source              TEXT    NOT NULL,
    source_event_id     INTEGER NOT NULL,
    event_type          TEXT    NOT NULL,
    priority            INTEGER NOT NULL DEFAULT 2,
    process_guid        TEXT,
    parent_process_guid TEXT,
    root_process_guid   TEXT,
    pid                 INTEGER,
    image               TEXT,
    parent_image        TEXT,
    command_line        TEXT,
    parent_command_line TEXT,
    user_name           TEXT,
    integrity_level     TEXT,
    sha256              TEXT,
    signature_signer    TEXT,
    signature_valid     INTEGER,
    target_process_guid TEXT,
    target_image        TEXT,
    granted_access      INTEGER,
    target_filename     TEXT,
    registry_path       TEXT,
    registry_details    TEXT,
    dest_ip             TEXT,
    dest_port           INTEGER,
    dest_hostname       TEXT,
    query_name          TEXT,
    query_results       TEXT,
    pipe_name           TEXT,
    script_block        TEXT,
    score_delta         INTEGER NOT NULL DEFAULT 0,
    raw_json            TEXT
) STRICT;

CREATE INDEX IF NOT EXISTS ix_events_ts          ON events(ts DESC);
CREATE INDEX IF NOT EXISTS ix_events_pguid_ts    ON events(process_guid, ts);
CREATE INDEX IF NOT EXISTS ix_events_root_ts     ON events(root_process_guid, ts);
CREATE INDEX IF NOT EXISTS ix_events_type_ts     ON events(event_type, ts DESC);
CREATE INDEX IF NOT EXISTS ix_events_image       ON events(image) WHERE image IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_events_scored      ON events(ts DESC) WHERE score_delta != 0;
CREATE INDEX IF NOT EXISTS ix_events_sha256      ON events(sha256) WHERE sha256 IS NOT NULL;

-- 2. process_tree : 程序節點（保留 7 天）
CREATE TABLE IF NOT EXISTS process_tree (
    process_guid        TEXT PRIMARY KEY,
    parent_process_guid TEXT,
    root_process_guid   TEXT NOT NULL,
    depth               INTEGER NOT NULL DEFAULT 0,
    pid                 INTEGER NOT NULL,
    image               TEXT,
    command_line        TEXT,
    user_name           TEXT,
    integrity_level     TEXT,
    sha256              TEXT,
    signature_signer    TEXT,
    signature_valid     INTEGER,
    start_ts            INTEGER NOT NULL,
    end_ts              INTEGER,
    event_count         INTEGER NOT NULL DEFAULT 0,
    is_terminated_by_us INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE INDEX IF NOT EXISTS ix_ptree_parent  ON process_tree(parent_process_guid);
CREATE INDEX IF NOT EXISTS ix_ptree_root    ON process_tree(root_process_guid);
CREATE INDEX IF NOT EXISTS ix_ptree_start   ON process_tree(start_ts DESC);
CREATE INDEX IF NOT EXISTS ix_ptree_alive   ON process_tree(end_ts) WHERE end_ts IS NULL;

-- 3. scores : 程序樹風險分數（milli-point，80 分 = 80000）
CREATE TABLE IF NOT EXISTS scores (
    root_process_guid   TEXT PRIMARY KEY,
    score               INTEGER NOT NULL DEFAULT 0,
    peak_score          INTEGER NOT NULL DEFAULT 0,
    shadow_score        INTEGER NOT NULL DEFAULT 0,
    last_update_ts      INTEGER NOT NULL,
    first_hit_ts        INTEGER NOT NULL,
    state               TEXT    NOT NULL DEFAULT 'normal',
    FOREIGN KEY (root_process_guid) REFERENCES process_tree(process_guid) ON DELETE CASCADE
) STRICT;

CREATE INDEX IF NOT EXISTS ix_scores_score ON scores(score DESC);
CREATE INDEX IF NOT EXISTS ix_scores_state ON scores(state) WHERE state != 'normal';

-- 4. alerts : 告警（保留 90 天）
CREATE TABLE IF NOT EXISTS alerts (
    id                  INTEGER PRIMARY KEY,
    ts                  INTEGER NOT NULL,
    root_process_guid   TEXT    NOT NULL,
    trigger_process_guid TEXT,
    severity            TEXT    NOT NULL,
    score_at_trigger    INTEGER NOT NULL,
    rule_ids            TEXT    NOT NULL,
    attack_ids          TEXT,
    title               TEXT    NOT NULL,
    summary             TEXT,
    ai_state            TEXT    NOT NULL DEFAULT 'pending',
    ai_narrative        TEXT,
    ai_recommendation   TEXT,
    ai_confidence       REAL,
    ai_attack_ids       TEXT,
    ai_model_id         TEXT,
    ai_latency_ms       INTEGER,
    actions_taken       TEXT    NOT NULL DEFAULT '[]',
    analyst_verdict     TEXT,
    analyst_note        TEXT,
    verdict_ts          INTEGER
) STRICT;

CREATE INDEX IF NOT EXISTS ix_alerts_ts       ON alerts(ts DESC);
CREATE INDEX IF NOT EXISTS ix_alerts_root     ON alerts(root_process_guid);
CREATE INDEX IF NOT EXISTS ix_alerts_severity ON alerts(severity, ts DESC);
CREATE INDEX IF NOT EXISTS ix_alerts_aistate  ON alerts(ai_state) WHERE ai_state = 'pending';
CREATE INDEX IF NOT EXISTS ix_alerts_verdict  ON alerts(analyst_verdict) WHERE analyst_verdict IS NOT NULL;

-- 5. exclusions : 排除清單（scope_rule_id '' = 全域；不可用 NULL，否則 UNIQUE 失效 —— S-10）
CREATE TABLE IF NOT EXISTS exclusions (
    id            INTEGER PRIMARY KEY,
    kind          TEXT    NOT NULL,
    value         TEXT    NOT NULL,
    scope_rule_id TEXT    NOT NULL DEFAULT '',
    reason        TEXT,
    created_by    TEXT    NOT NULL DEFAULT 'user',
    created_ts    INTEGER NOT NULL,
    expires_ts    INTEGER,
    enabled       INTEGER NOT NULL DEFAULT 1,
    hit_count     INTEGER NOT NULL DEFAULT 0,
    last_hit_ts   INTEGER,
    UNIQUE(kind, value, scope_rule_id)
) STRICT;

CREATE INDEX IF NOT EXISTS ix_excl_kind ON exclusions(kind, enabled);

-- 6. rule_hits : 規則命中紀錄（S-3；event_id 為 SET NULL —— S-12）
CREATE TABLE IF NOT EXISTS rule_hits (
    id                  INTEGER PRIMARY KEY,
    ts                  INTEGER NOT NULL,
    rule_id             TEXT    NOT NULL,
    root_process_guid   TEXT    NOT NULL,
    event_id            INTEGER,
    alert_id            INTEGER,
    score_delta         INTEGER NOT NULL DEFAULT 0,
    dryrun              INTEGER NOT NULL DEFAULT 0,
    suppressed          INTEGER NOT NULL DEFAULT 0,
    suppressed_by       INTEGER,
    rule_hash           TEXT    NOT NULL,
    FOREIGN KEY (event_id)      REFERENCES events(id)     ON DELETE SET NULL,
    FOREIGN KEY (alert_id)      REFERENCES alerts(id)     ON DELETE SET NULL,
    FOREIGN KEY (suppressed_by) REFERENCES exclusions(id) ON DELETE SET NULL
) STRICT;

CREATE INDEX IF NOT EXISTS ix_rule_hits_rule  ON rule_hits(rule_id, ts DESC);
CREATE INDEX IF NOT EXISTS ix_rule_hits_alert ON rule_hits(alert_id) WHERE alert_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_rule_hits_tree  ON rule_hits(root_process_guid, ts DESC);
-- FK 子表的父鍵查詢索引：刪除 events / exclusions 時 SET NULL 需要以 event_id / suppressed_by 反查
CREATE INDEX IF NOT EXISTS ix_rule_hits_event ON rule_hits(event_id) WHERE event_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_rule_hits_excl  ON rule_hits(suppressed_by) WHERE suppressed_by IS NOT NULL;

-- 7. alert_events : 告警 ↔ 事件多對多（S-4）
--    ⚠ event_id 為 CASCADE，events retention 必須排除被引用者（RetentionJob）
CREATE TABLE IF NOT EXISTS alert_events (
    alert_id            INTEGER NOT NULL,
    event_id            INTEGER NOT NULL,
    step_index          INTEGER,
    role                TEXT    NOT NULL DEFAULT 'evidence',
    PRIMARY KEY (alert_id, event_id),
    FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE,
    FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
) STRICT;

CREATE INDEX IF NOT EXISTS ix_alert_events_event ON alert_events(event_id);

-- 8. audit_log : 稽核記錄（append-only + 雜湊鏈；S-5 / S-13）
--    row_hash = SHA256(prev_hash || canonical_json(本列除 row_hash 外欄位))；第一列 prev_hash = 64 個 '0'
--    AUTOINCREMENT：id 永不重用，刪列會留下可偵測的缺口（SDD-03 §8.6.3）
--    alert_id 刻意不宣告 FK（S-13：SET NULL 會就地改寫此列使雜湊鏈失效）
CREATE TABLE IF NOT EXISTS audit_log (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    ts                  INTEGER NOT NULL,
    actor               TEXT    NOT NULL,
    action              TEXT    NOT NULL,
    event_kind          TEXT    NOT NULL DEFAULT '',
    alert_id            INTEGER,
    target              TEXT,
    params              TEXT    NOT NULL DEFAULT '{}',
    result              TEXT    NOT NULL,
    error               TEXT,
    prev_hash           TEXT    NOT NULL,
    row_hash            TEXT    NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS ix_audit_ts    ON audit_log(ts DESC);
CREATE INDEX IF NOT EXISTS ix_audit_alert ON audit_log(alert_id) WHERE alert_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_audit_kind  ON audit_log(action, ts DESC);

-- append-only 的資料庫層強制。誠實定位：防程式碼缺陷，不防管理員（任何人都能 DROP TRIGGER）
CREATE TRIGGER IF NOT EXISTS trg_audit_no_update
BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;

CREATE TRIGGER IF NOT EXISTS trg_audit_no_delete
BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;

-- 9. agent_health : 自我遙測（S-6 / S-11）
CREATE TABLE IF NOT EXISTS agent_health (
    id               INTEGER PRIMARY KEY,
    ts               INTEGER NOT NULL,
    events_ingested  INTEGER NOT NULL,
    events_dropped   INTEGER NOT NULL,
    events_filtered  INTEGER NOT NULL DEFAULT 0,
    queue_depth      INTEGER NOT NULL,
    cpu_percent      REAL    NOT NULL,
    private_bytes_mb REAL    NOT NULL,
    db_size_mb       REAL    NOT NULL,
    sysmon_state     TEXT    NOT NULL,
    llm_state        TEXT    NOT NULL,
    tier2_p95_ms     REAL,
    llm_p95_ms       REAL
) STRICT;

CREATE INDEX IF NOT EXISTS ix_health_ts ON agent_health(ts DESC);

-- 10. dismissed_suggestions : 已忽略的排除建議（exclusions.dismissSuggestion，part3 §3.8.1 端點 22）
CREATE TABLE IF NOT EXISTS dismissed_suggestions (
    suggestion_id TEXT PRIMARY KEY,
    dismissed_ts  INTEGER NOT NULL
) STRICT;
