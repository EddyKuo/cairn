#include "engine/AnalysisEngine.h"

#include <algorithm>
#include <cstdio>
#include <unordered_set>

#include "rules/TextMatch.h"

namespace cairn::engine {

using model::GuidValue;
using model::TreeState;

namespace {
constexpr size_t kMaxHitsPerTree   = 64;
constexpr size_t kMaxTrackedAlerts = 20'000;
constexpr size_t kLatencyWindow    = 1024;

bool IsLoopback(std::string_view ip) noexcept
{
    return ip.rfind("127.", 0) == 0 || ip == "::1" || ip == "0.0.0.0" || ip.empty();
}

int SeverityRank(model::Severity s) noexcept { return static_cast<int>(s); }
} // namespace

Result<std::unique_ptr<AnalysisEngine>> AnalysisEngine::Create(Deps deps, EnginePolicy policy)
{
    if (!deps.interner) return MakeError(ErrorCode::InvalidArgument, "AnalysisEngine: interner 為必填");
    if (!deps.writes) return MakeError(ErrorCode::InvalidArgument, "AnalysisEngine: writes 為必填");
    if (!deps.clock) return MakeError(ErrorCode::InvalidArgument, "AnalysisEngine: clock 為必填");
    return std::unique_ptr<AnalysisEngine>(new AnalysisEngine(deps, std::move(policy)));
}

AnalysisEngine::AnalysisEngine(Deps deps, EnginePolicy policy)
    : m_deps(deps), m_policy(std::move(policy)),
      m_tree(*deps.interner, m_policy.treeLimits, m_policy.treeBoundaryImages)
{
    for (auto& s : m_policy.neverTargetImages) s = model::ToLowerAscii(s);
    m_latencyUs.reserve(kLatencyWindow);
}

// ---------------------------------------------------------------- 寫入輔助

void AnalysisEngine::PostWrite(model::WritePayload&& p)
{
    model::WriteOp op{std::move(p), {}};
    if (!m_deps.writes->Post(std::move(op))) ++m_stats.writeDropped;
}

void AnalysisEngine::PostScore(const GuidValue& root)
{
    const score::TreeScore* ts = m_scores.Find(root);
    if (!ts) return;
    model::ScoreRow row;
    row.rootProcessGuid = root;
    row.scoreMilli      = ts->scoreMilli;
    row.peakMilli       = ts->peakMilli;
    row.shadowMilli     = ts->shadowMilli;
    row.lastUpdateTs    = ts->lastUpdateMs;
    row.firstHitTs      = ts->firstHitMs;
    row.state           = ts->state;
    PostWrite(std::move(row));
}

std::string AnalysisEngine::ImageOf(const tree::ProcessNode& n) const
{
    if (n.image != model::kInvalidInternId) return std::string(m_deps.interner->Resolve(n.image));
    return n.imageFallback;
}

model::ProcessRow AnalysisEngine::MakeProcessRow(const tree::ProcessNode& n) const
{
    model::ProcessRow r;
    r.processGuid       = n.guid;
    r.parentProcessGuid = n.parentGuid;
    r.rootProcessGuid   = n.rootGuid;
    r.depth             = n.depth;
    r.pid               = n.pid;
    r.image             = ImageOf(n);
    r.commandLine       = n.commandLine;
    r.userName          = std::string(m_deps.interner->Resolve(n.user));
    r.integrityLevel    = n.integrityLevel;
    r.sha256            = n.sha256;
    r.signatureSigner   = std::string(m_deps.interner->Resolve(n.signer));
    r.signatureValid    = n.signatureValid;
    r.startTs           = n.startMs;
    if (n.endMs) r.endTs = n.endMs;
    r.eventCount = n.eventCount;
    return r;
}

void AnalysisEngine::RecordLatency(int64_t micros)
{
    if (m_latencyUs.size() < kLatencyWindow) m_latencyUs.push_back(micros);
    else m_latencyUs[m_latencyPos] = micros;
    m_latencyPos = (m_latencyPos + 1) % kLatencyWindow;
}

// ---------------------------------------------------------------- 設定

void AnalysisEngine::SetNextIds(int64_t nextEventId, int64_t nextAlertId) noexcept
{
    m_nextEventId = std::max<int64_t>(1, nextEventId);
    m_nextAlertId = std::max<int64_t>(1, nextAlertId);
}

void AnalysisEngine::SeedProcesses(const std::vector<tree::SnapshotProcess>& procs)
{
    const int64_t now = m_deps.clock->NowMs();
    m_tree.Seed(procs, *m_deps.interner, now);
    for (const auto& p : procs)
        if (const auto* n = m_tree.Find(p.guid)) PostWrite(MakeProcessRow(*n));
}

void AnalysisEngine::ReplaceRuleSet(std::shared_ptr<const rules::RuleSet> rs)
{
    m_rules.SetRuleSet(std::move(rs));
}

void AnalysisEngine::ReplaceExclusions(std::vector<rules::ExclusionEntry> entries)
{
    m_exclusions.Reload(std::move(entries));
}

void AnalysisEngine::SetPolicy(EnginePolicy policy)
{
    // 樹的上限與邊界在建構時決定；執行期只更新回應相關政策
    for (auto& s : policy.neverTargetImages) s = model::ToLowerAscii(s);
    policy.treeLimits         = m_policy.treeLimits;
    policy.treeBoundaryImages = m_policy.treeBoundaryImages;
    m_policy = std::move(policy);
}

void AnalysisEngine::SetProtectionPaused(bool paused) noexcept { m_paused = paused; }
void AnalysisEngine::SetLearningMode(bool on) noexcept { m_policy.learningMode = on; }

// ---------------------------------------------------------------- 事件路徑

void AnalysisEngine::OnReroot(const GuidValue& oldRoot, const GuidValue& newRoot, int64_t nowMs)
{
    m_rules.Rekey(oldRoot, newRoot);
    if (auto it = m_evidence.find(oldRoot); it != m_evidence.end()) {
        TreeEvidence src = std::move(it->second);
        m_evidence.erase(it);
        TreeEvidence& dst = m_evidence[newRoot];
        for (auto& h : src.hits) {
            if (dst.hits.size() >= kMaxHitsPerTree) dst.hits.pop_front();
            dst.hits.push_back(std::move(h));
        }
        if (src.lastDestIp && !dst.lastDestIp) {
            dst.lastDestIp   = src.lastDestIp;
            dst.lastDestPort = src.lastDestPort;
        }
    }
    if (auto tr = m_scores.MergeRoot(oldRoot, newRoot, nowMs)) {
        model::ScoreRow zero;   // 舊根的分數列歸零（DB 端以新根為準）
        zero.rootProcessGuid = oldRoot;
        zero.lastUpdateTs    = nowMs;
        zero.firstHitTs      = nowMs;
        PostWrite(std::move(zero));
        PostScore(newRoot);
        // 合併後跨過閾值：比照 ApplyDelta 的升級處理（無觸發事件，以合成事件建立告警）
        if (tr->IsEscalation() && (tr->to == TreeState::Alerted || tr->to == TreeState::Blocked)) {
            const score::TreeScore* ts = m_scores.Find(newRoot);
            if (ts && ts->alertId == 0) {
                model::NormalizedEvent synthetic;
                synthetic.processGuid = newRoot;
                synthetic.time        = FromUnixMs(nowMs);
                PendingAlert pa{newRoot, *tr, {}};
                RaiseAlert(std::move(pa), synthetic, 0, nowMs);
            }
        }
        if (tr->to == TreeState::Watched || tr->to == TreeState::Alerted || tr->to == TreeState::Blocked)
            SetSampled(newRoot, true);
    }
}

void AnalysisEngine::OnEvent(model::NormalizedEvent&& ev)
{
    const int64_t clockNow = m_deps.clock->NowMs();
    int64_t tsMs = ToUnixMs(ev.time);
    if (tsMs <= 0) tsMs = clockNow;
    const int64_t eventId = m_nextEventId++;
    ++m_stats.eventsProcessed;

    auto reroot = [this, tsMs](const GuidValue& o, const GuidValue& n) { OnReroot(o, n, tsMs); };

    // ---- 1) 程序樹 ----
    tree::ProcessNode* node = nullptr;
    switch (ev.type) {
    case model::EventType::ProcessCreate:
        node = m_tree.OnProcessCreate(ev, clockNow, reroot);
        if (node) PostWrite(MakeProcessRow(*node));
        break;
    case model::EventType::ProcessTerminate:
        node = m_tree.OnProcessExit(ev.processGuid, tsMs);
        if (node) PostWrite(model::ProcessEndUpdate{node->guid, tsMs});
        break;
    default: {
        const size_t before = m_tree.NodeCount();
        node = m_tree.FindOrCreateStub(ev, clockNow);
        if (node && m_tree.NodeCount() != before) PostWrite(MakeProcessRow(*node));
        break;
    }
    }
    if (node) {
        ++node->eventCount;
        node->lastEventMs = clockNow;
    }
    const GuidValue root = node ? node->rootGuid : ev.processGuid;

    if (ev.type == model::EventType::NetworkConnect && ev.destinationIp && !IsLoopback(*ev.destinationIp)) {
        TreeEvidence& te = m_evidence[root];
        te.lastDestIp   = ev.destinationIp;
        te.lastDestPort = ev.destinationPort;
    }

    // ---- 2) 規則求值（Tier-1 / Tier-2）----
    const auto t0 = std::chrono::steady_clock::now();
    rules::EvalContext ctx{ev, node, &m_tree, *m_deps.interner, nullptr, tsMs, m_scores.CurrentScore(root, tsMs)};
    std::vector<rules::EngineHit> hits = m_rules.Evaluate(ctx, eventId, tsMs);
    RecordLatency(std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - t0).count());

    // ---- 3) 排除 → 計分（完全不經 LLM）----
    int64_t eventDelta = 0;
    std::vector<model::RuleHitRow> plainRows;
    std::vector<PendingAlert>      alerts;
    std::vector<GuidValue>         touchedRoots;

    const std::string_view image = model::ResolveField(*m_deps.interner, ev.image, ev.imageFallback);
    const std::string_view signer = model::ResolveField(*m_deps.interner, ev.signer, ev.signerFallback);
    const rules::ExclusionSubject subject{image,
                                          !ev.sha256.empty() ? std::string_view{ev.sha256}
                                          : node             ? std::string_view{node->sha256}
                                                             : std::string_view{},
                                          signer,
                                          !ev.commandLine.empty() ? std::string_view{ev.commandLine}
                                          : node                  ? std::string_view{node->commandLine}
                                                                  : std::string_view{}};

    for (auto& h : hits) {
        const rules::Rule& rule = *h.rule;
        ++m_stats.ruleHits;
        const GuidValue scoreRoot =
            rule.correlateBy == rules::CorrelateBy::ProcessGuid ? m_tree.RootOf(h.key) : h.key;

        const auto supp   = m_exclusions.IsSuppressed(rule.id, rule.exceptions, subject, tsMs);
        const bool dryRun = rule.status == model::RuleStatus::DryRun;
        const bool booster = !h.boosterId.empty();

        score::RuleHit rh;
        rh.ruleId        = rule.id;
        rh.deltaMilli    = h.scoreMilli;
        rh.tsMs          = tsMs;
        rh.halfLifeMs    = rule.halfLifeMs;
        rh.deterministic = rule.deterministic && !booster;
        rh.dryRun        = dryRun;
        rh.suppressed    = supp.has_value();
        if (booster) rh.ruleId = rule.id + "#" + h.boosterId;   // booster 自有冷卻鍵
        const score::ScoreTransition tr = m_scores.ApplyDelta(scoreRoot, rh);
        eventDelta += tr.appliedDeltaMilli;

        if (supp) ++m_stats.suppressedHits;
        if (dryRun) ++m_stats.dryrunHits;
        if (supp && supp->exclusionId) PostWrite(model::ExclusionHitIncrement{*supp->exclusionId, 1, tsMs});

        model::RuleHitRow row;
        row.ts              = tsMs;
        row.ruleId          = rule.id;
        row.rootProcessGuid = scoreRoot;
        row.eventId         = eventId;
        row.scoreDeltaMilli = supp ? 0 : (dryRun ? h.scoreMilli : tr.appliedDeltaMilli);
        row.dryrun          = dryRun;
        row.suppressed      = supp.has_value();
        if (supp) row.suppressedBy = supp->exclusionId;
        row.ruleHash = rule.hashHex;

        if (!supp && !dryRun) {
            TreeEvidence& te = m_evidence[scoreRoot];
            HitRecord hr;
            hr.ruleId        = rule.id;
            hr.title         = rule.title;
            hr.severity      = rule.severity;
            hr.attackIds     = rule.attackIds;
            hr.response      = rule.response;
            hr.deterministic = rule.deterministic && !booster;
            hr.sequence      = rule.IsSequence();
            hr.scoreMilli    = h.scoreMilli;
            hr.tsMs          = tsMs;
            hr.evidence      = h.evidence;
            if (te.hits.size() >= kMaxHitsPerTree) te.hits.pop_front();
            te.hits.push_back(std::move(hr));
        }

        if (std::find(touchedRoots.begin(), touchedRoots.end(), scoreRoot) == touchedRoots.end())
            touchedRoots.push_back(scoreRoot);

        if (tr.IsEscalation() && (tr.to == TreeState::Alerted || tr.to == TreeState::Blocked)) {
            // 同一事件內同一棵樹的多次升級合併為一則告警（取最高狀態）
            auto pit = std::find_if(alerts.begin(), alerts.end(), [&](const PendingAlert& p) { return p.root == scoreRoot; });
            if (pit == alerts.end()) {
                alerts.push_back(PendingAlert{scoreRoot, tr, {}});
                pit = alerts.end() - 1;
            } else if (tr.to > pit->tr.to) {
                pit->tr = tr;
            }
            pit->rows.push_back(std::move(row));
        } else {
            if (tr.to == TreeState::Watched && tr.from == TreeState::Benign) SetSampled(scoreRoot, true);
            // 若此樹已有待建告警，這筆命中也歸入同一告警
            auto pit = std::find_if(alerts.begin(), alerts.end(), [&](const PendingAlert& p) { return p.root == scoreRoot; });
            if (pit != alerts.end()) pit->rows.push_back(std::move(row));
            else plainRows.push_back(std::move(row));
        }
    }

    // ---- 4) 投遞：事件先於命中與告警（WriterThread 須保證 alert_events 的 FK 不早於事件落地）----
    model::EventRow er;
    er.id              = eventId;
    er.rootProcessGuid = root;
    er.scoreDeltaMilli = eventDelta;
    const model::NormalizedEvent* evForAlert = nullptr;
    model::NormalizedEvent alertEvCopy;
    if (!alerts.empty()) {
        alertEvCopy.processGuid = ev.processGuid;
        alertEvCopy.image       = ev.image;
        alertEvCopy.imageFallback = ev.imageFallback;
        alertEvCopy.signatureValid = ev.signatureValid;
        alertEvCopy.time        = ev.time;
        evForAlert              = &alertEvCopy;
    }
    er.ev = std::move(ev);
    PostWrite(std::move(er));

    for (auto& r : plainRows) PostWrite(std::move(r));
    for (auto& pa : alerts) RaiseAlert(std::move(pa), *evForAlert, eventId, tsMs);
    for (const auto& r : touchedRoots) PostScore(r);
}

void AnalysisEngine::RaiseAlert(PendingAlert&& pa, const model::NormalizedEvent& ev, int64_t eventId, int64_t tsMs)
{
    const int64_t alertId = m_nextAlertId++;
    m_scores.SetAlertId(pa.root, alertId);
    m_alertRoots[alertId] = pa.root;
    m_alertOrder.push_back(alertId);
    while (m_alertOrder.size() > kMaxTrackedAlerts) {
        m_alertRoots.erase(m_alertOrder.front());
        m_alertOrder.pop_front();
    }
    ++m_stats.alertsRaised;
    SetSampled(pa.root, true);

    TreeEvidence& te = m_evidence[pa.root];

    model::AlertRow a;
    a.id                  = alertId;
    a.ts                  = tsMs;
    a.rootProcessGuid     = pa.root;
    if (!ev.processGuid.IsNull()) a.triggerProcessGuid = ev.processGuid;
    a.scoreAtTriggerMilli = pa.tr.scoreMilli;
    a.aiState             = model::AiState::Pending;

    // ---- 規則 id / ATT&CK / 嚴重度 / 標題（純模板，不依賴 LLM）----
    model::Severity sev = model::Severity::High;
    const HitRecord* top = nullptr;
    std::unordered_set<std::string> seenRule, seenAttack;
    for (const auto& h : te.hits) {
        if (seenRule.insert(h.ruleId).second) a.ruleIds.push_back(h.ruleId);
        for (const auto& at : h.attackIds)
            if (seenAttack.insert(at).second) a.attackIds.push_back(at);
        if (SeverityRank(h.severity) > SeverityRank(sev)) sev = h.severity;
        if (!top || h.scoreMilli > top->scoreMilli) top = &h;
    }
    if (pa.tr.to == TreeState::Blocked) sev = model::Severity::Critical;
    a.severity = sev;
    a.title    = top ? top->title : std::string("程序樹風險分數超過告警閾值");

    std::string rootImage;
    if (const auto* rn = m_tree.Find(pa.root)) rootImage = ImageOf(*rn);
    std::string trigImage(model::ResolveField(*m_deps.interner, ev.image, ev.imageFallback));
    char scoreBuf[32];
    std::snprintf(scoreBuf, sizeof(scoreBuf), "%lld.%03lld", static_cast<long long>(pa.tr.scoreMilli / 1000),
                  static_cast<long long>(pa.tr.scoreMilli % 1000));
    a.summary = "程序樹 " + (rootImage.empty() ? pa.root.ToString() : rootImage) + " 的風險分數達 " + scoreBuf +
                (pa.tr.to == TreeState::Blocked ? "（≥ 95，阻擋級）" : "（≥ 80，告警級）") + "。命中規則：";
    for (size_t i = 0; i < a.ruleIds.size(); ++i) {
        if (i) a.summary += "、";
        a.summary += a.ruleIds[i];
    }
    if (!trigImage.empty()) a.summary += "。觸發程序：" + trigImage;
    a.summary += "。";

    // ---- alert_events：構成鏈的事件與其步驟序號 ----
    std::unordered_set<int64_t> seenEvents;
    if (eventId > 0) {
        a.events.push_back(model::AlertEventLink{eventId, std::nullopt, "trigger"});
        seenEvents.insert(eventId);
    }
    for (auto it = te.hits.rbegin(); it != te.hits.rend() && a.events.size() < m_policy.maxEvidenceEventsPerAlert; ++it) {
        for (size_t s = 0; s < it->evidence.size(); ++s) {
            const auto& rec = it->evidence[s];
            if (rec.eventId <= 0) continue;
            if (!seenEvents.insert(rec.eventId).second) {
                // 觸發事件本身也是某一步：補上步驟序號
                if (rec.eventId == eventId && it->sequence && a.events.front().eventId == eventId &&
                    !a.events.front().stepIndex)
                    a.events.front().stepIndex = static_cast<int32_t>(s);
                continue;
            }
            model::AlertEventLink l;
            l.eventId = rec.eventId;
            if (it->sequence) l.stepIndex = static_cast<int32_t>(s);
            l.role = "evidence";
            a.events.push_back(std::move(l));
            if (a.events.size() >= m_policy.maxEvidenceEventsPerAlert) break;
        }
    }

    for (auto& r : pa.rows) r.alertId = alertId;
    a.hits = std::move(pa.rows);

    model::AlertRaised raised;
    raised.alertId         = alertId;
    raised.rootProcessGuid = pa.root;
    raised.scoreMilli      = pa.tr.scoreMilli;
    raised.severity        = a.severity;
    raised.state           = pa.tr.to;
    raised.title           = a.title;

    PostWrite(std::move(a));
    if (m_deps.alerts) m_deps.alerts->OnAlertRaised(raised);

    PlanResponses(alertId, pa.root, pa.tr, ev);
}

bool AnalysisEngine::IsNeverTarget(std::string_view imagePath) const
{
    const std::string base = model::ToLowerAscii(tree::BaseName(imagePath));
    return std::find(m_policy.neverTargetImages.begin(), m_policy.neverTargetImages.end(), base) !=
           m_policy.neverTargetImages.end();
}

void AnalysisEngine::PlanResponses(int64_t alertId, const GuidValue& root, const score::ScoreTransition& tr,
                                   const model::NormalizedEvent& ev)
{
    if (!m_deps.responses) return;

    const TreeEvidence& te = m_evidence[root];
    const int64_t score = tr.scoreMilli;
    bool anyDeterministic = false;
    std::vector<model::ActionKind> acts;
    auto add = [&](model::ActionKind k) {
        if (std::find(acts.begin(), acts.end(), k) == acts.end()) acts.push_back(k);
    };
    for (const auto& h : te.hits) {
        anyDeterministic = anyDeterministic || h.deterministic;
        if (h.response.requireConfirmation) continue;   // 需人工確認的規則不自動執行
        if (score < static_cast<int64_t>(h.response.onScoreGe) * model::kScoreScale) continue;
        for (auto k : h.response.actions) add(k);
    }
    if (tr.to == TreeState::Blocked && m_policy.blockedDefaultActions) {
        add(model::ActionKind::TerminateProcessTree);
        add(model::ActionKind::QuarantineFile);
        add(model::ActionKind::FirewallBlock);
    }
    // C-8 原則 4：terminate_process_tree 僅在分數 >= 95 或 deterministic 時自動執行；否則降為可逆的 suspend
    auto has = [&](model::ActionKind k) { return std::find(acts.begin(), acts.end(), k) != acts.end(); };
    if (has(model::ActionKind::TerminateProcessTree) && !(score >= model::kThresholdBlocked || anyDeterministic)) {
        acts.erase(std::remove(acts.begin(), acts.end(), model::ActionKind::TerminateProcessTree), acts.end());
        add(model::ActionKind::SuspendProcess);
    }
    if (has(model::ActionKind::TerminateProcessTree))
        acts.erase(std::remove(acts.begin(), acts.end(), model::ActionKind::SuspendProcess), acts.end());
    if (acts.empty()) return;

    if (!m_policy.autoResponseEnabled || m_policy.learningMode || m_paused) {
        m_stats.responsesWithheld += acts.size();
        return;
    }

    // 執行順序：先止血（暫停／終止），再斷 C2，最後隔離檔案（檔案可能被持有者鎖定）
    std::stable_sort(acts.begin(), acts.end(), [](model::ActionKind a, model::ActionKind b) {
        auto rank = [](model::ActionKind k) {
            switch (k) {
            case model::ActionKind::SuspendProcess: return 0;
            case model::ActionKind::TerminateProcessTree: return 0;
            case model::ActionKind::FirewallBlock: return 1;
            case model::ActionKind::QuarantineFile: return 2;
            }
            return 3;
        };
        return rank(a) < rank(b);
    });

    std::vector<model::ProcessRef> procs = SnapshotTree(root, /*aliveOnly=*/true);
    procs.erase(std::remove_if(procs.begin(), procs.end(),
                               [&](const model::ProcessRef& p) { return IsNeverTarget(p.image); }),
                procs.end());

    char scoreBuf[16];
    std::snprintf(scoreBuf, sizeof(scoreBuf), "%lld", static_cast<long long>(score / 1000));

    for (auto k : acts) {
        model::ResponseCommand cmd;
        cmd.alertId         = alertId;
        cmd.action          = k;
        cmd.rootProcessGuid = root;
        cmd.actor           = "rule_engine";
        cmd.automatic       = true;
        cmd.reason          = std::string("auto: score ") + scoreBuf + " state " +
                     std::string(model::TreeStateToDb(tr.to));

        switch (k) {
        case model::ActionKind::SuspendProcess:
        case model::ActionKind::TerminateProcessTree:
            if (procs.empty()) continue;
            cmd.target.processes = procs;
            cmd.target.key = "tree:" + root.ToString();
            break;
        case model::ActionKind::QuarantineFile: {
            // 只隔離「使用者可寫目錄下、且非有效簽章」的執行檔：隔離 System32 的 powershell.exe 會毀掉系統
            const std::string img(model::ResolveField(*m_deps.interner, ev.image, ev.imageFallback));
            if (img.empty() || IsNeverTarget(img)) continue;
            const bool userDir = rules::ContainsCi(img, "\\users\\") || rules::ContainsCi(img, "\\temp\\") ||
                                 rules::ContainsCi(img, "\\appdata\\") || rules::ContainsCi(img, "\\downloads\\") ||
                                 rules::ContainsCi(img, "\\programdata\\") || rules::ContainsCi(img, "\\public\\");
            const bool signedOk = ev.signatureValid.value_or(false);
            if (!userDir || signedOk) continue;
            cmd.target.filePath = img;
            cmd.target.key      = "file:" + img;
            break;
        }
        case model::ActionKind::FirewallBlock:
            if (!te.lastDestIp) continue;
            cmd.target.ip   = te.lastDestIp;
            cmd.target.port = te.lastDestPort;
            cmd.target.key  = "ip:" + *te.lastDestIp;
            break;
        }
        m_deps.responses->Submit(std::move(cmd));
        ++m_stats.responsesSubmitted;
    }
}

void AnalysisEngine::SetSampled(const GuidValue& root, bool on)
{
    m_tree.WalkSubtreeMut(root, [on](tree::ProcessNode& n) {
        if (on) tree::SetFlag(n.flags, tree::NodeFlags::Sampled);
        else tree::ClearFlag(n.flags, tree::NodeFlags::Sampled);
    });
}

// ---------------------------------------------------------------- 定時器

void AnalysisEngine::OnTick(UnixMs nowMs)
{
    ++m_tickCount;
    for (const auto& tr : m_scores.SweepDecay(nowMs)) {
        if (tr.erased) {
            model::ScoreRow zero;
            zero.rootProcessGuid = tr.root;
            zero.peakMilli       = tr.peakMilli;
            zero.lastUpdateTs    = nowMs;
            zero.firstHitTs      = nowMs;
            zero.state           = TreeState::Benign;
            PostWrite(std::move(zero));
        } else {
            PostScore(tr.root);
        }
        if (tr.to == TreeState::Benign) SetSampled(tr.root, false);
    }
    m_tree.ExpireOrphans(nowMs);
    (void)m_rules.Expire(nowMs - m_policy.sequenceExpireSlackMs);

    if (m_tickCount % 10 == 0) {
        std::vector<GuidValue> reclaimed;
        m_tree.Reap(nowMs, [&](const GuidValue& root) {
            if (m_rules.HasActiveFor(root)) return false;                         // (e)
            if (const score::TreeScore* ts = m_scores.Find(root)) {
                const bool terminal = ts->state == TreeState::Resolved || ts->state == TreeState::Excluded;
                if (ts->state == TreeState::Benign) {
                    if (ts->alertId != 0) return false;                           // (d)
                } else if (terminal) {
                    if (nowMs - ts->stateChangedMs <= m_policy.resolvedRetentionMs) return false;
                } else {
                    return false;                                                 // Watched 以上絕不回收
                }
            }
            reclaimed.push_back(root);
            return true;
        });
        for (const auto& r : reclaimed) {
            m_scores.Erase(r);
            m_evidence.erase(r);
        }
    }
}

// ---------------------------------------------------------------- 分析師操作與查詢

Status AnalysisEngine::ApplyVerdict(int64_t alertId, model::Verdict verdict)
{
    auto it = m_alertRoots.find(alertId);
    if (it == m_alertRoots.end())
        return MakeError(ErrorCode::NotFound, "告警不在記憶體中（可能已被回收）：" + std::to_string(alertId));
    return ApplyVerdictByRoot(it->second, verdict);
}

Status AnalysisEngine::ApplyVerdictByRoot(const GuidValue& root, model::Verdict /*verdict*/)
{
    // 真陽性、誤報、良性三者對引擎的效果相同：該樹不再自動轉移（SDD-02 §4.4）。
    // 「誤報 → 排除規則」由 RPC 層另行新增 exclusion 後呼叫 ReplaceExclusions。
    const int64_t now = m_deps.clock->NowMs();
    if (!m_scores.MarkResolved(root, now))
        return MakeError(ErrorCode::NotFound, "程序樹沒有分數紀錄：" + root.ToString());
    PostScore(root);
    return Ok();
}

void AnalysisEngine::MarkTerminatedByUs(const GuidValue& processGuid)
{
    if (auto* n = m_tree.Find(processGuid)) tree::SetFlag(n->flags, tree::NodeFlags::TerminatedByUs);
    PostWrite(model::ProcessTerminatedByUs{processGuid});
}

std::vector<model::ProcessRef> AnalysisEngine::SnapshotTree(const GuidValue& root, bool aliveOnly) const
{
    std::vector<model::ProcessRef> out;
    m_tree.WalkSubtree(root, [&](const tree::ProcessNode& n) {
        if (aliveOnly && tree::HasFlag(n.flags, tree::NodeFlags::Exited)) return;
        model::ProcessRef r;
        r.processGuid = n.guid;
        r.pid         = n.pid;
        r.startTsMs   = n.startMs;
        r.image       = ImageOf(n);
        r.depth       = n.depth;
        out.push_back(std::move(r));
    });
    return out;
}

std::optional<GuidValue> AnalysisEngine::RootOfAlert(int64_t alertId) const
{
    auto it = m_alertRoots.find(alertId);
    if (it == m_alertRoots.end()) return std::nullopt;
    return it->second;
}

int64_t AnalysisEngine::CurrentScore(const GuidValue& root)
{
    return m_scores.CurrentScore(root, m_deps.clock->NowMs());
}

EngineStats AnalysisEngine::Stats() const
{
    EngineStats s    = m_stats;
    s.treeNodes      = m_tree.NodeCount();
    s.trees          = m_tree.TreeCount();
    s.scoredTrees    = m_scores.Size();
    s.tree           = m_tree.Stats();
    s.rules          = m_rules.Stats();
    s.degraded       = s.tree.degraded || s.rules.seq.rejected > 0;
    s.protectionPaused = m_paused;
    s.learningMode   = m_policy.learningMode;
    s.nextEventId    = m_nextEventId;
    s.nextAlertId    = m_nextAlertId;
    if (!m_latencyUs.empty()) {
        std::vector<int64_t> v = m_latencyUs;
        const size_t k = (v.size() * 95) / 100;
        std::nth_element(v.begin(), v.begin() + static_cast<std::ptrdiff_t>(std::min(k, v.size() - 1)), v.end());
        s.tier2P95Ms = static_cast<double>(v[std::min(k, v.size() - 1)]) / 1000.0;
    }
    return s;
}

} // namespace cairn::engine
