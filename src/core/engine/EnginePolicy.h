// src/core/engine/EnginePolicy.h              namespace cairn::engine
// AnalysisEngine 的政策設定。由 svc 讀取 config/policy.default.json 後填入（core 不解析 JSON）。
// JSON 欄位名（snake_case）見各欄位註解；整合層需逐一對應。
#pragma once
#include <cstdint>
#include <string>
#include <vector>

#include "tree/ProcessTree.h"

namespace cairn::engine {

struct EnginePolicy {
    // "auto_response_enabled"：總開關。false 時只告警不自動回應。
    bool autoResponseEnabled = true;

    // "blocked_default_actions"：分數 >= 95（Blocked）時，除規則指定動作外，另加
    // terminate_process_tree + quarantine_file + firewall_block（part2 §2.4.3 閾值表）。
    bool blockedDefaultActions = true;

    // "learning_mode"：學習期（安裝後 3 天）——照常計分與告警，但不執行任何自動回應（part3 §3.10.1）。
    // 由 svc 依安裝時間與 learning.finish 設定；引擎只看這個旗標。
    bool learningMode = false;

    // "tree.orphan_grace_ms" / "tree.retention_after_exit_ms" / "tree.max_nodes" / "tree.max_trees" /
    // "tree.max_orphans_pending"
    tree::TreeLimits treeLimits{};

    // "tree.resolved_retention_ms"：Resolved / Excluded 的樹於判定後保留多久才可被 Reaper 回收
    int64_t resolvedRetentionMs = 3'600'000;

    // "tree.boundary_images"：工作階段骨幹程序（小寫檔名），其子程序各自成樹
    std::vector<std::string> treeBoundaryImages = tree::ProcessTree::DefaultBoundaryImages();

    // "response.never_target_images"：自動回應永不作用的程序（小寫檔名）。
    // 殺掉這些程序會讓系統藍屏或 Cairn 自殺，屬「回應造成的損害大於攻擊」。
    std::vector<std::string> neverTargetImages = {
        "system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe",
        "svchost.exe", "explorer.exe", "dwm.exe", "fontdrvhost.exe", "msmpeng.exe",
        "cairnagent.exe", "cairnconsole.exe", "llama-server.exe", "sysmon.exe", "sysmon64.exe"};

    // "alert.max_evidence_events"：單一告警附帶的 alert_events 上限
    size_t maxEvidenceEventsPerAlert = 64;

    // "sequence.expire_slack_ms"：以牆鐘清理部分比對時的寬限（事件時戳可能落後牆鐘）
    int64_t sequenceExpireSlackMs = 10'000;
};

} // namespace cairn::engine
