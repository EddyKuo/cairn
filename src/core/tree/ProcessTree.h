// src/core/tree/ProcessTree.h                 namespace cairn::tree
// 全機程序森林：掛載、亂序修補（孤兒暫存區 + 延遲掛載）、走訪、淘汰（SDD-02 §4.2.3 / §4.2.4）。
// ★ 位於 src/core，不得 include <windows.h>。
// 執行緒：AnalysisThread 獨佔，故意不做執行緒安全。
//
// 【樹邊界】（對 SDD 的補充，見 AnalysisEngine 報告）：
//   若父程序是 explorer.exe / services.exe / svchost.exe 等「工作階段骨幹」程序，
//   子程序自成一棵樹的根（仍記入父節點 children 供顯示）。否則所有使用者程序都會以
//   explorer.exe 為根而落在同一棵樹，correlate_by: process_tree_root 與回應動作的
//   「整棵樹暫停／終止」會波及整個桌面工作階段。
#pragma once
#include <deque>
#include <functional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "model/NormalizedEvent.h"
#include "tree/ProcessNode.h"

namespace cairn::tree {

struct TreeLimits {
    size_t  maxNodes             = 50'000;
    size_t  maxTrees             = 8'000;
    size_t  maxOrphansPending    = 2'000;
    int64_t orphanGraceMs        = 5'000;
    int64_t retentionAfterExitMs = 1'800'000;   // 30 分鐘
};

struct TreeStats {
    uint64_t orphansReparented = 0;
    uint64_t orphansPromoted   = 0;
    uint64_t orphansDropped    = 0;
    uint64_t nodesReaped       = 0;
    uint64_t provisionalRejected = 0;   // 超過上限而拒收的新暫定節點
    bool     degraded          = false;
};

// 暫定樹被修補時通知呼叫端（ScoreBoard::MergeRoot、SequenceMatcher::Rekey）。
using RerootCallback = std::function<void(const GuidValue& oldRoot, const GuidValue& newRoot)>;

class ProcessTree {
public:
    // interner：解析 image 以判定樹邊界。boundaryImages：小寫的映像檔名（不含路徑），例如 "explorer.exe"。
    ProcessTree(const model::StringInterner& interner, TreeLimits limits = {},
                std::vector<std::string> boundaryImages = DefaultBoundaryImages());

    [[nodiscard]] static std::vector<std::string> DefaultBoundaryImages();

    // EID 1。回傳新節點（或既有 stub 節點補齊後）的指標；超過上限拒收時回傳 nullptr。
    ProcessNode* OnProcessCreate(const model::NormalizedEvent& e, int64_t nowMs, const RerootCallback& onReroot);
    // EID 5
    ProcessNode* OnProcessExit(const GuidValue& guid, int64_t atMs);
    // 非 EID 1 事件：找不到節點時以事件欄位補建 stub（暫定根），使 correlate_by 仍可運作。
    ProcessNode* FindOrCreateStub(const model::NormalizedEvent& e, int64_t nowMs);

    // 啟動快照重建骨架（part2 §2.4.1）。須在開始消費事件前呼叫。
    void Seed(const std::vector<SnapshotProcess>& procs, model::StringInterner& interner, int64_t nowMs);

    [[nodiscard]] ProcessNode*       Find(const GuidValue& guid) noexcept;
    [[nodiscard]] const ProcessNode* Find(const GuidValue& guid) const noexcept;
    [[nodiscard]] GuidValue          RootOf(const GuidValue& guid) const noexcept;   // 找不到回傳 guid 本身

    // 以顯式堆疊前序走訪（根 → 葉），只走 rootGuid 相同的節點（不跨樹邊界）。
    void WalkSubtree(const GuidValue& start, const std::function<void(const ProcessNode&)>& visit) const;
    void WalkSubtreeMut(const GuidValue& start, const std::function<void(ProcessNode&)>& visit);

    // 由 OnTick 每秒呼叫：寬限期已過的暫定節點正式升格為根。
    void ExpireOrphans(int64_t nowMs);

    // 由 OnTick 每 10 秒呼叫：canReclaim(root) 由引擎依 ScoreBoard / 序列狀態判定（§4.2.4 條件 c/d/e）。
    size_t Reap(int64_t nowMs, const std::function<bool(const GuidValue& root)>& canReclaim);

    [[nodiscard]] size_t NodeCount() const noexcept { return m_nodes.size(); }
    [[nodiscard]] size_t TreeCount() const noexcept { return m_roots.size(); }
    [[nodiscard]] const TreeStats& Stats() const noexcept { return m_stats; }

private:
    [[nodiscard]] bool IsBoundaryImage(InternId image, std::string_view fallback) const;
    void AttachToParent(ProcessNode& node, ProcessNode* parent);
    void Reparent(const GuidValue& childGuid, const GuidValue& parentGuid, const RerootCallback& onReroot);
    void RegisterRoot(const GuidValue& g) { m_roots.insert(g); }
    void UnregisterRoot(const GuidValue& g) { m_roots.erase(g); }
    void RemoveNode(const GuidValue& g);
    void FillFromEvent(ProcessNode& n, const model::NormalizedEvent& e);

    struct OrphanTicket {
        GuidValue guid{};
        int64_t   deadlineMs = 0;
    };

    const model::StringInterner& m_interner;
    TreeLimits m_limits;
    std::unordered_set<std::string> m_boundary;   // 小寫映像檔名

    std::unordered_map<GuidValue, ProcessNode, model::GuidHash>            m_nodes;
    std::unordered_map<GuidValue, std::vector<GuidValue>, model::GuidHash> m_orphansByParent;
    std::deque<OrphanTicket>                                               m_orphanDeadlines;
    std::unordered_set<GuidValue, model::GuidHash>                         m_roots;
    size_t    m_pendingOrphans = 0;
    TreeStats m_stats;
};

// 小寫化後取映像檔名（最後一個 '\\' 或 '/' 之後）。
[[nodiscard]] std::string_view BaseName(std::string_view path) noexcept;

} // namespace cairn::tree
