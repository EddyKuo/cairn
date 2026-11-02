#include "tree/ProcessTree.h"

#include "base/IClock.h"

#include <algorithm>

namespace cairn::tree {

std::string_view BaseName(std::string_view path) noexcept
{
    const auto pos = path.find_last_of("\\/");
    return pos == std::string_view::npos ? path : path.substr(pos + 1);
}

std::vector<std::string> ProcessTree::DefaultBoundaryImages()
{
    // 工作階段骨幹：其子程序各自代表一個獨立的「使用者行為」，不應被歸到同一棵樹。
    return {"system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
            "svchost.exe", "userinit.exe", "explorer.exe", "sihost.exe", "taskhostw.exe",
            "runtimebroker.exe", "dllhost.exe", "wmiprvse.exe", "lsass.exe"};
}

ProcessTree::ProcessTree(const model::StringInterner& interner, TreeLimits limits,
                         std::vector<std::string> boundaryImages)
    : m_interner(interner), m_limits(limits)
{
    for (auto& b : boundaryImages) m_boundary.insert(model::ToLowerAscii(b));
}

bool ProcessTree::IsBoundaryImage(InternId image, std::string_view fallback) const
{
    std::string_view path = image != kInvalidInternId ? m_interner.Resolve(image) : fallback;
    if (path.empty()) return false;
    return m_boundary.count(model::ToLowerAscii(BaseName(path))) != 0;
}

void ProcessTree::FillFromEvent(ProcessNode& n, const model::NormalizedEvent& e)
{
    n.guid = e.processGuid;
    if (!e.parentProcessGuid.IsNull()) n.parentGuid = e.parentProcessGuid;
    if (e.pid) n.pid = e.pid;
    if (e.parentPid) n.parentPid = e.parentPid;
    if (e.image != kInvalidInternId) n.image = e.image;
    else if (e.imageFallback) n.imageFallback = model::ToLowerAscii(*e.imageFallback);
    if (e.signer != kInvalidInternId) n.signer = e.signer;
    if (e.user != kInvalidInternId) n.user = e.user;
    if (!e.commandLine.empty()) n.commandLine = e.commandLine.substr(0, kMaxCommandLineKept);
    if (!e.sha256.empty()) n.sha256 = e.sha256;
    if (!e.integrityLevel.empty()) n.integrityLevel = e.integrityLevel;
    if (e.signatureValid) {
        n.signatureValid = e.signatureValid;
        if (*e.signatureValid) SetFlag(n.flags, NodeFlags::SignedValid);
    }
    if (e.integrityLevel == "High" || e.integrityLevel == "System") SetFlag(n.flags, NodeFlags::Elevated);
    if (IsBoundaryImage(n.image, n.imageFallback)) SetFlag(n.flags, NodeFlags::Boundary);
}

void ProcessTree::AttachToParent(ProcessNode& node, ProcessNode* parent)
{
    if (!parent) return;
    if (std::find(parent->children.begin(), parent->children.end(), node.guid) == parent->children.end())
        parent->children.push_back(node.guid);
    ClearFlag(node.flags, NodeFlags::Provisional);
    if (HasFlag(parent->flags, NodeFlags::Boundary)) {
        node.rootGuid = node.guid;   // 跨邊界：自成一棵樹
        node.depth    = 0;
        RegisterRoot(node.guid);
    } else {
        node.rootGuid = parent->rootGuid;
        node.depth    = static_cast<uint16_t>(std::min<int>(parent->depth + 1, kMaxDepth));
        UnregisterRoot(node.guid);
    }
}

ProcessNode* ProcessTree::OnProcessCreate(const model::NormalizedEvent& e, int64_t nowMs,
                                          const RerootCallback& onReroot)
{
    if (e.processGuid.IsNull()) return nullptr;

    ProcessNode* parent = e.parentProcessGuid.IsNull() ? nullptr : Find(e.parentProcessGuid);

    auto it = m_nodes.find(e.processGuid);
    if (it != m_nodes.end()) {
        ProcessNode& existing = it->second;
        if (!HasFlag(existing.flags, NodeFlags::Stub)) return &existing;   // 重複的 EID 1
        // stub 補齊：EID 1 晚於其他事件抵達
        FillFromEvent(existing, e);
        ClearFlag(existing.flags, NodeFlags::Stub);
        existing.startMs = ToUnixMs(e.time);
        const bool attached = parent && std::find(parent->children.begin(), parent->children.end(),
                                                  existing.guid) != parent->children.end();
        if (parent && !attached && existing.rootGuid == existing.guid) {
            // stub 先前不知道父程序（非 EID 1 事件沒有 ParentProcessGuid）：
            // 以 Reparent 處理，確保既有分數與序列狀態跟著搬
            if (HasFlag(existing.flags, NodeFlags::Provisional)) {
                if (auto it2 = m_orphansByParent.find(existing.parentGuid); it2 != m_orphansByParent.end()) {
                    auto& v = it2->second;
                    v.erase(std::remove(v.begin(), v.end(), existing.guid), v.end());
                    if (v.empty()) m_orphansByParent.erase(it2);
                    if (m_pendingOrphans) --m_pendingOrphans;
                }
            }
            Reparent(existing.guid, parent->guid, onReroot);
        }
        return &existing;
    }

    if (!parent && m_nodes.size() >= m_limits.maxNodes) {
        ++m_stats.provisionalRejected;
        m_stats.degraded = true;
        return nullptr;
    }

    ProcessNode node{};
    FillFromEvent(node, e);
    node.startMs     = ToUnixMs(e.time);
    node.lastEventMs = nowMs;
    node.rootGuid    = node.guid;

    auto [nit, ok] = m_nodes.emplace(node.guid, std::move(node));
    ProcessNode& n = nit->second;
    (void)ok;

    if (parent) {
        AttachToParent(n, parent);
    } else {
        SetFlag(n.flags, NodeFlags::Provisional);
        RegisterRoot(n.guid);
        if (!e.parentProcessGuid.IsNull()) {
            if (m_pendingOrphans >= m_limits.maxOrphansPending) {
                ++m_stats.orphansDropped;   // 不再等父節點：直接當根
                ClearFlag(n.flags, NodeFlags::Provisional);
            } else {
                m_orphansByParent[e.parentProcessGuid].push_back(n.guid);
                m_orphanDeadlines.push_back(OrphanTicket{n.guid, nowMs + m_limits.orphanGraceMs});
                ++m_pendingOrphans;
            }
        } else {
            ClearFlag(n.flags, NodeFlags::Provisional);
        }
    }

    // 反向修補：本節點可能正是別人在等的父親
    if (auto pend = m_orphansByParent.find(n.guid); pend != m_orphansByParent.end()) {
        std::vector<GuidValue> kids = std::move(pend->second);
        m_orphansByParent.erase(pend);
        for (const auto& kid : kids) {
            if (m_pendingOrphans) --m_pendingOrphans;
            Reparent(kid, n.guid, onReroot);
        }
    }
    return &m_nodes.at(e.processGuid);
}

void ProcessTree::Reparent(const GuidValue& childGuid, const GuidValue& parentGuid, const RerootCallback& onReroot)
{
    ProcessNode* child  = Find(childGuid);
    ProcessNode* parent = Find(parentGuid);
    if (!child || !parent) return;

    const GuidValue oldRoot = child->rootGuid;
    AttachToParent(*child, parent);
    ++m_stats.orphansReparented;
    if (child->rootGuid == oldRoot) return;   // 跨邊界：仍是自己的根，無需改鍵

    const GuidValue newRoot = child->rootGuid;
    // 整棵暫定子樹改根（顯式堆疊，不遞迴）
    std::vector<GuidValue> stack{childGuid};
    while (!stack.empty()) {
        const GuidValue g = stack.back();
        stack.pop_back();
        ProcessNode* n = Find(g);
        if (!n) continue;
        for (const auto& c : n->children) {
            ProcessNode* cn = Find(c);
            if (cn && cn->rootGuid == oldRoot) {
                cn->rootGuid = newRoot;
                cn->depth    = static_cast<uint16_t>(std::min<int>(n->depth + 1, kMaxDepth));
                stack.push_back(c);
            }
        }
    }
    UnregisterRoot(oldRoot);
    if (onReroot) onReroot(oldRoot, newRoot);
}

ProcessNode* ProcessTree::OnProcessExit(const GuidValue& guid, int64_t atMs)
{
    ProcessNode* n = Find(guid);
    if (!n) return nullptr;
    n->endMs = atMs;
    SetFlag(n->flags, NodeFlags::Exited);
    return n;
}

ProcessNode* ProcessTree::FindOrCreateStub(const model::NormalizedEvent& e, int64_t nowMs)
{
    if (e.processGuid.IsNull()) return nullptr;
    if (ProcessNode* n = Find(e.processGuid)) return n;
    if (m_nodes.size() >= m_limits.maxNodes) {
        ++m_stats.provisionalRejected;
        m_stats.degraded = true;
        return nullptr;
    }

    ProcessNode node{};
    FillFromEvent(node, e);
    node.startMs     = ToUnixMs(e.time);
    node.lastEventMs = nowMs;
    node.rootGuid    = node.guid;
    SetFlag(node.flags, NodeFlags::Stub);
    auto [it, ok] = m_nodes.emplace(node.guid, std::move(node));
    (void)ok;
    ProcessNode& n = it->second;

    ProcessNode* parent = n.parentGuid.IsNull() ? nullptr : Find(n.parentGuid);
    if (parent) {
        AttachToParent(n, parent);
    } else {
        RegisterRoot(n.guid);
        if (!n.parentGuid.IsNull() && m_pendingOrphans < m_limits.maxOrphansPending) {
            SetFlag(n.flags, NodeFlags::Provisional);
            m_orphansByParent[n.parentGuid].push_back(n.guid);
            m_orphanDeadlines.push_back(OrphanTicket{n.guid, nowMs + m_limits.orphanGraceMs});
            ++m_pendingOrphans;
        }
    }
    return &n;
}

void ProcessTree::Seed(const std::vector<SnapshotProcess>& procs, model::StringInterner& interner, int64_t nowMs)
{
    for (const auto& p : procs) {
        if (p.guid.IsNull() || m_nodes.count(p.guid)) continue;
        ProcessNode n{};
        n.guid       = p.guid;
        n.parentGuid = p.parentGuid;
        n.rootGuid   = p.guid;
        n.pid        = p.pid;
        n.parentPid  = p.parentPid;
        n.image      = interner.InternLower(p.image);
        if (n.image == kInvalidInternId) n.imageFallback = model::ToLowerAscii(p.image);
        n.startMs     = p.startMs;
        n.lastEventMs = nowMs;
        if (p.synthetic) SetFlag(n.flags, NodeFlags::Synthetic);
        if (IsBoundaryImage(n.image, n.imageFallback)) SetFlag(n.flags, NodeFlags::Boundary);
        m_nodes.emplace(n.guid, std::move(n));
    }
    // 第二輪：掛載（依 depth 由淺到深難以預知，故先全部當根，再依父子關係掛上並改根）
    for (const auto& p : procs) {
        ProcessNode* n = Find(p.guid);
        if (!n) continue;
        ProcessNode* parent = p.parentGuid.IsNull() ? nullptr : Find(p.parentGuid);
        if (parent && parent != n) AttachToParent(*n, parent);
        else RegisterRoot(n->guid);
    }
    // 第三輪：根據最終的父子關係重新傳播 rootGuid / depth（快照順序不保證父先於子）
    std::vector<GuidValue> roots(m_roots.begin(), m_roots.end());
    for (const auto& r : roots) {
        std::vector<GuidValue> stack{r};
        while (!stack.empty()) {
            const GuidValue g = stack.back();
            stack.pop_back();
            ProcessNode* n = Find(g);
            if (!n) continue;
            for (const auto& c : n->children) {
                ProcessNode* cn = Find(c);
                if (!cn || cn->guid == r) continue;
                if (HasFlag(n->flags, NodeFlags::Boundary)) continue;   // 子程序已自成一棵樹
                cn->rootGuid = n->rootGuid;
                cn->depth    = static_cast<uint16_t>(std::min<int>(n->depth + 1, kMaxDepth));
                UnregisterRoot(cn->guid);
                stack.push_back(c);
            }
        }
    }
}

ProcessNode* ProcessTree::Find(const GuidValue& guid) noexcept
{
    auto it = m_nodes.find(guid);
    return it == m_nodes.end() ? nullptr : &it->second;
}

const ProcessNode* ProcessTree::Find(const GuidValue& guid) const noexcept
{
    auto it = m_nodes.find(guid);
    return it == m_nodes.end() ? nullptr : &it->second;
}

GuidValue ProcessTree::RootOf(const GuidValue& guid) const noexcept
{
    const ProcessNode* n = Find(guid);
    return n ? n->rootGuid : guid;
}

void ProcessTree::WalkSubtree(const GuidValue& start, const std::function<void(const ProcessNode&)>& visit) const
{
    const ProcessNode* s = Find(start);
    if (!s) return;
    const GuidValue root = s->rootGuid;
    // 前序（根 → 葉）：以堆疊實作，子節點反向推入以維持 children 的原始順序
    std::vector<const ProcessNode*> stack{s};
    size_t guard = 0;
    while (!stack.empty() && guard++ < m_nodes.size() + 1) {
        const ProcessNode* n = stack.back();
        stack.pop_back();
        visit(*n);
        for (auto it = n->children.rbegin(); it != n->children.rend(); ++it) {
            const ProcessNode* c = Find(*it);
            if (c && c->rootGuid == root && c->guid != root) stack.push_back(c);
        }
    }
}

void ProcessTree::WalkSubtreeMut(const GuidValue& start, const std::function<void(ProcessNode&)>& visit)
{
    ProcessNode* s = Find(start);
    if (!s) return;
    const GuidValue root = s->rootGuid;
    std::vector<ProcessNode*> stack{s};
    size_t guard = 0;
    while (!stack.empty() && guard++ < m_nodes.size() + 1) {
        ProcessNode* n = stack.back();
        stack.pop_back();
        visit(*n);
        for (auto it = n->children.rbegin(); it != n->children.rend(); ++it) {
            ProcessNode* c = Find(*it);
            if (c && c->rootGuid == root && c->guid != root) stack.push_back(c);
        }
    }
}

void ProcessTree::ExpireOrphans(int64_t nowMs)
{
    while (!m_orphanDeadlines.empty() && m_orphanDeadlines.front().deadlineMs <= nowMs) {
        const OrphanTicket t = m_orphanDeadlines.front();
        m_orphanDeadlines.pop_front();
        ProcessNode* n = Find(t.guid);
        if (!n || !HasFlag(n->flags, NodeFlags::Provisional)) continue;
        ClearFlag(n->flags, NodeFlags::Provisional);   // 正式承認它是根
        if (auto it = m_orphansByParent.find(n->parentGuid); it != m_orphansByParent.end()) {
            auto& v = it->second;
            v.erase(std::remove(v.begin(), v.end(), t.guid), v.end());
            if (v.empty()) m_orphansByParent.erase(it);
        }
        if (m_pendingOrphans) --m_pendingOrphans;
        ++m_stats.orphansPromoted;
    }
}

void ProcessTree::RemoveNode(const GuidValue& g)
{
    auto it = m_nodes.find(g);
    if (it == m_nodes.end()) return;
    if (ProcessNode* p = Find(it->second.parentGuid)) {
        auto& ch = p->children;
        ch.erase(std::remove(ch.begin(), ch.end(), g), ch.end());
    }
    UnregisterRoot(g);
    m_nodes.erase(it);
    ++m_stats.nodesReaped;
}

size_t ProcessTree::Reap(int64_t nowMs, const std::function<bool(const GuidValue& root)>& canReclaim)
{
    struct Candidate {
        GuidValue root{};
        int64_t   lastEventMs = 0;
        std::vector<GuidValue> members;
    };
    std::vector<Candidate> cands;
    const std::vector<GuidValue> roots(m_roots.begin(), m_roots.end());
    for (const auto& r : roots) {
        Candidate c{r, 0, {}};
        bool allExited = true;
        WalkSubtree(r, [&](const ProcessNode& n) {
            c.members.push_back(n.guid);
            c.lastEventMs = std::max({c.lastEventMs, n.lastEventMs, n.endMs});
            if (!HasFlag(n.flags, NodeFlags::Exited)) allExited = false;
        });
        if (c.members.empty() || !allExited) continue;                        // (a)
        if (nowMs - c.lastEventMs <= m_limits.retentionAfterExitMs) continue; // (b)
        if (canReclaim && !canReclaim(r)) continue;                            // (c)(d)(e)
        cands.push_back(std::move(c));
    }
    std::sort(cands.begin(), cands.end(),
              [](const Candidate& a, const Candidate& b) { return a.lastEventMs < b.lastEventMs; });

    size_t removed = 0;
    for (const auto& c : cands) {
        for (const auto& g : c.members) {
            RemoveNode(g);
            ++removed;
        }
    }
    m_stats.degraded = m_nodes.size() > m_limits.maxNodes || m_roots.size() > m_limits.maxTrees;
    return removed;
}

} // namespace cairn::tree
