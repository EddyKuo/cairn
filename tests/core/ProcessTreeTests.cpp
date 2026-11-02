// ProcessTreeTests —— 掛載、亂序修補、PID 重用、樹邊界、深樹、孤兒逾時、淘汰（SDD-02 §4.2）
#include <gtest/gtest.h>

#include <vector>

#include "TestHelpers.h"
#include "tree/ProcessTree.h"

using namespace cairn;
using cairn::test::EventFactory;
using cairn::test::G;

class ProcessTreeTest : public ::testing::Test {
protected:
    model::StringInterner in;
    EventFactory          f{in};
    tree::ProcessTree     t{in};
    std::vector<std::pair<model::GuidValue, model::GuidValue>> reroots;
    tree::RerootCallback  cb = [this](const model::GuidValue& o, const model::GuidValue& n) { reroots.emplace_back(o, n); };
};

TEST_F(ProcessTreeTest, ChildInheritsRootFromParent)
{
    t.OnProcessCreate(f.ProcessCreate(1, 0, "C:\\Program Files\\Office\\WINWORD.EXE", ""), f.Now(), cb);
    auto* c = t.OnProcessCreate(f.ProcessCreate(2, 1, "C:\\Windows\\System32\\powershell.exe", "winword.exe"), f.Now(), cb);
    ASSERT_NE(c, nullptr);
    EXPECT_EQ(c->rootGuid, G(1));
    EXPECT_EQ(c->depth, 1);
    EXPECT_EQ(t.RootOf(G(2)), G(1));
    EXPECT_TRUE(reroots.empty());
}

TEST_F(ProcessTreeTest, BoundaryParentStartsNewTree)
{
    t.OnProcessCreate(f.ProcessCreate(1, 0, "C:\\Windows\\explorer.exe", ""), f.Now(), cb);
    auto* w = t.OnProcessCreate(f.ProcessCreate(2, 1, "C:\\Office\\winword.exe", "C:\\Windows\\explorer.exe"), f.Now(), cb);
    auto* n = t.OnProcessCreate(f.ProcessCreate(3, 1, "C:\\Windows\\notepad.exe", "C:\\Windows\\explorer.exe"), f.Now(), cb);
    ASSERT_TRUE(w && n);
    EXPECT_EQ(w->rootGuid, G(2)) << "explorer 的子程序自成一棵樹";
    EXPECT_EQ(n->rootGuid, G(3));
    EXPECT_NE(w->rootGuid, n->rootGuid) << "不同使用者行為不得落在同一棵樹";
    const auto* ex = t.Find(G(1));
    ASSERT_NE(ex, nullptr);
    EXPECT_EQ(ex->children.size(), 2u) << "仍記入父節點 children 供顯示";
}

TEST_F(ProcessTreeTest, OrphanReparentedWhenParentArrivesLate)
{
    // 子程序的 EID 1 先到（跨通道亂序）
    auto* c = t.OnProcessCreate(f.ProcessCreate(2, 1, "C:\\x\\child.exe", "C:\\x\\parent.exe"), f.Now(), cb);
    ASSERT_NE(c, nullptr);
    EXPECT_EQ(c->rootGuid, G(2)) << "暫定自成一棵樹";
    EXPECT_TRUE(tree::HasFlag(c->flags, tree::NodeFlags::Provisional));
    auto* gc = t.OnProcessCreate(f.ProcessCreate(3, 2, "C:\\x\\grandchild.exe", "C:\\x\\child.exe"), f.Now(), cb);
    ASSERT_NE(gc, nullptr);
    EXPECT_EQ(gc->rootGuid, G(2));

    t.OnProcessCreate(f.ProcessCreate(1, 0, "C:\\x\\parent.exe", ""), f.Now(), cb);
    EXPECT_EQ(t.Find(G(2))->rootGuid, G(1));
    EXPECT_EQ(t.Find(G(3))->rootGuid, G(1)) << "整棵暫定子樹改根";
    EXPECT_EQ(t.Find(G(3))->depth, 2);
    ASSERT_EQ(reroots.size(), 1u);
    EXPECT_EQ(reroots[0].first, G(2));
    EXPECT_EQ(reroots[0].second, G(1));
    EXPECT_EQ(t.Stats().orphansReparented, 1u);
}

TEST_F(ProcessTreeTest, OrphanPromotedAfterGrace)
{
    t.OnProcessCreate(f.ProcessCreate(2, 1, "C:\\x\\child.exe", "C:\\x\\gone.exe"), f.Now(), cb);
    t.ExpireOrphans(f.Now() + 4'999);
    EXPECT_TRUE(tree::HasFlag(t.Find(G(2))->flags, tree::NodeFlags::Provisional));
    t.ExpireOrphans(f.Now() + 5'000);
    EXPECT_FALSE(tree::HasFlag(t.Find(G(2))->flags, tree::NodeFlags::Provisional));
    EXPECT_EQ(t.Stats().orphansPromoted, 1u);
}

TEST_F(ProcessTreeTest, PidReuseDoesNotMergeProcesses)
{
    auto e1 = f.ProcessCreate(10, 0, "C:\\evil\\malware.exe", "");
    e1.pid  = 4242;
    t.OnProcessCreate(e1, f.Now(), cb);
    t.OnProcessExit(G(10), f.Now());
    auto e2 = f.ProcessCreate(11, 0, "C:\\Windows\\notepad.exe", "");
    e2.pid  = 4242;   // 同一個 PID 被無辜程序重用
    t.OnProcessCreate(e2, f.Now(), cb);
    ASSERT_TRUE(t.Find(G(10)) && t.Find(G(11)));
    EXPECT_NE(t.Find(G(10))->rootGuid, t.Find(G(11))->rootGuid);
    EXPECT_TRUE(tree::HasFlag(t.Find(G(10))->flags, tree::NodeFlags::Exited));
    EXPECT_FALSE(tree::HasFlag(t.Find(G(11))->flags, tree::NodeFlags::Exited));
}

TEST_F(ProcessTreeTest, DepthCappedAt64AndWalkIsIterative)
{
    t.OnProcessCreate(f.ProcessCreate(1, 0, "C:\\x\\p0.exe", ""), f.Now(), cb);
    for (uint32_t i = 2; i <= 200; ++i)
        t.OnProcessCreate(f.ProcessCreate(i, i - 1, "C:\\x\\p.exe", "C:\\x\\p.exe"), f.Now(), cb);
    EXPECT_EQ(t.Find(G(200))->depth, tree::kMaxDepth);
    size_t visited = 0;
    t.WalkSubtree(G(1), [&](const tree::ProcessNode&) { ++visited; });
    EXPECT_EQ(visited, 200u);
}

TEST_F(ProcessTreeTest, WalkIsPreorderRootToLeaf)
{
    t.OnProcessCreate(f.ProcessCreate(1, 0, "C:\\x\\a.exe", ""), f.Now(), cb);
    t.OnProcessCreate(f.ProcessCreate(2, 1, "C:\\x\\b.exe", "a.exe"), f.Now(), cb);
    t.OnProcessCreate(f.ProcessCreate(3, 2, "C:\\x\\c.exe", "b.exe"), f.Now(), cb);
    t.OnProcessCreate(f.ProcessCreate(4, 1, "C:\\x\\d.exe", "a.exe"), f.Now(), cb);
    std::vector<model::GuidValue> order;
    t.WalkSubtree(G(1), [&](const tree::ProcessNode& n) { order.push_back(n.guid); });
    ASSERT_EQ(order.size(), 4u);
    EXPECT_EQ(order[0], G(1));
    EXPECT_EQ(order[1], G(2));
    EXPECT_EQ(order[2], G(3));
    EXPECT_EQ(order[3], G(4));
}

TEST_F(ProcessTreeTest, StubCreatedForUnknownProcessAndCompletedByLateCreate)
{
    auto rt = f.RemoteThread(7, "C:\\x\\inj.exe", 8, "C:\\Windows\\notepad.exe");
    auto* stub = t.FindOrCreateStub(rt, f.Now());
    ASSERT_NE(stub, nullptr);
    EXPECT_TRUE(tree::HasFlag(stub->flags, tree::NodeFlags::Stub));
    auto* full = t.OnProcessCreate(f.ProcessCreate(7, 0, "C:\\x\\inj.exe", "", "inj.exe --go"), f.Now(), cb);
    EXPECT_EQ(full, stub) << "既有 stub 節點被補齊，而非重複建立";
    EXPECT_FALSE(tree::HasFlag(full->flags, tree::NodeFlags::Stub));
    EXPECT_EQ(full->commandLine, "inj.exe --go");
}

TEST_F(ProcessTreeTest, ReapOnlyExitedIdleTreesThatEngineAllows)
{
    t.OnProcessCreate(f.ProcessCreate(1, 0, "C:\\x\\a.exe", ""), f.Now(), cb);
    t.OnProcessCreate(f.ProcessCreate(2, 1, "C:\\x\\b.exe", "a.exe"), f.Now(), cb);
    t.OnProcessCreate(f.ProcessCreate(5, 0, "C:\\x\\alive.exe", ""), f.Now(), cb);
    t.OnProcessExit(G(1), f.Now());
    t.OnProcessExit(G(2), f.Now());

    const int64_t later = f.Now() + 1'800'001;
    EXPECT_EQ(t.Reap(later, [](const model::GuidValue&) { return false; }), 0u) << "引擎不允許（如分數 >= 40）則不回收";
    EXPECT_EQ(t.Reap(f.Now() + 1'000, [](const model::GuidValue&) { return true; }), 0u) << "保留期內不回收";
    EXPECT_EQ(t.Reap(later, [](const model::GuidValue&) { return true; }), 2u);
    EXPECT_EQ(t.Find(G(1)), nullptr);
    EXPECT_NE(t.Find(G(5)), nullptr) << "仍在執行的樹不回收";
}

TEST_F(ProcessTreeTest, SeedFromSnapshotBuildsSkeleton)
{
    std::vector<tree::SnapshotProcess> snap{
        {G(3), G(2), 30, 20, "C:\\Office\\winword.exe", 100, true},   // 子先於父（快照順序不保證）
        {G(2), G(1), 20, 10, "C:\\Windows\\explorer.exe", 50, true},
        {G(1), {}, 10, 0, "C:\\Windows\\System32\\userinit.exe", 10, true},
        {G(4), G(3), 40, 30, "C:\\Windows\\System32\\cmd.exe", 120, true},
    };
    t.Seed(snap, in, f.Now());
    EXPECT_EQ(t.NodeCount(), 4u);
    EXPECT_EQ(t.Find(G(3))->rootGuid, G(3)) << "explorer 為邊界，winword 自成一棵樹";
    EXPECT_EQ(t.Find(G(4))->rootGuid, G(3));
    EXPECT_EQ(t.Find(G(4))->depth, 1);
    EXPECT_TRUE(tree::HasFlag(t.Find(G(4))->flags, tree::NodeFlags::Synthetic));
}
