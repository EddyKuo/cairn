// tests/svc/AuditChainTests.cpp
// audit_log 雜湊鏈：寫入、驗證、竄改偵測、刪列缺口偵測、append-only 觸發器（SDD-03 §8.6）。
#include <gtest/gtest.h>

#include "store/AuditChain.h"
#include "store/Sha256.h"
#include "store/SqliteDb.h"
#include "StoreTestUtil.h"

using namespace cairn;
using namespace cairn::store;
using namespace cairn::testutil;

namespace {

model::AuditRow Row(int i)
{
    model::AuditRow r;
    r.ts         = 1'787'000'000'000 + i;
    r.actor      = "analyst";
    r.action     = i % 2 ? "suspend_process" : "exclusion_add";
    r.alertId    = i;
    r.target     = "pid:" + std::to_string(1000 + i);
    r.paramsJson = R"({"reason":"測試"})";
    r.result     = "ok";
    return r;
}

std::unique_ptr<SqliteDb> OpenWriter(const TempDir& d)
{
    auto db = SqliteDb::Open(d.Db(), ConnRole::Writer);
    EXPECT_TRUE(db) << (db ? "" : db.GetError().ToString());
    return std::move(db).Value();
}

void AppendN(SqliteDb& db, AuditChain& chain, int n)
{
    for (int i = 1; i <= n; ++i) {
        Transaction tx{db};
        ASSERT_TRUE(tx.Begin());
        auto id = chain.Append(Row(i));
        ASSERT_TRUE(id) << id.GetError().ToString();
        ASSERT_TRUE(tx.Commit());
    }
}

} // namespace

TEST(Sha256, KnownVectors)
{
    EXPECT_EQ(Sha256Hex(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    EXPECT_EQ(Sha256Hex("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST(AuditChain, CanonicalJsonIsStable)
{
    AuditFields f;
    f.ts = 1;
    f.actor = "system";
    f.action = "x";
    f.eventKind = "k";
    f.params = "{}";
    f.result = "ok";
    f.prevHash = std::string(kGenesisHash);
    // 期望值先放進區域變數：MSVC 傳統前處理器無法正確切分巨集引數中的 raw string（C2017）
    const std::string expected =
        R"({"ts":1,"actor":"system","action":"x","event_kind":"k","alert_id":null,"target":null,"params":"{}","result":"ok","error":null,"prev_hash":")" +
        std::string(kGenesisHash) + "\"}";
    EXPECT_EQ(CanonicalAuditJson(f), expected);
    EXPECT_EQ(ComputeAuditRowHash(f), ComputeAuditRowHash(f));
}

TEST(AuditChain, AppendThenVerifyValid)
{
    TempDir dir;
    auto db = OpenWriter(dir);
    AuditChain chain{*db};
    ASSERT_TRUE(chain.Load());
    EXPECT_EQ(chain.LastHash(), kGenesisHash);
    AppendN(*db, chain, 5);
    auto rep = VerifyAuditChain(*db);
    ASSERT_TRUE(rep);
    EXPECT_TRUE(rep.Value().valid) << rep.Value().detail;
    EXPECT_EQ(rep.Value().verifiedCount, 5);
    // 部分區段驗證（從中間開始，以前一列的 hash 為起點）
    auto part = VerifyAuditChain(*db, 3, 0);
    ASSERT_TRUE(part);
    EXPECT_TRUE(part.Value().valid);
    EXPECT_EQ(part.Value().verifiedCount, 3);
}

TEST(AuditChain, ChainContinuesAcrossRestart)
{
    TempDir dir;
    {
        auto db = OpenWriter(dir);
        AuditChain chain{*db};
        ASSERT_TRUE(chain.Load());
        AppendN(*db, chain, 2);
    }
    auto db = OpenWriter(dir);
    AuditChain chain{*db};
    ASSERT_TRUE(chain.Load());
    EXPECT_NE(chain.LastHash(), kGenesisHash);
    AppendN(*db, chain, 2);
    auto rep = VerifyAuditChain(*db);
    ASSERT_TRUE(rep);
    EXPECT_TRUE(rep.Value().valid) << rep.Value().detail;
    EXPECT_EQ(rep.Value().verifiedCount, 4);
}

TEST(AuditChain, AppendOnlyTriggersRejectUpdateAndDelete)
{
    TempDir dir;
    auto db = OpenWriter(dir);
    AuditChain chain{*db};
    ASSERT_TRUE(chain.Load());
    AppendN(*db, chain, 1);
    EXPECT_FALSE(db->Exec("UPDATE audit_log SET result='failed';"));
    EXPECT_FALSE(db->Exec("DELETE FROM audit_log;"));
}

TEST(AuditChain, DetectsTamperedRow)
{
    TempDir dir;
    auto db = OpenWriter(dir);
    AuditChain chain{*db};
    ASSERT_TRUE(chain.Load());
    AppendN(*db, chain, 4);
    // 觸發器防的是程式缺陷不是管理員：攻擊者可以 DROP TRIGGER。鏈必須仍能偵測。
    ASSERT_TRUE(db->Exec("DROP TRIGGER trg_audit_no_update;"));
    ASSERT_TRUE(db->Exec("UPDATE audit_log SET result='failed' WHERE id=3;"));
    auto rep = VerifyAuditChain(*db);
    ASSERT_TRUE(rep);
    EXPECT_FALSE(rep.Value().valid);
    EXPECT_EQ(rep.Value().firstBrokenId, 3);
}

TEST(AuditChain, DetectsDeletedRowAsGap)
{
    TempDir dir;
    auto db = OpenWriter(dir);
    AuditChain chain{*db};
    ASSERT_TRUE(chain.Load());
    AppendN(*db, chain, 4);
    ASSERT_TRUE(db->Exec("DROP TRIGGER trg_audit_no_delete;"));
    ASSERT_TRUE(db->Exec("DELETE FROM audit_log WHERE id=2;"));
    auto rep = VerifyAuditChain(*db);
    ASSERT_TRUE(rep);
    EXPECT_FALSE(rep.Value().valid);
    EXPECT_EQ(rep.Value().firstBrokenId, 2);
    EXPECT_NE(rep.Value().detail.find("gap"), std::string::npos);
}

TEST(AuditChain, RollbackKeepsChainTailConsistent)
{
    TempDir dir;
    auto db = OpenWriter(dir);
    AuditChain chain{*db};
    ASSERT_TRUE(chain.Load());
    AppendN(*db, chain, 1);
    {
        Transaction tx{*db};
        ASSERT_TRUE(tx.Begin());
        ASSERT_TRUE(chain.Append(Row(2)));
        // 不 Commit → 解構時 ROLLBACK；鏈尾必須能還原
    }
    ASSERT_TRUE(chain.Reload());
    AppendN(*db, chain, 1);
    auto rep = VerifyAuditChain(*db);
    ASSERT_TRUE(rep);
    EXPECT_TRUE(rep.Value().valid) << rep.Value().detail;   // 回滾的交易不消耗 AUTOINCREMENT 序號
}

TEST(AuditChain, DerivesEventKind)
{
    model::AuditRow r;
    r.action = "quarantine_file";
    EXPECT_EQ(DeriveEventKind(r), "action_completed");
    r.action = "firewall_block_revert";
    EXPECT_EQ(DeriveEventKind(r), "action_reverted");
    r.paramsJson = R"({"event_kind":"verdict_set"})";
    EXPECT_EQ(DeriveEventKind(r), "verdict_set");
}
