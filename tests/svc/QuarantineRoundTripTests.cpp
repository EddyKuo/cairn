// tests/svc/QuarantineRoundTripTests.cpp
// W3 出場條件 1：隔離 → 還原 往返無損（雜湊必須一致）。
//   ctest --preset x64-debug -R QuarantineRoundTrip --output-on-failure
// 不需管理員：以暫存目錄當隔離區且不套用僅 SY/BA 的 ACL（applyVaultAcl=false）。
#include <gtest/gtest.h>

#include <windows.h>

#include <filesystem>
#include <fstream>
#include <random>

#include <nlohmann/json.hpp>

#include "base/IClock.h"
#include "response/QuarantineStore.h"
#include "response/ResponseJson.h"
#include "response/Sha256.h"

using namespace cairn;
using namespace cairn::response;
namespace fs = std::filesystem;

namespace {

class QuarantineRoundTrip : public ::testing::Test {
protected:
    void SetUp() override
    {
        std::random_device rd;
        m_root = fs::temp_directory_path() / ("cairn-qtest-" + std::to_string(rd()));
        fs::create_directories(m_root / "victim");
        m_vault = m_root / "vault";
    }
    void TearDown() override
    {
        std::error_code ec;
        fs::remove_all(m_root, ec);
    }

    fs::path WriteSample(const std::string& name, size_t size)
    {
        std::mt19937 rng{1234};   // 測試資料不需密碼學亂數
        std::string data(size, '\0');
        for (auto& c : data) c = static_cast<char>(rng() & 0xFF);
        const auto p = m_root / "victim" / name;
        std::ofstream(p, std::ios::binary).write(data.data(), static_cast<std::streamsize>(data.size()));
        return p;
    }

    static std::string FileSha(const fs::path& p)
    {
        std::ifstream in(p, std::ios::binary);
        std::string s((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        return Sha256::HexOf(s);
    }

    static fs::path FromU8(const std::string& s)
    {
        return fs::path(std::u8string(s.begin(), s.end()));
    }

    static std::string U8(const fs::path& p)
    {
        const auto u = p.u8string();
        return std::string(u.begin(), u.end());
    }

    fs::path  m_root;
    fs::path  m_vault;
    FakeClock m_clock;
};

} // namespace

TEST_F(QuarantineRoundTrip, QuarantineThenRestoreIsLossless)
{
    const auto sample = WriteSample("invoice_Q3.docm", 1024 * 1024 + 7);
    const auto before = FileSha(sample);

    QuarantineStore store{m_vault, m_clock, /*applyVaultAcl=*/false};
    ASSERT_TRUE(store.Init());

    QuarantineRequest req;
    req.path    = U8(sample);
    req.alertId = 4821;
    req.ruleIds = {"R-T1486-001"};
    req.actor   = "test";
    auto q = store.Quarantine(req);
    ASSERT_TRUE(q) << q.GetError().ToString();
    EXPECT_TRUE(q.Value().originalDeleted);
    EXPECT_FALSE(fs::exists(sample)) << "原檔必須在加密副本寫入成功後被刪除";
    EXPECT_EQ(q.Value().entry.sha256, before);

    // 隔離區內是密文，不得與明文相同
    const auto qFile = m_vault / (q.Value().entry.quarantineId + ".q");
    ASSERT_TRUE(fs::exists(qFile));
    EXPECT_NE(FileSha(qFile), before);

    auto r = store.Restore(q.Value().entry.quarantineId);
    ASSERT_TRUE(r) << r.GetError().ToString();
    EXPECT_EQ(FromU8(r.Value().restoredPath), sample);
    EXPECT_EQ(FileSha(sample), before) << "還原後雜湊必須與隔離前一致";
    EXPECT_FALSE(fs::exists(qFile)) << "還原後隔離副本應移除";
}

TEST_F(QuarantineRoundTrip, RestoreToOccupiedPathUsesRestoredSuffix)
{
    const auto sample = WriteSample("payload.exe", 4096);
    const auto before = FileSha(sample);
    QuarantineStore store{m_vault, m_clock, false};
    ASSERT_TRUE(store.Init());
    auto q = store.Quarantine({U8(sample), 1, {}, "test", std::nullopt});
    ASSERT_TRUE(q);
    std::ofstream(sample) << "new file occupying the original path";

    auto r = store.Restore(q.Value().entry.quarantineId);
    ASSERT_TRUE(r);
    auto restored = sample;
    restored += ".restored";
    EXPECT_EQ(FromU8(r.Value().restoredPath), restored);
    EXPECT_EQ(FileSha(restored), before);
}

TEST_F(QuarantineRoundTrip, TamperedCiphertextIsRejected)
{
    const auto sample = WriteSample("x.bin", 8192);
    QuarantineStore store{m_vault, m_clock, false};
    ASSERT_TRUE(store.Init());
    auto q = store.Quarantine({U8(sample), 1, {}, "test", std::nullopt});
    ASSERT_TRUE(q);

    const auto qFile = m_vault / (q.Value().entry.quarantineId + ".q");
    {
        std::fstream f(qFile, std::ios::in | std::ios::out | std::ios::binary);
        f.seekp(100);
        f.put('\x5A');
    }
    auto r = store.Restore(q.Value().entry.quarantineId);
    EXPECT_FALSE(r) << "GCM tag 驗證必須偵測隔離區被竄改";
    EXPECT_FALSE(fs::exists(sample));
}

TEST_F(QuarantineRoundTrip, MetadataHashMismatchIsRejected)
{
    const auto sample = WriteSample("y.bin", 2048);
    QuarantineStore store{m_vault, m_clock, false};
    ASSERT_TRUE(store.Init());
    auto q = store.Quarantine({U8(sample), 1, {}, "test", std::nullopt});
    ASSERT_TRUE(q);

    const auto meta = m_vault / (q.Value().entry.quarantineId + ".json");
    auto j = nlohmann::json::parse(std::ifstream(meta));
    j["sha256"] = std::string(64, '0');
    std::ofstream(meta, std::ios::trunc) << j.dump();

    auto r = store.Restore(q.Value().entry.quarantineId);
    ASSERT_FALSE(r);
    EXPECT_EQ(r.Code(), ErrorCode::RestoreHashMismatch);
}

TEST_F(QuarantineRoundTrip, MissingFileIsNotFound)
{
    QuarantineStore store{m_vault, m_clock, false};
    ASSERT_TRUE(store.Init());
    auto q = store.Quarantine({U8(m_root / "victim" / "nope.exe"), 1, {}, "test", std::nullopt});
    ASSERT_FALSE(q);
    EXPECT_EQ(q.Code(), ErrorCode::NotFound);   // 動作層轉為 ok=true "already gone"
}

TEST_F(QuarantineRoundTrip, OversizeFileIsRefusedAndOriginalKept)
{
    const auto sample = WriteSample("big.bin", 4096);
    QuarantineStore store{m_vault, m_clock, false, /*maxBytes=*/1024};
    ASSERT_TRUE(store.Init());
    auto q = store.Quarantine({U8(sample), 1, {}, "test", std::nullopt});
    EXPECT_FALSE(q);
    EXPECT_TRUE(fs::exists(sample)) << "拒絕隔離時原檔不得被動";
}

TEST_F(QuarantineRoundTrip, KeyPersistsAcrossInstances)
{
    const auto sample = WriteSample("z.bin", 1000);
    const auto before = FileSha(sample);
    std::string id;
    {
        QuarantineStore a{m_vault, m_clock, false};
        ASSERT_TRUE(a.Init());
        auto q = a.Quarantine({U8(sample), 1, {}, "test", std::nullopt});
        ASSERT_TRUE(q);
        id = q.Value().entry.quarantineId;
    }
    QuarantineStore b{m_vault, m_clock, false};   // 重新以 DPAPI 解開 vault.key
    ASSERT_TRUE(b.Init());
    EXPECT_EQ(b.List().size(), 1u);
    auto r = b.Restore(id);
    ASSERT_TRUE(r) << r.GetError().ToString();
    EXPECT_EQ(FileSha(sample), before);
}

TEST_F(QuarantineRoundTrip, ActionAdapterTreatsMissingFileAsSuccess)
{
    QuarantineStore store{m_vault, m_clock, false};
    ASSERT_TRUE(store.Init());
    QuarantineFileAction action{store};
    model::ResponseTarget target;
    target.filePath = U8(m_root / "victim" / "already-deleted.exe");
    ActionContext ctx{1, model::ActionKind::QuarantineFile, &target, "test", "test", false};
    ActionRecord rec;
    rec.actionId = "ACT-0001-01";
    const auto out = action.Execute(ctx, rec);
    ASSERT_EQ(out.size(), 1u);
    EXPECT_TRUE(out[0].ok);
    EXPECT_EQ(out[0].reason, "already gone");
}
