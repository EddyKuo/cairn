// tests/svc/StoreTestUtil.h —— 儲存層測試的共用小工具（臨時目錄、事件建構）
#pragma once
#include <atomic>
#include <chrono>
#include <filesystem>
#include <random>
#include <string>

#include "model/GuidValue.h"
#include "model/NormalizedEvent.h"
#include "model/StringInterner.h"
#include "model/WriteOp.h"

namespace cairn::testutil {

// RAII 臨時目錄：解構時整個刪除
class TempDir {
public:
    TempDir()
    {
        std::random_device rd;
        m_path = std::filesystem::temp_directory_path() /
                 ("cairn-test-" + std::to_string(rd()) + "-" + std::to_string(Counter()++));
        std::filesystem::create_directories(m_path);
    }
    ~TempDir()
    {
        std::error_code ec;
        std::filesystem::remove_all(m_path, ec);
    }
    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;
    [[nodiscard]] const std::filesystem::path& Path() const noexcept { return m_path; }
    [[nodiscard]] std::filesystem::path Db() const { return m_path / "cairn.db"; }

private:
    static std::atomic<int>& Counter()
    {
        static std::atomic<int> c{0};
        return c;
    }
    std::filesystem::path m_path;
};

inline model::GuidValue MakeGuid(uint32_t n)
{
    model::GuidValue g;
    g.bytes[0] = 0x10;
    for (int i = 0; i < 4; ++i) g.bytes[12 + i] = static_cast<uint8_t>((n >> (8 * (3 - i))) & 0xFF);
    return g;
}

inline model::EventRow MakeEventRow(model::StringInterner& in, int64_t id, int64_t tsMs, uint32_t proc, uint32_t root,
                                    model::EventType type = model::EventType::ProcessCreate)
{
    model::EventRow r;
    r.id = id;
    r.ev.time          = std::chrono::system_clock::time_point{std::chrono::milliseconds{tsMs}};
    r.ev.type          = type;
    r.ev.source        = model::EventSourceKind::Sysmon;
    r.ev.sourceEventId = 1;
    r.ev.priority      = EventPriority::High;
    r.ev.processGuid   = MakeGuid(proc);
    r.ev.pid           = proc;
    r.ev.image         = in.InternLower("C:\\Windows\\System32\\cmd.exe");
    r.ev.commandLine   = "cmd.exe /c echo " + std::to_string(id);
    r.rootProcessGuid  = MakeGuid(root);
    return r;
}

inline model::ProcessRow MakeProcessRow(uint32_t proc, uint32_t parent, uint32_t root, int64_t startTs)
{
    model::ProcessRow p;
    p.processGuid       = MakeGuid(proc);
    if (parent) p.parentProcessGuid = MakeGuid(parent);
    p.rootProcessGuid   = MakeGuid(root);
    p.pid               = proc;
    p.image             = "C:\\Windows\\System32\\cmd.exe";
    p.commandLine       = "cmd.exe";
    p.startTs           = startTs;
    p.depth             = parent ? 1 : 0;
    return p;
}

template <class T>
model::WriteOp Op(T payload)
{
    model::WriteOp op;
    op.payload = std::move(payload);
    return op;
}

} // namespace cairn::testutil
