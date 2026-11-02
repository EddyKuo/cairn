// tests/core/TestHelpers.h —— core 測試共用的事件建構器與 fake sink
#pragma once
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "base/IClock.h"
#include "model/NarrativeTypes.h"
#include "model/NormalizedEvent.h"
#include "model/ResponseCommand.h"
#include "model/WriteOp.h"

namespace cairn::test {

// 以序號產生可讀的 GUID：{00000000-0000-0000-0000-0000000000NN}
inline model::GuidValue G(uint32_t n)
{
    model::GuidValue g;
    g.bytes[12] = static_cast<uint8_t>(n >> 24);
    g.bytes[13] = static_cast<uint8_t>(n >> 16);
    g.bytes[14] = static_cast<uint8_t>(n >> 8);
    g.bytes[15] = static_cast<uint8_t>(n);
    return g;
}

class EventFactory {
public:
    explicit EventFactory(model::StringInterner& in, UnixMs base = 1'700'000'000'000) : m_in(in), m_now(base) {}

    UnixMs Now() const { return m_now; }
    void   Advance(int64_t ms) { m_now += ms; }
    void   SetNow(UnixMs ms) { m_now = ms; }

    model::NormalizedEvent Base(model::EventType t, uint16_t eid, uint32_t guid, std::string_view image)
    {
        model::NormalizedEvent e;
        e.time          = FromUnixMs(m_now);
        e.type          = t;
        e.sourceEventId = eid;
        e.priority      = PriorityOfEid(eid);
        e.processGuid   = G(guid);
        e.pid           = guid + 1000;
        e.image         = m_in.InternLower(image);
        return e;
    }

    model::NormalizedEvent ProcessCreate(uint32_t guid, uint32_t parent, std::string_view image,
                                         std::string_view parentImage, std::string cmd = {})
    {
        auto e              = Base(model::EventType::ProcessCreate, 1, guid, image);
        e.parentProcessGuid = G(parent);
        e.parentPid         = parent + 1000;
        e.parentImage       = m_in.InternLower(parentImage);
        e.commandLine       = std::move(cmd);
        return e;
    }

    model::NormalizedEvent ProcessExit(uint32_t guid, std::string_view image)
    {
        return Base(model::EventType::ProcessTerminate, 5, guid, image);
    }

    model::NormalizedEvent RemoteThread(uint32_t guid, std::string_view image, uint32_t target,
                                        std::string_view targetImage)
    {
        auto e              = Base(model::EventType::CreateRemoteThread, 8, guid, image);
        e.targetProcessGuid = G(target);
        e.targetImage       = m_in.InternLower(targetImage);
        return e;
    }

    model::NormalizedEvent ProcessAccess(uint32_t guid, std::string_view image, std::string_view targetImage,
                                         uint32_t access)
    {
        auto e          = Base(model::EventType::ProcessAccess, 10, guid, image);
        e.targetImage   = m_in.InternLower(targetImage);
        e.grantedAccess = access;
        return e;
    }

    model::NormalizedEvent FileCreate(uint32_t guid, std::string_view image, std::string path)
    {
        auto e           = Base(model::EventType::FileCreate, 11, guid, image);
        e.targetFilename = std::move(path);
        return e;
    }

    model::NormalizedEvent FileDelete(uint32_t guid, std::string_view image, std::string path)
    {
        auto e           = Base(model::EventType::FileDelete, 23, guid, image);
        e.targetFilename = std::move(path);
        return e;
    }

    model::NormalizedEvent RegSet(uint32_t guid, std::string_view image, std::string path, std::string details)
    {
        auto e            = Base(model::EventType::RegistrySet, 13, guid, image);
        e.registryPath    = std::move(path);
        e.registryDetails = std::move(details);
        return e;
    }

    model::NormalizedEvent Network(uint32_t guid, std::string_view image, std::string ip, uint16_t port)
    {
        auto e            = Base(model::EventType::NetworkConnect, 3, guid, image);
        e.destinationIp   = std::move(ip);
        e.destinationPort = port;
        return e;
    }

    model::NormalizedEvent ScriptBlock(uint32_t guid, std::string_view image, std::string text)
    {
        auto e        = Base(model::EventType::ScriptBlock, 4104, guid, image);
        e.source      = model::EventSourceKind::PowerShell;
        e.scriptBlock = std::move(text);
        return e;
    }

private:
    model::StringInterner& m_in;
    UnixMs                 m_now;
};

// ---- fake sinks ----
class FakeWriteSink final : public model::IWriteSink {
public:
    bool Post(model::WriteOp&& op) override
    {
        if (rejectAll) return false;
        ops.push_back(std::move(op));
        return true;
    }

    template <class T>
    std::vector<const T*> All() const
    {
        std::vector<const T*> v;
        for (const auto& op : ops)
            if (const auto* p = std::get_if<T>(&op.payload)) v.push_back(p);
        return v;
    }

    template <class T>
    size_t IndexOfFirst() const
    {
        for (size_t i = 0; i < ops.size(); ++i)
            if (std::holds_alternative<T>(ops[i].payload)) return i;
        return ops.size();
    }

    std::vector<model::WriteOp> ops;
    bool rejectAll = false;
};

class FakeAlertSink final : public model::IAlertSink {
public:
    void OnAlertRaised(const model::AlertRaised& a) override { raised.push_back(a); }
    std::vector<model::AlertRaised> raised;
};

class FakeResponseSink final : public model::IResponseSink {
public:
    void Submit(model::ResponseCommand&& c) override { cmds.push_back(std::move(c)); }
    std::vector<model::ResponseCommand> cmds;
};

} // namespace cairn::test
