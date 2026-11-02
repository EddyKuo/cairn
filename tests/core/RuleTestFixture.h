// tests/core/RuleTestFixture.h —— 以「程序樹 + RuleEngine」直接餵事件的測試夾具（不經 AnalysisEngine）
#pragma once
#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "TestHelpers.h"
#include "rules/RuleEngine.h"
#include "rules/RuleLoader.h"
#include "tree/ProcessTree.h"

namespace cairn::test {

class RuleFixture : public ::testing::Test {
protected:
    model::StringInterner in;
    EventFactory          f{in};
    tree::ProcessTree     tree{in};
    rules::RuleEngine     engine;
    int64_t               nextEventId = 1;

    void Load(const std::string& yaml)
    {
        auto r = rules::LoadRuleTexts({{"inline.yaml", yaml}}, in);
        ASSERT_TRUE(r) << r.GetError().ToString();
        for (const auto& i : r.Value().rules) ASSERT_TRUE(i.loadError.empty()) << i.loadError;
        engine.SetRuleSet(r.Value().ruleSet);
    }

    // 更新程序樹後求值；回傳本事件的命中
    std::vector<rules::EngineHit> Feed(const model::NormalizedEvent& ev)
    {
        tree::ProcessNode* node = nullptr;
        auto cb = [this](const model::GuidValue& o, const model::GuidValue& n) { engine.Rekey(o, n); };
        if (ev.type == model::EventType::ProcessCreate) node = tree.OnProcessCreate(ev, f.Now(), cb);
        else node = tree.FindOrCreateStub(ev, f.Now());
        const int64_t ts = ToUnixMs(ev.time);
        rules::EvalContext ctx{ev, node, &tree, in, nullptr, ts, 0};
        return engine.Evaluate(ctx, nextEventId++, ts);
    }

    static bool HasRule(const std::vector<rules::EngineHit>& hits, const std::string& id, bool booster = false)
    {
        for (const auto& h : hits)
            if (h.rule->id == id && h.boosterId.empty() != booster) return true;
        return false;
    }
};

} // namespace cairn::test
