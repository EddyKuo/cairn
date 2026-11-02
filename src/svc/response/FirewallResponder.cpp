// src/svc/response/FirewallResponder.cpp      Win32 實作（INetFwPolicy2 COM）
#include "response/FirewallResponder.h"

#include <windows.h>
#include <objbase.h>
#include <oleauto.h>
#include <netfw.h>

#include <wil/com.h>
#include <wil/resource.h>

#include "common/WinUtil.h"
#include "response/ResponseJson.h"

namespace cairn::response {

namespace {

// 自持 BSTR（避免依賴 wil::make_bstr 的例外政策）
class Bstr {
public:
    explicit Bstr(const std::wstring& s) : m_b(::SysAllocStringLen(s.data(), static_cast<UINT>(s.size()))) {}
    ~Bstr() { if (m_b) ::SysFreeString(m_b); }
    Bstr(const Bstr&) = delete;
    Bstr& operator=(const Bstr&) = delete;
    [[nodiscard]] BSTR get() const noexcept { return m_b; }
    [[nodiscard]] explicit operator bool() const noexcept { return m_b != nullptr; }

private:
    BSTR m_b;
};

std::string BstrToUtf8(BSTR b)
{
    if (!b) return {};
    return svc::WideToUtf8(std::wstring_view(b, ::SysStringLen(b)));
}

Error HrError(std::string_view what, HRESULT hr)
{
    return MakeWin32Error(ErrorCode::FirewallComFailed, static_cast<uint32_t>(hr),
                          std::string(what) + " — " + svc::LastErrorMessage(static_cast<DWORD>(hr)));
}

} // namespace

struct FirewallBlockAction::Impl {
    wil::com_ptr_nothrow<INetFwPolicy2> policy;

    Result<INetFwRules*> Rules(wil::com_ptr_nothrow<INetFwRules>& holder)
    {
        if (!policy) {
            const HRESULT hr = ::CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER,
                                                  IID_PPV_ARGS(policy.put()));
            if (FAILED(hr)) return HrError("CoCreateInstance(NetFwPolicy2)", hr);
        }
        const HRESULT hr = policy->get_Rules(holder.put());
        if (FAILED(hr)) return HrError("INetFwPolicy2::get_Rules", hr);
        return holder.get();
    }

    // 目前作用中的設定檔是否全部啟用防火牆
    bool FirewallEnabledForCurrentProfiles()
    {
        if (!policy) return true;
        long profiles = 0;
        if (FAILED(policy->get_CurrentProfileTypes(&profiles))) return true;
        for (NET_FW_PROFILE_TYPE2 p : {NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC}) {
            if (!(profiles & p)) continue;
            VARIANT_BOOL enabled = VARIANT_TRUE;
            if (SUCCEEDED(policy->get_FirewallEnabled(p, &enabled)) && enabled == VARIANT_FALSE) return false;
        }
        return true;
    }
};

FirewallBlockAction::FirewallBlockAction() : m_impl(std::make_unique<Impl>()) {}
FirewallBlockAction::~FirewallBlockAction() = default;

void FirewallBlockAction::ReleaseCom() noexcept
{
    m_impl->policy.reset();
}

Result<ActionImpact> FirewallBlockAction::Prepare(const ActionContext& ctx)
{
    if (!ctx.target || !ctx.target->ip || !IsValidIpLiteral(*ctx.target->ip))
        return MakeReject(ErrorCode::InvalidArgument, "INVALID_TARGET", "firewall_block requires a literal IPv4/IPv6 address");
    const auto& ip = *ctx.target->ip;

    ImpactItem it;
    it.key   = "ip:" + ip;
    it.label = ip;
    it.ip    = ip;

    // 已存在同名規則（重複封鎖）屬資訊性提示
    const auto name = FirewallRuleName(ctx.alertId, ip);
    if (auto ex = RuleExists(name); ex && ex.Value()) {
        it.warning = "此告警已封鎖過此 IP（將覆寫既有規則）";
        it.warningLevel = "medium";
    }
    ActionImpact impact;
    impact.items.push_back(std::move(it));
    impact.totalCount = 1;
    impact.warnings.push_back("以 IP 為單位的封鎖：攻擊者更換 IP 即失效，僅封鎖出站連線");
    if (!m_impl->FirewallEnabledForCurrentProfiles())
        impact.warnings.push_back("Windows 防火牆在目前設定檔為停用狀態，封鎖規則不會生效");
    return impact;
}

std::vector<TargetOutcome> FirewallBlockAction::Execute(const ActionContext& ctx, ActionRecord& record)
{
    std::vector<TargetOutcome> outcomes;
    if (!ctx.target || !ctx.target->ip) return outcomes;
    const auto& ip = *ctx.target->ip;
    TargetOutcome o{"ip:" + ip, ip, false, 0, {}};
    if (!IsValidIpLiteral(ip)) {
        o.reason = "invalid IP literal";
        outcomes.push_back(std::move(o));
        return outcomes;
    }

    wil::com_ptr_nothrow<INetFwRules> rules;
    auto rr = m_impl->Rules(rules);
    if (!rr) {
        o.win32Error = rr.GetError().win32;
        o.reason = rr.GetError().context;
        outcomes.push_back(std::move(o));
        return outcomes;
    }

    const std::string name = FirewallRuleName(ctx.alertId, ip);
    const Bstr bName{svc::Utf8ToWide(name)};
    (void)rules->Remove(bName.get());   // 冪等：先刪同名舊規則（不存在時的錯誤可忽略）

    wil::com_ptr_nothrow<INetFwRule> rule;
    HRESULT hr = ::CoCreateInstance(__uuidof(NetFwRule), nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(rule.put()));
    if (FAILED(hr)) {
        o.win32Error = static_cast<uint32_t>(hr);
        o.reason = "CoCreateInstance(NetFwRule) failed";
        outcomes.push_back(std::move(o));
        return outcomes;
    }

    std::string desc = "Cairn alert " + std::to_string(ctx.alertId);
    if (!ctx.reason.empty()) desc += " — " + ctx.reason;
    const Bstr bDesc{svc::Utf8ToWide(desc)};
    const Bstr bAddr{svc::Utf8ToWide(ip)};
    const Bstr bGroup{L"Cairn"};

    // 各 put_* 依序設定；任一失敗即停止並回報（不留半設定的規則：Add 在最後）
    struct Step { const char* what; HRESULT hr; };
    const Step steps[] = {
        {"put_Name", rule->put_Name(bName.get())},
        {"put_Description", rule->put_Description(bDesc.get())},
        {"put_Grouping", rule->put_Grouping(bGroup.get())},
        {"put_Direction", rule->put_Direction(NET_FW_RULE_DIR_OUT)},
        {"put_Action", rule->put_Action(NET_FW_ACTION_BLOCK)},
        {"put_RemoteAddresses", rule->put_RemoteAddresses(bAddr.get())},
        {"put_Profiles", rule->put_Profiles(NET_FW_PROFILE2_ALL)},
        {"put_Enabled", rule->put_Enabled(VARIANT_TRUE)},
    };
    for (const auto& s : steps) {
        if (FAILED(s.hr)) {
            o.win32Error = static_cast<uint32_t>(s.hr);
            o.reason = std::string("INetFwRule::") + s.what + " failed";
            outcomes.push_back(std::move(o));
            return outcomes;
        }
    }
    hr = rules->Add(rule.get());
    if (FAILED(hr)) {
        o.win32Error = static_cast<uint32_t>(hr);
        o.reason = hr == E_ACCESSDENIED ? "INetFwRules::Add access denied（需系統管理員權限）" : "INetFwRules::Add failed";
        outcomes.push_back(std::move(o));
        return outcomes;
    }
    o.ok = true;
    o.reason = "outbound block rule added: " + name;
    record.firewallRuleName = name;
    record.ip = ip;
    outcomes.push_back(std::move(o));
    return outcomes;
}

Result<std::vector<TargetOutcome>> FirewallBlockAction::Revert(const ActionRecord& record)
{
    if (record.firewallRuleName.empty())
        return MakeReject(ErrorCode::InvalidArgument, "ACTION_NOT_FOUND", "no firewall rule recorded for this action");
    std::vector<TargetOutcome> outcomes;
    TargetOutcome o{"ip:" + record.ip, record.ip, false, 0, {}};

    wil::com_ptr_nothrow<INetFwRules> rules;
    auto rr = m_impl->Rules(rules);
    if (!rr) return rr.GetError();

    const Bstr bName{svc::Utf8ToWide(record.firewallRuleName)};
    wil::com_ptr_nothrow<INetFwRule> existing;
    const HRESULT hrItem = rules->Item(bName.get(), existing.put());
    if (FAILED(hrItem)) {
        o.ok = true;   // 規則已不存在：目標狀態已達成
        o.reason = "rule already removed";
    } else if (const HRESULT hr = rules->Remove(bName.get()); FAILED(hr)) {
        o.win32Error = static_cast<uint32_t>(hr);
        o.reason = "INetFwRules::Remove failed";
    } else {
        o.ok = true;
        o.reason = "rule removed: " + record.firewallRuleName;
    }
    outcomes.push_back(std::move(o));
    return outcomes;
}

Result<bool> FirewallBlockAction::RuleExists(const std::string& name)
{
    wil::com_ptr_nothrow<INetFwRules> rules;
    auto rr = m_impl->Rules(rules);
    if (!rr) return rr.GetError();
    const Bstr bName{svc::Utf8ToWide(name)};
    wil::com_ptr_nothrow<INetFwRule> rule;
    return SUCCEEDED(rules->Item(bName.get(), rule.put()));
}

Result<std::vector<std::string>> FirewallBlockAction::CleanupOrphans(const std::vector<std::string>& keepNames)
{
    wil::com_ptr_nothrow<INetFwRules> rules;
    auto rr = m_impl->Rules(rules);
    if (!rr) return rr.GetError();

    wil::com_ptr_nothrow<IUnknown> unk;
    HRESULT hr = rules->get__NewEnum(unk.put());
    if (FAILED(hr)) return HrError("INetFwRules::get__NewEnum", hr);
    wil::com_ptr_nothrow<IEnumVARIANT> en;
    hr = unk->QueryInterface(IID_PPV_ARGS(en.put()));
    if (FAILED(hr)) return HrError("QueryInterface(IEnumVARIANT)", hr);

    // 先收集再刪除：列舉期間修改集合的行為未定義
    std::vector<std::string> ours;
    VARIANT v;
    ::VariantInit(&v);
    ULONG fetched = 0;
    while (en->Next(1, &v, &fetched) == S_OK && fetched == 1) {
        if (v.vt == VT_DISPATCH && v.pdispVal) {
            wil::com_ptr_nothrow<INetFwRule> r;
            if (SUCCEEDED(v.pdispVal->QueryInterface(IID_PPV_ARGS(r.put())))) {
                BSTR name = nullptr;
                if (SUCCEEDED(r->get_Name(&name))) {
                    auto n = BstrToUtf8(name);
                    if (n.rfind(kFirewallRulePrefix, 0) == 0) ours.push_back(std::move(n));
                }
                if (name) ::SysFreeString(name);
            }
        }
        ::VariantClear(&v);
    }

    std::vector<std::string> removed;
    for (const auto& n : ours) {
        bool keep = false;
        for (const auto& k : keepNames)
            if (k == n) keep = true;
        if (keep) continue;
        const Bstr b{svc::Utf8ToWide(n)};
        if (SUCCEEDED(rules->Remove(b.get()))) removed.push_back(n);
    }
    return removed;
}

} // namespace cairn::response
