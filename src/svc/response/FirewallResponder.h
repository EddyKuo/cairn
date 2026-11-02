// src/svc/response/FirewallResponder.h        namespace cairn::response
// firewall_block（SDD-03 §8.2.4）：INetFwPolicy2 COM，不用 netsh。標頭可攜；實作為 Win32。
//
//   - 規則名 `Cairn - Block {alertId} ({ip})`（CONVENTIONS C-2.2 前綴「Cairn - Block 」含尾端空格；
//     IP 不做字元置換，孤兒清理以原始 IP 比對）
//   - 僅 outbound、NET_FW_PROFILE2_ALL；已存在同名規則先 Remove 再 Add（冪等）
//   - COM 介面只在 ResponseThread（T6）使用；延遲建立（防火牆服務未就緒不致讓服務啟動失敗）
//
// ⚠ 誠實限制：以 IP 為單位的封鎖，攻擊者換 IP 即失效（M0 不做網域封鎖）。
#pragma once
#include <memory>
#include <string>
#include <vector>

#include "response/IResponseAction.h"

namespace cairn::response {

inline constexpr const char* kFirewallRulePrefix = "Cairn - Block ";

[[nodiscard]] std::string FirewallRuleName(int64_t alertId, const std::string& ip);
// 嚴格驗證 IPv4 / IPv6 字面值（防止把 "*" 或 "LocalSubnet" 之類的關鍵字塞進 RemoteAddresses）
[[nodiscard]] bool IsValidIpLiteral(const std::string& ip);

class FirewallBlockAction final : public IResponseAction {
public:
    FirewallBlockAction();
    ~FirewallBlockAction() override;   // 必須在 CoUninitialize 前於 T6 上解構（釋放 COM 指標）
    [[nodiscard]] model::ActionKind Kind() const noexcept override { return model::ActionKind::FirewallBlock; }
    [[nodiscard]] Result<ActionImpact> Prepare(const ActionContext& ctx) override;
    [[nodiscard]] std::vector<TargetOutcome> Execute(const ActionContext& ctx, ActionRecord& record) override;
    [[nodiscard]] Result<std::vector<TargetOutcome>> Revert(const ActionRecord& record) override;

    // 服務啟動時：列出所有以前綴開頭的規則，不在 keepNames 中者移除（DB 重建後的永久封鎖防護）。
    // 回傳被移除的規則名。
    [[nodiscard]] Result<std::vector<std::string>> CleanupOrphans(const std::vector<std::string>& keepNames);

    // 測試／UI 用：規則是否存在
    [[nodiscard]] Result<bool> RuleExists(const std::string& name);

    // 釋放 COM 指標（T6 結束前呼叫）
    void ReleaseCom() noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace cairn::response
