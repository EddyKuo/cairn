// src/core/rules/Fields.h                     namespace cairn::rules
// 欄位在編譯期解析為 enum，執行期不做字串查表（SDD-02 §5.3）。
// 三值約定：缺值以 std::monostate 表示，任何述詞（含否定型）在缺值時一律為 false（§5.4.6）。
#pragma once
#include <bitset>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "model/GuidValue.h"
#include "model/NormalizedEvent.h"
#include "model/StringInterner.h"

namespace cairn::tree {
struct ProcessNode;
class ProcessTree;
} // namespace cairn::tree

namespace cairn::rules {

enum class FieldId : uint16_t {
    Image, ParentImage, CommandLine, ParentCommandLine, User, IntegrityLevel,
    Sha256, SignatureSigner, SignatureValid,
    ProcessGuid, ParentProcessGuid, RootProcessGuid, Pid, ParentPid,
    TargetImage, TargetProcessGuid, GrantedAccess,
    TargetFilename, RegistryEventType, RegistryPath, RegistryDetails,
    DestIp, DestPort, DestHostname, QueryName, QueryResults, PipeName, ScriptBlock,
    TamperType, SourceEventId,
    // 衍生欄位（非事件原生，由引擎計算）
    TreeDepth, TreeScore, ImageIsSigned, ImageInUserWritableDir, ParentIsOffice,
    Count_
};
inline constexpr size_t kFieldCount = static_cast<size_t>(FieldId::Count_);
using FieldMask = std::bitset<kFieldCount>;

enum class FieldKind : uint8_t { String, Int, Bool, Guid };

[[nodiscard]] std::optional<FieldId> FieldFromName(std::string_view yamlName) noexcept;
[[nodiscard]] std::string_view FieldName(FieldId f) noexcept;
[[nodiscard]] FieldKind KindOf(FieldId f) noexcept;
[[nodiscard]] std::vector<std::string_view> AllFieldNames();

using FieldValue = std::variant<std::monostate, std::string_view, int64_t, bool, model::GuidValue>;

class BindingSet;

// 求值脈絡：全部是非擁有的參照。
struct EvalContext {
    const model::NormalizedEvent& ev;
    const tree::ProcessNode*      node     = nullptr;   // 事件所屬節點；可能為 nullptr
    const tree::ProcessTree*      tree     = nullptr;
    const model::StringInterner&  interner;
    const BindingSet*             bindings = nullptr;   // step >= 1 時為前序步驟的匯出值
    int64_t                       nowMs    = 0;
    int64_t                       treeScoreMilli = 0;

    [[nodiscard]] FieldValue Get(FieldId f) const noexcept;
};

} // namespace cairn::rules
