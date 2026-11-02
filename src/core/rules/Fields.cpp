#include "rules/Fields.h"

#include <array>

#include "rules/TextMatch.h"
#include "tree/ProcessTree.h"

namespace cairn::rules {

namespace {
struct FieldDef {
    FieldId          id;
    std::string_view name;
    FieldKind        kind;
};

constexpr std::array<FieldDef, kFieldCount> kFields{{
    {FieldId::Image, "image", FieldKind::String},
    {FieldId::ParentImage, "parent_image", FieldKind::String},
    {FieldId::CommandLine, "command_line", FieldKind::String},
    {FieldId::ParentCommandLine, "parent_command_line", FieldKind::String},
    {FieldId::User, "user", FieldKind::String},
    {FieldId::IntegrityLevel, "integrity_level", FieldKind::String},
    {FieldId::Sha256, "sha256", FieldKind::String},
    {FieldId::SignatureSigner, "signer", FieldKind::String},
    {FieldId::SignatureValid, "signature_valid", FieldKind::Bool},
    {FieldId::ProcessGuid, "process_guid", FieldKind::Guid},
    {FieldId::ParentProcessGuid, "parent_process_guid", FieldKind::Guid},
    {FieldId::RootProcessGuid, "root_process_guid", FieldKind::Guid},
    {FieldId::Pid, "pid", FieldKind::Int},
    {FieldId::ParentPid, "parent_pid", FieldKind::Int},
    {FieldId::TargetImage, "target_image", FieldKind::String},
    {FieldId::TargetProcessGuid, "target_process_guid", FieldKind::Guid},
    {FieldId::GrantedAccess, "granted_access", FieldKind::Int},
    {FieldId::TargetFilename, "target_filename", FieldKind::String},
    {FieldId::RegistryEventType, "registry_event_type", FieldKind::String},
    {FieldId::RegistryPath, "registry_path", FieldKind::String},
    {FieldId::RegistryDetails, "registry_details", FieldKind::String},
    {FieldId::DestIp, "dest_ip", FieldKind::String},
    {FieldId::DestPort, "dest_port", FieldKind::Int},
    {FieldId::DestHostname, "dest_hostname", FieldKind::String},
    {FieldId::QueryName, "query_name", FieldKind::String},
    {FieldId::QueryResults, "query_results", FieldKind::String},
    {FieldId::PipeName, "pipe_name", FieldKind::String},
    {FieldId::ScriptBlock, "script_block", FieldKind::String},
    {FieldId::TamperType, "tamper_type", FieldKind::String},
    {FieldId::SourceEventId, "event_id", FieldKind::Int},
    {FieldId::TreeDepth, "tree_depth", FieldKind::Int},
    {FieldId::TreeScore, "tree_score", FieldKind::Int},
    {FieldId::ImageIsSigned, "image_is_signed", FieldKind::Bool},
    {FieldId::ImageInUserWritableDir, "image_in_user_writable_dir", FieldKind::Bool},
    {FieldId::ParentIsOffice, "parent_is_office", FieldKind::Bool},
}};

// 別名（文件中出現過的寫法）
constexpr std::array<std::pair<std::string_view, FieldId>, 6> kAliases{{
    {"signature_signer", FieldId::SignatureSigner},
    {"destination_ip", FieldId::DestIp},
    {"destination_port", FieldId::DestPort},
    {"destination_hostname", FieldId::DestHostname},
    {"parent_guid", FieldId::ParentProcessGuid},
    {"source_event_id", FieldId::SourceEventId},
}};

std::string_view OptStr(const std::optional<std::string>& s) noexcept
{
    return s ? std::string_view{*s} : std::string_view{};
}

bool IsUserWritable(std::string_view path) noexcept
{
    static constexpr std::array<std::string_view, 8> kDirs{
        "\\users\\", "\\appdata\\", "\\temp\\", "\\tmp\\", "\\downloads\\", "\\programdata\\",
        "\\windows\\tasks\\", "\\recycle"};
    for (auto d : kDirs)
        if (ContainsCi(path, d)) return true;
    return false;
}

bool IsOffice(std::string_view path) noexcept
{
    static constexpr std::array<std::string_view, 7> kOffice{
        "\\winword.exe", "\\excel.exe", "\\powerpnt.exe", "\\outlook.exe",
        "\\msaccess.exe", "\\mspub.exe", "\\onenote.exe"};
    for (auto o : kOffice)
        if (EndsWithCi(path, o)) return true;
    return false;
}
} // namespace

std::optional<FieldId> FieldFromName(std::string_view n) noexcept
{
    for (const auto& f : kFields)
        if (f.name == n) return f.id;
    for (const auto& [a, id] : kAliases)
        if (a == n) return id;
    return std::nullopt;
}

std::string_view FieldName(FieldId f) noexcept
{
    const auto i = static_cast<size_t>(f);
    return i < kFields.size() ? kFields[i].name : std::string_view{"?"};
}

FieldKind KindOf(FieldId f) noexcept
{
    const auto i = static_cast<size_t>(f);
    return i < kFields.size() ? kFields[i].kind : FieldKind::String;
}

std::vector<std::string_view> AllFieldNames()
{
    std::vector<std::string_view> v;
    for (const auto& f : kFields) v.push_back(f.name);
    return v;
}

FieldValue EvalContext::Get(FieldId f) const noexcept
{
    auto str = [](std::string_view s) -> FieldValue {
        if (s.empty()) return std::monostate{};
        return s;
    };
    switch (f) {
    case FieldId::Image:
        return str(model::ResolveField(interner, ev.image, ev.imageFallback));
    case FieldId::ParentImage: {
        std::string_view s = model::ResolveField(interner, ev.parentImage, ev.parentImageFallback);
        if (s.empty() && node && tree) {
            if (const auto* p = tree->Find(node->parentGuid)) {
                s = p->image != model::kInvalidInternId ? interner.Resolve(p->image)
                                                        : std::string_view{p->imageFallback};
            }
        }
        return str(s);
    }
    case FieldId::CommandLine:
        if (!ev.commandLine.empty()) return std::string_view{ev.commandLine};
        if (node && !node->commandLine.empty()) return std::string_view{node->commandLine};
        return std::monostate{};
    case FieldId::ParentCommandLine:
        return str(ev.parentCommandLine);
    case FieldId::User:
        return str(interner.Resolve(ev.user));
    case FieldId::IntegrityLevel:
        return str(ev.integrityLevel);
    case FieldId::Sha256:
        if (!ev.sha256.empty()) return std::string_view{ev.sha256};
        if (node && !node->sha256.empty()) return std::string_view{node->sha256};
        return std::monostate{};
    case FieldId::SignatureSigner:
        return str(model::ResolveField(interner, ev.signer, ev.signerFallback));
    case FieldId::SignatureValid:
        if (ev.signatureValid) return *ev.signatureValid;
        if (node && node->signatureValid) return *node->signatureValid;
        return std::monostate{};
    case FieldId::ProcessGuid:
        if (ev.processGuid.IsNull()) return std::monostate{};
        return ev.processGuid;
    case FieldId::ParentProcessGuid:
        if (!ev.parentProcessGuid.IsNull()) return ev.parentProcessGuid;
        if (node && !node->parentGuid.IsNull()) return node->parentGuid;
        return std::monostate{};
    case FieldId::RootProcessGuid:
        if (node) return node->rootGuid;
        return std::monostate{};
    case FieldId::Pid:
        if (ev.pid) return static_cast<int64_t>(ev.pid);
        return std::monostate{};
    case FieldId::ParentPid:
        if (ev.parentPid) return static_cast<int64_t>(ev.parentPid);
        return std::monostate{};
    case FieldId::TargetImage:
        if (ev.targetImage && *ev.targetImage != model::kInvalidInternId) return str(interner.Resolve(*ev.targetImage));
        return str(OptStr(ev.targetImageFallback));
    case FieldId::TargetProcessGuid:
        if (ev.targetProcessGuid) return *ev.targetProcessGuid;
        return std::monostate{};
    case FieldId::GrantedAccess:
        if (ev.grantedAccess) return static_cast<int64_t>(*ev.grantedAccess);
        return std::monostate{};
    case FieldId::TargetFilename:
        return str(OptStr(ev.targetFilename));
    case FieldId::RegistryEventType:
        return str(OptStr(ev.registryEventType));
    case FieldId::RegistryPath:
        return str(OptStr(ev.registryPath));
    case FieldId::RegistryDetails:
        return str(OptStr(ev.registryDetails));
    case FieldId::DestIp:
        return str(OptStr(ev.destinationIp));
    case FieldId::DestPort:
        if (ev.destinationPort) return static_cast<int64_t>(*ev.destinationPort);
        return std::monostate{};
    case FieldId::DestHostname:
        return str(OptStr(ev.destinationHostname));
    case FieldId::QueryName:
        return str(OptStr(ev.queryName));
    case FieldId::QueryResults:
        return str(OptStr(ev.queryResults));
    case FieldId::PipeName:
        return str(OptStr(ev.pipeName));
    case FieldId::ScriptBlock:
        return str(OptStr(ev.scriptBlock));
    case FieldId::TamperType:
        return str(OptStr(ev.tamperType));
    case FieldId::SourceEventId:
        return static_cast<int64_t>(ev.sourceEventId);
    case FieldId::TreeDepth:
        if (node) return static_cast<int64_t>(node->depth);
        return std::monostate{};
    case FieldId::TreeScore:
        return treeScoreMilli / 1000;
    case FieldId::ImageIsSigned: {
        const FieldValue v = Get(FieldId::SignatureValid);
        if (std::holds_alternative<bool>(v)) {
            const FieldValue s = Get(FieldId::SignatureSigner);
            return std::get<bool>(v) && std::holds_alternative<std::string_view>(s);
        }
        return std::monostate{};
    }
    case FieldId::ImageInUserWritableDir: {
        const std::string_view img = model::ResolveField(interner, ev.image, ev.imageFallback);
        if (img.empty()) return std::monostate{};
        return IsUserWritable(img);
    }
    case FieldId::ParentIsOffice: {
        const FieldValue p = Get(FieldId::ParentImage);
        if (!std::holds_alternative<std::string_view>(p)) return std::monostate{};
        return IsOffice(std::get<std::string_view>(p));
    }
    case FieldId::Count_:
        break;
    }
    return std::monostate{};
}

} // namespace cairn::rules
