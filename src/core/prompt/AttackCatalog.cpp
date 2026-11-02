#include "prompt/AttackCatalog.h"

#include <cstdio>
#include <cstdlib>
#include <exception>

#include <nlohmann/json.hpp>

namespace cairn::llm {

namespace {

// 內嵌清單的精簡表示：
//   "T1005"          → 單一技術
//   "T1059.001-012"  → T1059 本身 + 子技術 T1059.001 … T1059.012
// 以空白分隔。新增／更新請以 MITRE enterprise-attack.json 為準（見 AttackCatalog.h）。
constexpr std::string_view kBuiltinSpec =
    // ---- T1001 – T1100 ----
    "T1001.001-003 T1003.001-008 T1005 T1006 T1007 T1008 T1010 T1011.001-001 T1012 T1014 "
    "T1016.001-002 T1018 T1020.001-001 T1021.001-008 T1025 T1027.001-013 T1029 T1030 T1033 "
    "T1036.001-009 T1037.001-005 T1039 T1040 T1041 T1046 T1047 T1048.001-003 T1049 "
    "T1052.001-001 T1053.002-007 T1055.001-015 T1056.001-004 T1057 T1059.001-012 T1068 "
    "T1069.001-003 T1070.001-010 T1071.001-005 T1072 T1074.001-002 T1078.001-004 T1080 "
    "T1082 T1083 T1087.001-004 T1090.001-004 T1091 T1092 T1095 T1098.001-007 "
    // ---- T1101 – T1250 ----
    "T1102.001-003 T1104 T1105 T1106 T1110.001-004 T1111 T1112 T1113 T1114.001-003 T1115 "
    "T1119 T1120 T1123 T1124 T1125 T1127.001-003 T1129 T1132.001-002 T1133 T1134.001-005 "
    "T1135 T1136.001-003 T1137.001-006 T1140 T1176.001-002 T1185 T1187 T1189 T1190 "
    "T1195.001-003 T1197 T1199 T1200 T1201 T1202 T1203 T1204.001-004 T1205.001-002 T1207 "
    "T1210 T1211 T1212 T1213.001-005 T1216.001-002 T1217 T1218.001-015 T1219.001-003 T1220 "
    "T1221 T1222.001-002 "
    // ---- T1480 – T1560 ----
    "T1480.001-002 T1482 T1484.001-002 T1485.001-001 T1486 T1489 T1490 T1491.001-002 T1495 "
    "T1496.001-004 T1497.001-003 T1498.001-002 T1499.001-004 T1505.001-006 T1518.001-002 "
    "T1525 T1526 T1528 T1529 T1530 T1531 T1534 T1535 T1537 T1538 T1539 T1540 "
    "T1542.001-005 T1543.001-005 T1546.001-017 T1547.001-015 T1548.001-006 T1550.001-004 "
    "T1552.001-008 T1553.001-006 T1554 T1555.001-006 T1556.001-009 T1557.001-004 "
    "T1558.001-005 T1559.001-003 T1560.001-003 "
    // ---- T1561 – T1620 ----
    "T1561.001-002 T1562.001-013 T1563.001-002 T1564.001-012 T1565.001-003 T1566.001-004 "
    "T1567.001-004 T1568.001-003 T1569.001-003 T1570 T1571 T1572 T1573.001-002 "
    "T1574.001-014 T1578.001-005 T1580 T1583.001-008 T1584.001-008 T1585.001-003 "
    "T1586.001-003 T1587.001-004 T1588.001-007 T1589.001-003 T1590.001-006 T1591.001-004 "
    "T1592.001-004 T1593.001-003 T1594 T1595.001-003 T1596.001-005 T1597.001-002 "
    "T1598.001-004 T1599.001-001 T1600.001-002 T1601.001-002 T1602.001-002 T1606.001-002 "
    "T1608.001-006 T1609 T1610 T1611 T1612 T1613 T1614.001-001 T1615 T1619 T1620 "
    // ---- T1621 以後 ----
    "T1621 T1622 T1647 T1648 T1649 T1650 T1651 T1652 T1653 T1654 T1656 T1657 T1659 "
    "T1665 T1666 T1667 T1668 T1669 T1671 T1672";

bool IsDigit(char c) noexcept { return c >= '0' && c <= '9'; }

void ExpandToken(std::string_view tok, std::unordered_set<std::string>& out)
{
    // tok: "T1234" 或 "T1234.aaa-bbb"
    if (tok.size() < 5) return;
    const std::string parent(tok.substr(0, 5));
    if (!AttackCatalog::IsWellFormed(parent)) return;
    out.insert(parent);
    if (tok.size() == 13 && tok[5] == '.' && tok[9] == '-') {
        const int from = std::atoi(std::string(tok.substr(6, 3)).c_str());
        const int to   = std::atoi(std::string(tok.substr(10, 3)).c_str());
        for (int n = from; n <= to && n <= 999; ++n) {
            char buf[16];
            std::snprintf(buf, sizeof(buf), "%s.%03d", parent.c_str(), n);
            out.insert(buf);
        }
    }
}

} // namespace

bool AttackCatalog::IsWellFormed(std::string_view id) noexcept
{
    if (id.size() != 5 && id.size() != 9) return false;
    if (id[0] != 'T') return false;
    for (size_t i = 1; i < 5; ++i)
        if (!IsDigit(id[i])) return false;
    if (id.size() == 9) {
        if (id[5] != '.') return false;
        for (size_t i = 6; i < 9; ++i)
            if (!IsDigit(id[i])) return false;
    }
    return true;
}

const AttackCatalog& AttackCatalog::Builtin()
{
    static const AttackCatalog kCatalog = [] {
        AttackCatalog c;
        std::string_view spec = kBuiltinSpec;
        while (!spec.empty()) {
            const size_t sp = spec.find(' ');
            const std::string_view tok = spec.substr(0, sp);
            if (!tok.empty()) ExpandToken(tok, c.m_ids);
            if (sp == std::string_view::npos) break;
            spec.remove_prefix(sp + 1);
        }
        return c;
    }();
    return kCatalog;
}

Result<AttackCatalog> AttackCatalog::FromJson(std::string_view json)
{
    try {
        const auto doc = nlohmann::json::parse(json.begin(), json.end());
        const nlohmann::json* arr = &doc;
        if (doc.is_object() && doc.contains("techniques")) arr = &doc.at("techniques");
        if (!arr->is_array()) return MakeError(ErrorCode::InvalidArgument, "attack-techniques.json: 需為陣列或 {techniques:[...]}");
        AttackCatalog c;
        for (const auto& v : *arr) {
            if (!v.is_string()) continue;
            const auto s = v.get<std::string>();
            if (IsWellFormed(s)) c.m_ids.insert(s);
        }
        if (c.m_ids.empty()) return MakeError(ErrorCode::InvalidArgument, "attack-techniques.json: 沒有任何合法的技術 ID");
        return c;
    } catch (const std::exception& e) {
        return MakeError(ErrorCode::InvalidArgument, std::string("attack-techniques.json 解析失敗: ") + e.what());
    }
}

AttackCatalog AttackCatalog::FromIds(const std::vector<std::string>& ids)
{
    AttackCatalog c;
    for (const auto& s : ids)
        if (IsWellFormed(s)) c.m_ids.insert(s);
    return c;
}

bool AttackCatalog::Contains(std::string_view id) const
{
    return IsWellFormed(id) && m_ids.find(std::string(id)) != m_ids.end();
}

std::vector<std::string> AttackCatalog::Filter(const std::vector<std::string>& ids) const
{
    std::vector<std::string>        out;
    std::unordered_set<std::string> seen;
    for (const auto& id : ids) {
        if (!Contains(id)) continue;
        if (seen.insert(id).second) out.push_back(id);
    }
    return out;
}

} // namespace cairn::llm
