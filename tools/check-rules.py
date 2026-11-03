#!/usr/bin/env python3
"""
tools/check-rules.py —— 規則與排除清單的靜態檢查（不需建置、不需 Windows）

除了 rules/_schema.json 的結構驗證，另外鏡像 RuleCompiler 的語意檢查，並交叉比對：
  1. JSON Schema（與 CI 原本的檢查相同）
  2. RuleCompiler 語意：時間範圍、equals_ref 只能引用前序步驟、threshold.within <= within、
     匯出綁定 <= 6、步驟 id 不重複、欄位型別與運算子相容、has_any 遮罩非 0、正則可編譯
  3. Schema 與 C++ 原始碼的漂移：欄位名 / 事件型別 / 別名（Fields.cpp、EventType.cpp、RuleCompiler.cpp）
  4. requires_events 與 event 型別一致（用到的事件型別所需 EID 都要列出）
  5. config/sysmon.xml 有開啟 requires_events 所需的 Sysmon 事件
  6. attack ID 在 AttackCatalog 內建白名單內
  7. 正則：C++ std::regex(ECMAScript) 不支援的語法（lookbehind、具名群組、內嵌旗標等）；
     prefilter 是否真的出現在正則的必要字面量中（避免 prefilter 擋掉真正的命中）
  8. exclusions.default.yaml：kind 合法、scope_rule_id 指向存在的規則、禁止排除 Microsoft Windows 簽章者
  9. 測試 / 工具 / 文件引用的規則 ID 是否存在（僅警告：測試可內嵌合成規則）

用法：python3 tools/check-rules.py [--strict]
  --strict：警告也視為失敗
結束碼：0 = 無錯誤；1 = 有錯誤（或 --strict 下有警告）
相依：pyyaml、jsonschema
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys
import xml.etree.ElementTree as ET

import jsonschema
import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def p(*parts: str) -> str:
    return os.path.join(ROOT, *parts)


def read(path: str) -> str:
    with open(path, encoding="utf-8") as f:
        return f.read()


# ---------------------------------------------------------------- 報告
class Report:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def err(self, where: str, msg: str) -> None:
        self.errors.append(f"ERROR   {where}: {msg}")

    def warn(self, where: str, msg: str) -> None:
        self.warnings.append(f"WARN    {where}: {msg}")


# ---------------------------------------------------------------- 從 C++ 萃取權威清單
def cpp_fields() -> dict[str, str]:
    """欄位名 → 型別（String/Int/Bool/Guid），含別名。"""
    src = read(p("src/core/rules/Fields.cpp"))
    fields = {m.group(2): m.group(3)
              for m in re.finditer(r'\{FieldId::(\w+),\s*"(\w+)",\s*FieldKind::(\w+)\}', src)}
    ids = {m.group(1): m.group(2)
           for m in re.finditer(r'\{FieldId::(\w+),\s*"(\w+)",\s*FieldKind::\w+\}', src)}
    for m in re.finditer(r'\{"(\w+)",\s*FieldId::(\w+)\}', src):
        canon = ids.get(m.group(2))
        if canon:
            fields[m.group(1)] = fields[canon]
    return fields


def cpp_event_types() -> dict[str, set[int]]:
    """規則可用的事件型別名稱 → 需要的 EID 集合（含 RuleCompiler 別名）。"""
    et_src = read(p("src/core/model/EventType.cpp"))
    enum_to_name = {m.group(1): m.group(2)
                    for m in re.finditer(r'\{EventType::(\w+),\s*"(\w+)"\}', et_src)}
    enum_to_eids: dict[str, set[int]] = {}
    for m in re.finditer(r'((?:case \d+:\s*)+)return EventType::(\w+);', et_src):
        enum_to_eids.setdefault(m.group(2), set()).update(int(x) for x in re.findall(r'\d+', m.group(1)))
    enum_to_eids.setdefault("ScriptBlock", set()).add(4104)
    enum_to_eids.setdefault("SecurityProcessCreate", set()).add(4688)

    out = {name: enum_to_eids.get(enum, set())
           for enum, name in enum_to_name.items() if name != "UNKNOWN"}

    rc_src = read(p("src/core/rules/RuleCompiler.cpp"))
    for m in re.finditer(r'\{"(\w+)",\s*\{((?:model::EventType::\w+,?\s*)+)\}\}', rc_src):
        eids: set[int] = set()
        for enum in re.findall(r'EventType::(\w+)', m.group(2)):
            eids |= enum_to_eids.get(enum, set())
        out[m.group(1)] = eids
    return out


def cpp_attack_whitelist() -> set[str]:
    src = read(p("src/core/prompt/AttackCatalog.cpp"))
    m = re.search(r'kBuiltinSpec\s*=\s*(.*?);', src, re.S)
    spec = " ".join(re.findall(r'"([^"]*)"', m.group(1))) if m else ""
    out: set[str] = set()
    for tok in spec.split():
        parent = tok[:5]
        out.add(parent)
        mm = re.fullmatch(r'T\d{4}\.(\d{3})-(\d{3})', tok)
        if mm:
            for n in range(int(mm.group(1)), int(mm.group(2)) + 1):
                out.add(f"{parent}.{n:03d}")
    return out


# ---------------------------------------------------------------- Sysmon 設定
SYSMON_ELEMENT_EIDS = {
    "ProcessCreate": [1], "FileCreateTime": [2], "NetworkConnect": [3], "ProcessTerminate": [5],
    "DriverLoad": [6], "ImageLoad": [7], "CreateRemoteThread": [8], "RawAccessRead": [9],
    "ProcessAccess": [10], "FileCreate": [11], "RegistryEvent": [12, 13, 14],
    "FileCreateStreamHash": [15], "PipeEvent": [17, 18], "WmiEvent": [19, 20, 21], "DnsQuery": [22],
    "FileDelete": [23], "ClipboardChange": [24], "ProcessTampering": [25], "FileDeleteDetected": [26],
    "FileBlockExecutable": [27], "FileBlockShredding": [28], "FileExecutableDetected": [29],
}


def sysmon_enabled_eids(rep: Report) -> tuple[set[int], dict[int, str]]:
    """回傳（會被記錄的 EID 集合, EID → 'include 篩選' 說明）。
    exclude 模式 = 全收（減去排除）；include 模式且有條件 = 只收符合者；include 空 = 不收。"""
    path = p("config/sysmon.xml")
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError as e:
        rep.err("config/sysmon.xml", f"XML 解析失敗：{e}")
        return set(), {}
    enabled: set[int] = set()
    filtered: dict[int, str] = {}
    for el in root.iter():
        eids = SYSMON_ELEMENT_EIDS.get(el.tag)
        if not eids or "onmatch" not in el.attrib:
            continue
        mode = el.attrib["onmatch"]
        n = len(list(el))
        if mode == "exclude":
            enabled.update(eids)
        elif mode == "include" and n > 0:
            enabled.update(eids)
            for e in eids:
                filtered[e] = f"{el.tag} onmatch=include（{n} 條件）"
    return enabled, filtered


# ---------------------------------------------------------------- 正則
ECMA_UNSUPPORTED = [
    (r'\(\?<[=!]', "lookbehind（C++ std::regex ECMAScript 不支援）"),
    (r'\(\?P?<\w+>', "具名群組（std::regex 不支援）"),
    (r'\(\?[a-zA-Z]+[):]', "內嵌旗標（只允許開頭的 (?i)，且會被剝除）"),
    (r'\(\?>', "原子群組（std::regex 不支援）"),
    (r'[*+?}]\+', "佔有量詞（std::regex 不支援）"),
    (r'\\[AZz]', "\\A / \\Z / \\z 錨點（std::regex 不支援，請用 ^ / $）"),
    (r'\\[pP]\{', "Unicode 屬性 \\p{..}（std::regex 不支援）"),
    (r'\(\?#', "註解群組（std::regex 不支援）"),
]


try:
    import re._parser as sre_parse          # Python 3.11+
    from re._constants import (ANY, AT, BRANCH, IN, LITERAL, MAX_REPEAT, MIN_REPEAT, SUBPATTERN)
except ImportError:                          # pragma: no cover
    import sre_parse                         # type: ignore
    from sre_constants import (ANY, AT, BRANCH, IN, LITERAL, MAX_REPEAT, MIN_REPEAT, SUBPATTERN)  # type: ignore

_MAX_ALTS = 256


def required_literals(body: str) -> list[list[str]] | None:
    """回傳正則的「匹配路徑 → 必要字面量」：外層每個元素是一種匹配路徑，
    內層是該路徑上一定逐字出現的字串。任何命中都至少符合其中一條路徑的所有字串。
    None = 路徑組合過多、無法判定。"""
    Path = tuple  # (已完成的字面量 tuple, 尚未結束的字面量 run)

    def seq(items, paths: list) -> list | None:
        for op, av in items:
            if op is LITERAL:
                paths = [(done, run + chr(av)) for done, run in paths]
            elif op is IN and 1 <= len(av) <= 4 and all(t is LITERAL for t, _ in av):
                # 單字元或小類別（如 [-/]）：每個字元各成一條路徑，字面量可延續
                paths = [(done, run + chr(v)) for done, run in paths for _, v in av]
            elif op is AT:
                continue                                   # 錨點不吃字元
            elif op is SUBPATTERN:
                paths = seq(av[-1], paths)
            elif op is BRANCH:
                out = []
                for b in av[1]:
                    sub = seq(b, paths)
                    if sub is None:
                        return None
                    out += sub
                paths = out
            elif op in (MAX_REPEAT, MIN_REPEAT):
                lo, _hi, sub = av
                paths = [close(p) for p in paths]
                if lo >= 1:
                    paths = seq(sub, paths)
                    if paths is None:
                        return None
                    paths = [close(p) for p in paths]      # 重複次數不定：之後的字面量不得與內部相連
            else:                                          # ANY / 大類別 / \s 等：打斷字面量
                paths = [close(p) for p in paths]
            if paths is None or len(paths) > _MAX_ALTS:
                return None
        return paths

    def close(p: Path) -> Path:
        done, run = p
        return (done + (run,), "") if run else p

    try:
        parsed = sre_parse.parse(body, re.I)
    except Exception:
        return None
    paths = seq(parsed, [((), "")])
    if paths is None:
        return None
    return [list(close(p)[0]) for p in paths]


def auto_prefilter(body: str) -> list[str]:
    """鏡像 RuleCompiler.cpp 的 AutoPrefilter（修正後版本）。"""
    if "|" in body:
        return []
    best = cur = ""
    depth = 0
    i = 0
    while i < len(body):
        c = body[i]
        if c == "\\":
            best, cur = (cur, "") if len(cur) > len(best) else (best, "")
            i += 2
            continue
        if c == "[":
            best, cur = (cur, "") if len(cur) > len(best) else (best, "")
            j = i + 1
            if j < len(body) and body[j] == "^":
                j += 1
            if j < len(body) and body[j] == "]":
                j += 1
            while j < len(body) and body[j] != "]":
                j += 2 if body[j] == "\\" else 1
            i = j + 1
            continue
        if c in "()":
            best, cur = (cur, "") if len(cur) > len(best) else (best, "")
            depth = depth + 1 if c == "(" else max(0, depth - 1)
            i += 1
            continue
        if depth > 0:
            i += 1
            continue
        if c.isalnum() or c in "_-":
            nxt = body[i + 1] if i + 1 < len(body) else ""
            if nxt in ("?", "*", "{"):
                best, cur = (cur, "") if len(cur) > len(best) else (best, "")
            else:
                cur += c
        else:
            best, cur = (cur, "") if len(cur) > len(best) else (best, "")
        i += 1
    if len(cur) > len(best):
        best = cur
    return [best.lower()] if len(best) >= 3 else []


def prefilter_gaps(body: str, prefilter: list[str]) -> list[list[str]] | None:
    """回傳「不含任何 prefilter 字串」的匹配路徑（= prefilter 會擋掉的真命中）。None = 無法判定。"""
    alts = required_literals(body)
    if alts is None:
        return None
    pre = [x.lower() for x in prefilter]
    return [a for a in alts if not any(pf in lit.lower() for pf in pre for lit in a)]


def check_regex(where: str, pattern: str, prefilter: list[str] | None, rep: Report) -> None:
    body = pattern[4:] if pattern.startswith("(?i)") else pattern
    for rx, why in ECMA_UNSUPPORTED:
        if re.search(rx, body):
            rep.err(where, f"正則使用 {why}：{pattern}")
    try:
        compiled = re.compile(body, re.I)
    except re.error as e:
        rep.err(where, f"正則無法編譯：{e}：{pattern}")
        return
    if prefilter is not None:
        if not prefilter:
            rep.err(where, "prefilter 為空清單：會讓 MatchExpr 永遠跳過 prefilter（等同未設），請移除或填值")
        for s in prefilter:
            if s != s.lower():
                rep.warn(where, f"prefilter '{s}' 含大寫：比對時會轉小寫，建議直接寫小寫")
    # prefilter 是「必要條件」：任何真正的命中都必須含有至少一個 prefilter 字串，否則 MatchExpr 直接跳過。
    effective = prefilter if prefilter is not None else auto_prefilter(body)
    if effective:
        gaps = prefilter_gaps(body, effective)
        src = "prefilter" if prefilter is not None else "AutoPrefilter 推導的 prefilter"
        if gaps is None:
            rep.warn(where, f"無法分析 {src} {effective} 是否涵蓋正則所有分支，請人工確認")
        elif gaps:
            shown = "; ".join("[" + ", ".join(repr(x) for x in g) + "]" for g in gaps[:3])
            rep.warn(where, f"{src} {effective} 不涵蓋某些匹配路徑（必要字面量 {shown}），"
                            f"這些命中會被跳過；常見原因是 \\s 可為 tab、或分支內沒有 prefilter 字串")
    del compiled


# ---------------------------------------------------------------- 規則語意
DUR_RE = re.compile(r'^(\d+)([sm])$')
STRING_OPS = {"contains", "not_contains", "starts_with", "not_starts_with", "ends_with", "not_ends_with",
              "contains_any", "not_contains_any", "starts_with_any", "not_starts_with_any",
              "ends_with_any", "not_ends_with_any"}
SINGLE_VALUE_OPS = {"contains", "not_contains", "starts_with", "not_starts_with", "ends_with",
                    "not_ends_with", "equals", "not_equals", "gt", "lt", "matches", "not_matches",
                    "equals_ref", "not_equals_ref"}
GUID_RE = re.compile(r'^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$')


def dur_ms(v) -> int | None:
    m = DUR_RE.match(str(v))
    if not m:
        return None
    return int(m.group(1)) * (1000 if m.group(2) == "s" else 60_000)


def check_duration(where: str, key: str, v, lo_ms: int, hi_ms: int, rep: Report) -> int | None:
    ms = dur_ms(v)
    if ms is None:
        rep.err(where, f"{key} 格式需為 \\d+[sm]：{v!r}")
        return None
    if not lo_ms <= ms <= hi_ms:
        rep.err(where, f"{key}={v} 超出 RuleCompiler 允許範圍 {lo_ms // 1000}s–{hi_ms // 1000}s")
    return ms


def parse_int(s) -> int | None:
    if isinstance(s, bool):
        return None
    if isinstance(s, int):
        return s
    try:
        return int(str(s), 0)
    except ValueError:
        return None


def as_list(v) -> list:
    return v if isinstance(v, list) else [v]


class StepScope:
    def __init__(self, allow_refs: bool, step_names: dict[str, int], current: int) -> None:
        self.allow_refs = allow_refs
        self.step_names = step_names
        self.current = current
        self.exports: set[tuple[int, str]] = set()


def check_condition(where: str, c, scope: StepScope, fields: dict[str, str], rep: Report) -> None:
    if not isinstance(c, dict):
        rep.err(where, "條件必須是物件")
        return
    for key in ("any_of", "all_of"):
        if key in c:
            for i, sub in enumerate(as_list(c[key])):
                check_condition(f"{where}.{key}[{i}]", sub, scope, fields, rep)
            return
    field, op, value = c.get("field"), str(c.get("op", "")).lower(), c.get("value")
    kind = fields.get(field)
    if kind is None:
        rep.err(where, f"未知欄位 '{field}'（RuleCompiler 會拒絕）")
        return
    if value is None:
        rep.err(where, "條件缺少 value")
        return
    w = f"{where}({field} {op})"

    if op in SINGLE_VALUE_OPS and isinstance(value, list):
        rep.err(w, f"{op} 需要單一值（清單請用 *_any 或 in）")
        return
    if op in STRING_OPS and kind != "String":
        rep.err(w, f"{op} 只能用於字串欄位（{field} 為 {kind}）")
    if op in ("gt", "lt", "has_any") and kind != "Int":
        rep.err(w, f"{op} 只能用於整數欄位（{field} 為 {kind}）")
    if op in ("matches", "not_matches"):
        if kind != "String":
            rep.err(w, f"{op} 只能用於字串欄位")
        check_regex(w, str(value), c.get("prefilter"), rep)
    elif "prefilter" in c:
        rep.warn(w, "prefilter 只對 matches / not_matches 有作用")

    if op == "has_any":
        mask = 0
        for x in as_list(value):
            i = parse_int(x)
            if i is None:
                rep.err(w, f"has_any 需要整數或 0x 遮罩：{x!r}")
            else:
                mask |= i
        if mask == 0:
            rep.err(w, "has_any 的遮罩不可為 0")
    elif op in ("equals_ref", "not_equals_ref"):
        if not scope.allow_refs:
            rep.err(w, "步驟 0 / 單事件規則 / booster 不可使用 equals_ref")
            return
        ref = str(value)
        if "." not in ref:
            rep.err(w, f"equals_ref 的值需為 <step_id>.<field>：{ref}")
            return
        step, src_field = ref.split(".", 1)
        if src_field not in fields:
            rep.err(w, f"equals_ref 引用未知欄位 '{src_field}'")
        idx = scope.step_names.get(step)
        if idx is None or idx >= scope.current:
            rep.err(w, f"equals_ref 引用的步驟 '{step}' 不存在於前序步驟")
        else:
            scope.exports.add((idx, fields.get(src_field, src_field)))
            if fields.get(src_field) != kind:
                rep.warn(w, f"equals_ref 兩端型別不同（{field}:{kind} vs {src_field}:{fields.get(src_field)}）")
    elif op not in ("matches", "not_matches"):
        for x in as_list(value):
            if kind == "Int" and parse_int(x) is None:
                rep.err(w, f"欄位 {field} 需要整數值：{x!r}")
            elif kind == "Bool" and str(x).lower() not in ("true", "false", "yes", "no", "1", "0"):
                rep.err(w, f"欄位 {field} 需要布林值：{x!r}")
            elif kind == "Guid" and not GUID_RE.match(str(x)):
                rep.err(w, f"欄位 {field} 需要 GUID：{x!r}")
            elif kind == "String" and isinstance(x, str) and x == "":
                rep.warn(w, "空字串值：contains/starts_with 空字串永遠成立")
        if isinstance(value, list) and len(value) == 0:
            rep.err(w, "清單不可為空")
        if isinstance(value, list) and len(set(map(str, value))) != len(value):
            rep.warn(w, "清單中有重複值")


def check_where(where: str, n, scope: StepScope, fields: dict[str, str], rep: Report) -> None:
    if n is None:
        return
    for i, c in enumerate(as_list(n)):
        check_condition(f"{where}.where[{i}]", c, scope, fields, rep)


def event_eids(where: str, ev, events: dict[str, set[int]], rep: Report) -> set[int]:
    out: set[int] = set()
    for e in as_list(ev):
        name = str(e).upper()
        if name not in events:
            rep.err(where, f"未知的事件型別 '{e}'（RuleCompiler 會拒絕）")
        else:
            out |= events[name]
    return out


def check_rule(where: str, doc: dict, ctx: dict, rep: Report) -> None:
    fields, events = ctx["fields"], ctx["events"]
    rid = doc.get("id", "?")

    title = str(doc.get("title", ""))
    if len(title.encode("utf-8")) > 360:
        rep.err(where, "title 超過 RuleCompiler 的 360 bytes 上限")
    check_duration(where, "decay", doc.get("decay"), 30_000, 3_600_000, rep)

    req = [parse_int(x) for x in as_list(doc.get("requires_events", []))]
    req_set = {x for x in req if x is not None}
    if len(req_set) != len(req):
        rep.warn(where, "requires_events 有重複或非整數值")

    used_eids: set[int] = set()
    exports: set[tuple[int, str]] = set()

    if "sequence" in doc:
        seq = doc["sequence"]
        within = check_duration(where, "sequence.within", seq.get("within"), 30_000, 600_000, rep)
        names: dict[str, int] = {}
        for i, st in enumerate(seq.get("steps", [])):
            sw = f"{where}.steps[{i}:{st.get('id')}]"
            if st.get("id") in names:
                rep.err(sw, f"步驟 id 重複：{st.get('id')}")
            used_eids |= event_eids(sw, st.get("event"), events, rep)
            scope = StepScope(allow_refs=i > 0, step_names=names, current=i)
            check_where(sw, st.get("where"), scope, fields, rep)
            exports |= scope.exports
            th = st.get("threshold")
            if th:
                tw = check_duration(sw, "threshold.within", th.get("within"), 1_000, 600_000, rep)
                if tw and within and tw > within:
                    rep.err(sw, "threshold.within 不得大於 sequence.within")
                df = th.get("distinct_field")
                if df is not None and df not in fields:
                    rep.err(sw, f"threshold.distinct_field 為未知欄位 '{df}'")
            names[st.get("id")] = i
        if len(names) == 1:
            rep.warn(where, "sequence 只有 1 步：可改寫成單事件規則（event + where）")
    else:
        within = None
        if "within" in doc:
            within = check_duration(where, "within", doc["within"], 30_000, 600_000, rep)
        used_eids |= event_eids(where, doc.get("event"), events, rep)
        check_where(where, doc.get("where"), StepScope(False, {}, 0), fields, rep)
        th = doc.get("threshold")
        if th:
            tw = check_duration(where, "threshold.within", th.get("within"), 1_000, 600_000, rep)
            if tw and tw > (within or 300_000):
                rep.err(where, "threshold.within 不得大於 within（預設 300s）")
        if not doc.get("where") and not th:
            rep.warn(where, "單事件規則沒有 where 也沒有 threshold：該事件型別每筆都會命中")

    if len(exports) > 6:
        rep.err(where, f"匯出綁定 {len(exports)} 個，超過上限 6")

    for i, b in enumerate(doc.get("boosters", []) or []):
        bw = f"{where}.boosters[{i}:{b.get('id')}]"
        used_eids |= event_eids(bw, b.get("event"), events, rep)
        check_where(bw, b.get("where"), StepScope(False, {}, 0), fields, rep)

    # requires_events 與事件型別一致
    if used_eids:
        # 同一事件型別對應多個 EID（例如 FILE_DELETE = 23/26、WMI = 19/20/21）時只要求至少一個
        for ev in set(map(lambda x: str(x).upper(), _all_events(doc))):
            eids = events.get(ev, set())
            if eids and not (eids & req_set):
                rep.err(where, f"用到事件型別 {ev}（EID {sorted(eids)}）但 requires_events 未列出")

    # Sysmon 設定是否會記錄
    enabled, filtered = ctx["sysmon"]
    for eid in sorted(req_set):
        if eid in (4104, 4688):
            continue
        if eid not in enabled:
            rep.err(where, f"requires_events 含 EID {eid}，但 config/sysmon.xml 沒有開啟該事件（規則永遠不會命中）")
        elif eid in filtered and doc.get("status", "dryrun") == "enabled":
            ctx["sysmon_review"].setdefault(eid, set()).add(rid)

    # ATT&CK 白名單
    for a in as_list(doc.get("attack", []) or []):
        if a not in ctx["attack"]:
            rep.err(where, f"attack '{a}' 不在 AttackCatalog 內建白名單（VerdictValidator 會剔除）")



def _all_events(doc: dict) -> list:
    out = []
    if "sequence" in doc:
        for st in doc["sequence"].get("steps", []):
            out += as_list(st.get("event"))
    elif "event" in doc:
        out += as_list(doc["event"])
    for b in doc.get("boosters", []) or []:
        out += as_list(b.get("event"))
    return out


# ---------------------------------------------------------------- schema ↔ C++ 漂移
def check_drift(schema: dict, ctx: dict, rep: Report) -> None:
    s_fields = set(schema["$defs"]["field"]["enum"])
    c_fields = set(ctx["fields"])
    for f in sorted(s_fields - c_fields):
        rep.err("rules/_schema.json", f"schema 允許欄位 '{f}'，但 Fields.cpp 不認得（RuleCompiler 會拒絕）")
    for f in sorted(c_fields - s_fields):
        rep.warn("rules/_schema.json", f"Fields.cpp 支援欄位 '{f}'，schema 卻未列出（CI 會誤擋）")

    s_ev = set(schema["$defs"]["eventType"]["enum"])
    c_ev = set(ctx["events"])
    for e in sorted(s_ev - c_ev):
        rep.err("rules/_schema.json", f"schema 允許事件型別 '{e}'，但 C++ 不認得")
    for e in sorted(c_ev - s_ev):
        rep.warn("rules/_schema.json", f"C++ 支援事件型別 / 別名 '{e}'，schema 卻未列出")


# ---------------------------------------------------------------- 排除清單
EXCL_KINDS = {"path", "path_glob", "sha256", "signer", "rule_id", "cmdline_glob"}


def check_exclusions(rule_ids: set[str], rep: Report) -> None:
    path = p("rules/exclusions.default.yaml")
    where = "rules/exclusions.default.yaml"
    data = yaml.safe_load(read(path)) or {}
    items = data.get("exclusions")
    if not isinstance(items, list):
        rep.err(where, "頂層需為 exclusions: [ ... ]")
        return
    seen = set()
    for i, e in enumerate(items):
        w = f"{where}[{i}]"
        if not isinstance(e, dict):
            rep.err(w, "項目必須是物件")
            continue
        for k in e:
            if k not in ("kind", "value", "scope_rule_id", "reason"):
                rep.err(w, f"未知鍵 '{k}'")
        kind, value = e.get("kind"), e.get("value")
        if kind not in EXCL_KINDS:
            rep.err(w, f"kind '{kind}' 不合法（需為 {sorted(EXCL_KINDS)}）")
        if not value or not str(value).strip():
            rep.err(w, "value 不可為空")
            continue
        value = str(value)
        if not e.get("reason"):
            rep.warn(w, "缺少 reason（稽核需要知道為何排除）")
        scope = e.get("scope_rule_id") or ""
        if scope and scope not in rule_ids:
            rep.err(w, f"scope_rule_id '{scope}' 不存在於 rules/*.yaml")
        if kind == "rule_id" and value not in rule_ids:
            rep.err(w, f"rule_id 排除指向不存在的規則 '{value}'")
        if kind == "signer" and value.strip().lower() in ("microsoft windows", "microsoft corporation",
                                                          "microsoft windows publisher"):
            rep.err(w, f"禁止排除 '{value}' 簽章者：會連帶排除 powershell.exe、rundll32.exe 等 LOLBin")
        if kind == "sha256" and not re.fullmatch(r'[0-9a-fA-F]{64}', value):
            rep.err(w, "sha256 需為 64 個十六進位字元")
        if kind == "path" and any(ch in value for ch in "*?"):
            rep.err(w, "kind=path 不支援萬用字元，請改用 path_glob")
        if kind in ("path_glob", "cmdline_glob") and value.strip() in ("*", "*\\*", "?"):
            rep.err(w, f"{kind} '{value}' 會排除所有東西")
        if kind == "path_glob" and value.startswith("*") and value.count("\\") <= 1:
            rep.warn(w, f"path_glob '{value}' 只靠檔名比對，容易被同名惡意檔案利用")
        key = (kind, value.lower(), scope)
        if key in seen:
            rep.warn(w, f"重複的排除：{kind} {value}")
        seen.add(key)


# ---------------------------------------------------------------- 外部引用
def check_references(rule_ids: set[str], rep: Report) -> None:
    # tests/*.cpp 常內嵌合成規則，不掃；docs 只掃操作文件（設計文件會提到後續里程碑的規則）
    pats = ["tools/*.ps1", "docs/DEMO-SCRIPT.md", "docs/WINDOWS-FIRST-RUN.md", "docs/RULE-DSL.md",
            "tests/fixtures/expected/*.json", "config/*.json"]
    seen: dict[str, set[str]] = {}
    for pat in pats:
        for f in glob.glob(p(pat)):
            for m in re.finditer(r'R-T\d{4}(?:\.\d{3})?-\d{3}\b', read(f)):
                seen.setdefault(m.group(0), set()).add(os.path.relpath(f, ROOT))
    for rid, files in sorted(seen.items()):
        if rid not in rule_ids and not rid.startswith("R-T9"):   # R-T9xxx 為文件中的範例規則
            rep.warn(", ".join(sorted(files)), f"引用規則 {rid}，但 rules/*.yaml 沒有這條")


# ---------------------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--strict", action="store_true", help="警告也視為失敗")
    args = ap.parse_args()

    rep = Report()
    schema = json.loads(read(p("rules/_schema.json")))
    cls = jsonschema.validators.validator_for(schema)
    cls.check_schema(schema)
    validator = cls(schema)

    ctx = {
        "fields": cpp_fields(),
        "events": cpp_event_types(),
        "attack": cpp_attack_whitelist(),
        "sysmon": sysmon_enabled_eids(rep),
        "sysmon_review": {},
    }
    if not ctx["fields"] or not ctx["events"] or not ctx["attack"]:
        print("無法從 C++ 原始碼萃取欄位 / 事件型別 / ATT&CK 清單：檢查腳本的 regex 需要更新", file=sys.stderr)
        return 2
    check_drift(schema, ctx, rep)

    rule_ids: dict[str, str] = {}
    n_rules = 0
    status_count: dict[str, int] = {}
    for f in sorted(glob.glob(p("rules/*.yaml"))):
        base = os.path.basename(f)
        if base.startswith(("exclusions", "_")):
            continue
        rel = os.path.relpath(f, ROOT)
        try:
            docs = list(yaml.safe_load_all(read(f)))
        except yaml.YAMLError as e:
            rep.err(rel, f"YAML 解析失敗：{e}")
            continue
        for doc in docs:
            if doc is None:
                continue
            n_rules += 1
            rid = doc.get("id", "?") if isinstance(doc, dict) else "?"
            where = f"{rel} [{rid}]"
            schema_errors = list(validator.iter_errors(doc))
            for e in schema_errors:
                rep.err(where, f"schema: {'/'.join(map(str, e.path)) or '(root)'}: {e.message[:200]}")
            if not isinstance(doc, dict):
                continue
            if rid in rule_ids:
                rep.err(where, f"規則 id 重複（亦見 {rule_ids[rid]}）")
            rule_ids[rid] = rel
            status_count[doc.get("status", "dryrun")] = status_count.get(doc.get("status", "dryrun"), 0) + 1
            ctx["file"] = f
            check_rule(where, doc, ctx, rep)

    check_exclusions(set(rule_ids), rep)
    check_references(set(rule_ids), rep)

    for line in rep.errors + rep.warnings:
        print(line)

    if ctx["sysmon_review"]:
        print("\nINFO    下列 enabled 規則依賴 sysmon.xml 以 include 篩選的事件，請人工確認 include 條件涵蓋規則要看的值：")
        enabled, filtered = ctx["sysmon"]
        for eid, rids in sorted(ctx["sysmon_review"].items()):
            print(f"          EID {eid}（{filtered[eid]}）← {', '.join(sorted(rids))}")

    st = ", ".join(f"{k}={v}" for k, v in sorted(status_count.items()))
    print(f"\n檢查 {n_rules} 條規則（{st}）：{len(rep.errors)} 個錯誤、{len(rep.warnings)} 個警告")
    if n_rules == 0 or rep.errors or (args.strict and rep.warnings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
