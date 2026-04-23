"""
analyzer.py — Regex-based static analysis engine.

For each source file the engine runs a catalogue of pattern-based checks,
one per MISRA/AUTOSAR rule.  Matches are written into the violations table
of the rules database.

Architecture note
-----------------
Each check is a plain Python function registered with the ``@check`` decorator.
A check receives the full file content (as a list of lines) and yields
``Finding`` named-tuples.  The engine calls every registered check in order
and stores the findings.

This design makes it straightforward to add new checks without touching the
orchestration code.
"""

import os
import re
from typing import Callable, Generator, List, NamedTuple, Optional

from .config import Config, DEFAULT_CONFIG
from .rules_db import RulesDatabase


# ---------------------------------------------------------------------------
# Finding data-class
# ---------------------------------------------------------------------------
class Finding(NamedTuple):
    rule_id: str
    line_number: int
    col_number: int
    snippet: str


CheckFn = Callable[[List[str], str], Generator[Finding, None, None]]

_CHECKS: List[CheckFn] = []


def check(fn: CheckFn) -> CheckFn:
    """Decorator that registers a function as an analysis check."""
    _CHECKS.append(fn)
    return fn


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------
def _strip_line_comment(line: str) -> str:
    """Remove everything after a // comment (naïve but practical)."""
    idx = line.find("//")
    return line[:idx] if idx != -1 else line


def _is_in_block_comment(lines: List[str], target_line: int) -> bool:
    """Very cheap heuristic: if the cumulative /* count != */ count up to
    target_line we are inside a block comment."""
    text = "\n".join(lines[:target_line])
    return text.count("/*") > text.count("*/")


# ---------------------------------------------------------------------------
# Registered checks — MISRA C:2012
# ---------------------------------------------------------------------------

@check
def check_M15_6(lines: List[str], ext: str) -> Generator[Finding, None, None]:
    """M15.6 — body of if/else/for/while shall be a compound statement (braces)."""
    pattern = re.compile(
        r"^\s*(if|else|for|while)\s*(\(.*\))?\s*(?![\{/])[^\{;]",
        re.IGNORECASE,
    )
    for i, raw in enumerate(lines, start=1):
        line = _strip_line_comment(raw)
        if pattern.match(line) and "{" not in line and not line.strip().startswith("//"):
            # Skip bare "else if" — handled as a single construct
            if re.match(r"^\s*else\s+if\b", line):
                continue
            yield Finding("M15.6", i, 1, raw.rstrip())


@check
def check_M15_7(lines: List[str], ext: str) -> Generator[Finding, None, None]:
    """M15.7 — if...else-if chain shall be terminated with an else."""
    if ext not in (".c", ".cpp", ".cxx", ".cc", ".h", ".hpp"):
        return
    # Collect blocks: look for else-if without a closing else
    i = 0
    while i < len(lines):
        raw = lines[i]
        stripped = raw.strip()
        if re.match(r"\bif\s*\(", stripped):
            # Scan forward to detect else-if chain without bare else
            j = i + 1
            has_else_if = False
            has_else = False
            depth = 0
            while j < len(lines):
                s = lines[j].strip()
                depth += s.count("{") - s.count("}")
                if re.match(r"else\s+if\b", s):
                    has_else_if = True
                elif re.match(r"else\b", s) and "if" not in s:
                    has_else = True
                    break
                elif depth < 0 or (depth == 0 and j > i + 1 and not re.match(r"^\s*(else)", lines[j])):
                    break
                j += 1
            if has_else_if and not has_else:
                yield Finding("M15.7", i + 1, 1, lines[i].rstrip())
        i += 1


@check
def check_M16_4(lines: List[str], ext: str) -> Generator[Finding, None, None]:
    """M16.4 — every switch shall have a default label."""
    in_switch = False
    brace_depth = 0
    switch_brace_depth = 0
    has_default = False
    switch_line = 0

    for i, raw in enumerate(lines, start=1):
        line = _strip_line_comment(raw)
        if re.search(r"\bswitch\s*\(", line):
            in_switch = True
            switch_line = i
            has_default = False
            switch_brace_depth = brace_depth + line.count("{") - line.count("}")
        if in_switch:
            brace_depth += line.count("{") - line.count("}")
            if re.search(r"\bdefault\s*:", line):
                has_default = True
            if brace_depth == switch_brace_depth and brace_depth > 0:
                # The switch block closed
                if not has_default:
                    yield Finding("M16.4", switch_line, 1, lines[switch_line - 1].rstrip())
                in_switch = False
                brace_depth = switch_brace_depth


@check
def check_M16_3(lines: List[str], ext: str) -> Generator[Finding, None, None]:
    """M16.3 — every switch clause shall end with break (no fall-through)."""
    in_switch = False
    in_case = False
    brace_depth = 0
    switch_brace_depth = 0
    case_line = 0
    last_was_break = True

    for i, raw in enumerate(lines, start=1):
        line = _strip_line_comment(raw).strip()
        if re.search(r"\bswitch\s*\(", raw):
            in_switch = True
            switch_brace_depth = brace_depth
            brace_depth += raw.count("{") - raw.count("}")
            continue

        if not in_switch:
            continue

        brace_depth += raw.count("{") - raw.count("}")

        if re.match(r"(case\b.+|default\s*):", line):
            if in_case and not last_was_break:
                yield Finding("M16.3", case_line, 1, lines[case_line - 1].rstrip())
            in_case = True
            case_line = i
            last_was_break = False

        if re.match(r"break\s*;", line) or re.match(r"return\b", line) or re.match(r"continue\b", line):
            last_was_break = True

        if brace_depth <= switch_brace_depth:
            in_switch = False
            in_case = False


@check
def check_M21_3(lines: List[str], ext: str) -> Generator[Finding, None, None]:
    """M21.3 — malloc/calloc/realloc/free shall not be used."""
    pattern = re.compile(r"\b(malloc|calloc|realloc|free)\s*\(")
    for i, raw in enumerate(lines, start=1):
        m = pattern.search(_strip_line_comment(raw))
        if m:
            yield Finding("M21.3", i, m.start() + 1, raw.rstrip())


@check
def check_M21_6(lines: List[str], ext: str) -> Generator[Finding, None, None]:
    """M21.6 — stdio functions (printf/scanf/…) not in production code."""
    pattern = re.compile(
        r"\b(printf|fprintf|sprintf|snprintf|scanf|fscanf|sscanf|puts|gets|fgets|fputs)\s*\("
    )
    for i, raw in enumerate(lines, start=1):
        m = pattern.search(_strip_line_comment(raw))
        if m:
            yield Finding("M21.6", i, m.start() + 1, raw.rstrip())


@check
def check_M17_7(lines: List[str], ext: str) -> Generator[Finding, None, None]:
    """M17.7 — return value of non-void function shall be used."""
    # Heuristic: standalone call statement on its own line that is not a void cast
    pattern = re.compile(r"^\s*(?!\(void\))(?!void\s)\w[\w_]*\s*\(.*\)\s*;")
    known_void_fns = re.compile(
        r"\b(printf|fprintf|sprintf|snprintf|puts|fputs|memcpy|memmove|memset|strcpy|strcat|void)\b"
    )
    for i, raw in enumerate(lines, start=1):
        line = _strip_line_comment(raw)
        if pattern.match(line) and not known_void_fns.search(line):
            if "=" not in line and "return" not in line:
                yield Finding("M17.7", i, 1, raw.rstrip())


@check
def check_M7_3(lines: List[str], ext: str) -> Generator[Finding, None, None]:
    """M7.3 — lowercase 'l' suffix on integer literals."""
    pattern = re.compile(r"\b\d+l\b")
    for i, raw in enumerate(lines, start=1):
        if pattern.search(_strip_line_comment(raw).lower()):
            m = re.search(r"\b\d+l\b", _strip_line_comment(raw), re.IGNORECASE)
            if m and m.group().endswith("l"):
                yield Finding("M7.3", i, m.start() + 1, raw.rstrip())


@check
def check_M7_1(lines: List[str], ext: str) -> Generator[Finding, None, None]:
    """M7.1 — octal constants (leading zero) shall not be used."""
    pattern = re.compile(r"\b0[0-7]+\b")
    for i, raw in enumerate(lines, start=1):
        line = _strip_line_comment(raw)
        m = pattern.search(line)
        if m and not re.match(r"0x", m.group(), re.IGNORECASE):
            yield Finding("M7.1", i, m.start() + 1, raw.rstrip())


@check
def check_M11_9(lines: List[str], ext: str) -> Generator[Finding, None, None]:
    """M11.9 — integer null pointer constant must be NULL not 0."""
    # Look for assignments/comparisons like: ptr = 0; or ptr == 0
    pattern = re.compile(r"\b(\w+\s*(?:=|==|!=)\s*0\s*;|\w+\s*(?:=|==|!=)\s*\(0\))")
    ptr_pattern = re.compile(r"\*|ptr|pointer|Ptr|Pointer", re.IGNORECASE)
    for i, raw in enumerate(lines, start=1):
        line = _strip_line_comment(raw)
        if pattern.search(line) and ptr_pattern.search(line):
            m = pattern.search(line)
            yield Finding("M11.9", i, m.start() + 1, raw.rstrip())


@check
def check_D4_10(lines: List[str], ext: str) -> Generator[Finding, None, None]:
    """D4.10 — header files shall have include guards."""
    if ext not in (".h", ".hpp", ".hxx"):
        return
    text = "\n".join(lines)
    has_guard = bool(
        re.search(r"#\s*ifndef\s+\w+", text)
        or re.search(r"#\s*pragma\s+once", text)
    )
    if not has_guard:
        yield Finding("D4.10", 1, 1, lines[0].rstrip() if lines else "")


@check
def check_M18_8(lines: List[str], ext: str) -> Generator[Finding, None, None]:
    """M18.8 — variable-length arrays (VLAs) shall not be used."""
    pattern = re.compile(r"\w+\s+\w+\s*\[\s*\w+\s*\]\s*;")
    decl_size_pattern = re.compile(r"\[\s*(\d+)\s*\]")
    for i, raw in enumerate(lines, start=1):
        line = _strip_line_comment(raw)
        if pattern.search(line):
            # If the size is a literal number it is NOT a VLA
            if not decl_size_pattern.search(line):
                # Check there's an identifier inside []
                m = re.search(r"\[\s*([A-Za-z_]\w*)\s*\]", line)
                if m:
                    yield Finding("M18.8", i, m.start() + 1, raw.rstrip())


@check
def check_M20_7(lines: List[str], ext: str) -> Generator[Finding, None, None]:
    """M20.7 — macro parameters shall be enclosed in parentheses."""
    in_define = False
    for i, raw in enumerate(lines, start=1):
        line = _strip_line_comment(raw)
        m = re.match(r"#\s*define\s+(\w+)\(([^)]*)\)\s+(.*)", line)
        if m:
            params_str, body = m.group(2), m.group(3)
            params = [p.strip() for p in params_str.split(",") if p.strip()]
            for param in params:
                # Check that every occurrence of param in body is wrapped in ()
                occurrences = list(re.finditer(r"\b" + re.escape(param) + r"\b", body))
                for occ in occurrences:
                    start = occ.start()
                    end = occ.end()
                    pre = body[:start].rstrip()
                    post = body[end:].lstrip()
                    if not (pre.endswith("(") and post.startswith(")")):
                        yield Finding("M20.7", i, 1, raw.rstrip())
                        break


@check
def check_M3_1(lines: List[str], ext: str) -> Generator[Finding, None, None]:
    """M3.1 — /* or // shall not appear within a comment."""
    for i, raw in enumerate(lines, start=1):
        # Look for /* inside a block comment start (nested /*)
        if "/*" in raw:
            # Find first /* and check for another /* after it
            idx = raw.index("/*")
            rest = raw[idx + 2:]
            if "/*" in rest:
                yield Finding("M3.1", i, idx + 1, raw.rstrip())


@check
def check_M17_2(lines: List[str], ext: str) -> Generator[Finding, None, None]:
    """M17.2 — functions shall not call themselves (direct recursion)."""
    # Find function definitions then check if body calls the same function
    fn_def = re.compile(r"^\w[\w\s\*]+\s+(\w+)\s*\([^)]*\)\s*\{?\s*$")
    current_fn: Optional[str] = None
    for i, raw in enumerate(lines, start=1):
        line = _strip_line_comment(raw)
        m = fn_def.match(line)
        if m:
            current_fn = m.group(1)
        if current_fn and re.search(r"\b" + re.escape(current_fn) + r"\s*\(", line):
            # Skip the definition line itself
            if i > 1:
                yield Finding("M17.2", i, 1, raw.rstrip())


# ---------------------------------------------------------------------------
# Registered checks — AUTOSAR C++14
# ---------------------------------------------------------------------------

@check
def check_A5_2_2(lines: List[str], ext: str) -> Generator[Finding, None, None]:
    """A5.2.2 — C-style casts shall not be used."""
    if ext not in (".cpp", ".cxx", ".cc", ".hpp"):
        return
    pattern = re.compile(r"\(\s*[\w\s\*&]+\)\s*\w")
    exclude = re.compile(r"(static_cast|dynamic_cast|reinterpret_cast|const_cast|sizeof|return)")
    for i, raw in enumerate(lines, start=1):
        line = _strip_line_comment(raw)
        if exclude.search(line):
            continue
        m = pattern.search(line)
        if m:
            yield Finding("A5-2-2", i, m.start() + 1, raw.rstrip())


@check
def check_A4_10_1(lines: List[str], ext: str) -> Generator[Finding, None, None]:
    """A4.10.1 — nullptr shall be used for null pointer, not NULL or 0."""
    if ext not in (".cpp", ".cxx", ".cc", ".hpp"):
        return
    pattern = re.compile(r"\bNULL\b")
    for i, raw in enumerate(lines, start=1):
        m = pattern.search(_strip_line_comment(raw))
        if m:
            yield Finding("A4-10-1", i, m.start() + 1, raw.rstrip())


@check
def check_A7_2_3(lines: List[str], ext: str) -> Generator[Finding, None, None]:
    """A7.2.3 — enumerations shall be declared as scoped enum classes."""
    if ext not in (".cpp", ".cxx", ".cc", ".hpp"):
        return
    pattern = re.compile(r"^\s*enum\s+(?!class\b)(?!struct\b)\w+")
    for i, raw in enumerate(lines, start=1):
        m = pattern.match(_strip_line_comment(raw))
        if m:
            yield Finding("A7-2-3", i, 1, raw.rstrip())


@check
def check_A7_1_6(lines: List[str], ext: str) -> Generator[Finding, None, None]:
    """A7.1.6 — typedef specifier shall not be used; use 'using' instead."""
    if ext not in (".cpp", ".cxx", ".cc", ".hpp"):
        return
    pattern = re.compile(r"^\s*typedef\b")
    for i, raw in enumerate(lines, start=1):
        m = pattern.match(_strip_line_comment(raw))
        if m:
            yield Finding("A7-1-6", i, 1, raw.rstrip())


@check
def check_A7_1_4(lines: List[str], ext: str) -> Generator[Finding, None, None]:
    """A7.1.4 — register keyword shall not be used."""
    pattern = re.compile(r"\bregister\b")
    for i, raw in enumerate(lines, start=1):
        m = pattern.search(_strip_line_comment(raw))
        if m:
            yield Finding("A7-1-4", i, m.start() + 1, raw.rstrip())


@check
def check_A18_5_1(lines: List[str], ext: str) -> Generator[Finding, None, None]:
    """A18.5.1 — malloc/calloc/realloc/free shall not be used (C++)."""
    if ext not in (".cpp", ".cxx", ".cc", ".hpp"):
        return
    pattern = re.compile(r"\b(malloc|calloc|realloc|free)\s*\(")
    for i, raw in enumerate(lines, start=1):
        m = pattern.search(_strip_line_comment(raw))
        if m:
            yield Finding("A18-5-1", i, m.start() + 1, raw.rstrip())


@check
def check_A18_1_1(lines: List[str], ext: str) -> Generator[Finding, None, None]:
    """A18.1.1 — C-style arrays shall not be used."""
    if ext not in (".cpp", ".cxx", ".cc", ".hpp"):
        return
    pattern = re.compile(r"\b\w+\s+\w+\s*\[\d*\]\s*(?:=|;)")
    exclude = re.compile(r"(std::|string|vector|array)")
    for i, raw in enumerate(lines, start=1):
        line = _strip_line_comment(raw)
        if pattern.search(line) and not exclude.search(line):
            m = pattern.search(line)
            yield Finding("A18-1-1", i, m.start() + 1, raw.rstrip())


@check
def check_A6_6_1(lines: List[str], ext: str) -> Generator[Finding, None, None]:
    """A6.6.1 — goto shall not be used (C++)."""
    if ext not in (".cpp", ".cxx", ".cc", ".hpp"):
        return
    pattern = re.compile(r"\bgoto\b")
    for i, raw in enumerate(lines, start=1):
        m = pattern.search(_strip_line_comment(raw))
        if m:
            yield Finding("A6-6-1", i, m.start() + 1, raw.rstrip())


@check
def check_M15_1(lines: List[str], ext: str) -> Generator[Finding, None, None]:
    """M15.1 — goto shall not be used (C)."""
    if ext not in (".c", ".h"):
        return
    pattern = re.compile(r"\bgoto\b")
    for i, raw in enumerate(lines, start=1):
        m = pattern.search(_strip_line_comment(raw))
        if m:
            yield Finding("M15.1", i, m.start() + 1, raw.rstrip())


@check
def check_A10_3_2(lines: List[str], ext: str) -> Generator[Finding, None, None]:
    """A10.3.2 — overriding virtual functions shall use 'override' specifier."""
    if ext not in (".cpp", ".cxx", ".cc", ".hpp"):
        return
    # Look for virtual function declarations that are missing override/final
    pattern = re.compile(r"^\s*virtual\b.*\)\s*(?:const\s*)?(?:noexcept\s*)?[^=;{]")
    no_override = re.compile(r"\b(override|final)\b")
    for i, raw in enumerate(lines, start=1):
        line = _strip_line_comment(raw)
        if pattern.match(line) and not no_override.search(line):
            # Skip pure virtuals
            if "= 0" not in line:
                yield Finding("A10-3-2", i, 1, raw.rstrip())


@check
def check_A12_4_1(lines: List[str], ext: str) -> Generator[Finding, None, None]:
    """A12.4.1 — destructor of a base class shall be public virtual."""
    if ext not in (".cpp", ".cxx", ".cc", ".hpp"):
        return
    pattern = re.compile(r"^\s*~\w+\s*\(\s*\)\s*(?:noexcept\s*)?[^=]")
    has_virtual = re.compile(r"\bvirtual\b")
    for i, raw in enumerate(lines, start=1):
        line = _strip_line_comment(raw)
        if pattern.match(line) and not has_virtual.search(line):
            yield Finding("A12-4-1", i, 1, raw.rstrip())


@check
def check_A5_0_2(lines: List[str], ext: str) -> Generator[Finding, None, None]:
    """A5.0.2 — if/while/for condition shall have type bool (C++)."""
    if ext not in (".cpp", ".cxx", ".cc", ".hpp"):
        return
    # Detect integer comparison used as condition without explicit bool cast
    pattern = re.compile(r"\b(if|while)\s*\(\s*\w+\s*\)")
    for i, raw in enumerate(lines, start=1):
        line = _strip_line_comment(raw)
        m = pattern.search(line)
        if m:
            yield Finding("A5-0-2", i, m.start() + 1, raw.rstrip())


@check
def check_A26_5_1(lines: List[str], ext: str) -> Generator[Finding, None, None]:
    """A26.5.1 — std::rand() shall not be used."""
    if ext not in (".cpp", ".cxx", ".cc", ".hpp"):
        return
    pattern = re.compile(r"\b(std::)?rand\s*\(\s*\)")
    for i, raw in enumerate(lines, start=1):
        m = pattern.search(_strip_line_comment(raw))
        if m:
            yield Finding("A26-5-1", i, m.start() + 1, raw.rstrip())


@check
def check_A3_9_1(lines: List[str], ext: str) -> Generator[Finding, None, None]:
    """A3.9.1 — fixed-width integer types (<cstdint>) shall be used."""
    if ext not in (".cpp", ".cxx", ".cc", ".hpp"):
        return
    # Detect raw short/long int that are not already using stdint types
    pattern = re.compile(r"\b(unsigned\s+)?(short|long)\s+(int\s+)?\w+\s*[;=,\)]")
    for i, raw in enumerate(lines, start=1):
        line = _strip_line_comment(raw)
        m = pattern.search(line)
        if m and "int8_t" not in line and "int16_t" not in line and "int32_t" not in line and "int64_t" not in line:
            yield Finding("A3-9-1", i, m.start() + 1, raw.rstrip())


# ---------------------------------------------------------------------------
# Main engine
# ---------------------------------------------------------------------------

def analyse_file(
    file_path: str,
    db: RulesDatabase,
    config: Config = DEFAULT_CONFIG,
) -> List[int]:
    """
    Run all registered checks against *file_path*, store findings in *db*,
    and return the list of inserted violation IDs.
    """
    _, ext = os.path.splitext(file_path)
    ext = ext.lower()

    try:
        with open(file_path, encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return []

    violation_ids: List[int] = []
    for check_fn in _CHECKS:
        for finding in check_fn(lines, ext):
            # Skip rules that are not in the enabled standards
            rule = db.get_rule(finding.rule_id)
            if rule is None:
                continue
            if rule["standard"] not in config.enabled_standards:
                continue
            vid = db.add_violation(
                file_path=file_path,
                line_number=finding.line_number,
                col_number=finding.col_number,
                rule_id=finding.rule_id,
                snippet=finding.snippet,
            )
            violation_ids.append(vid)
    return violation_ids


def analyse_all(
    file_paths: List[str],
    db: RulesDatabase,
    config: Config = DEFAULT_CONFIG,
) -> int:
    """Analyse every file in *file_paths* and return total violations found."""
    total = 0
    for fp in file_paths:
        ids = analyse_file(fp, db, config)
        total += len(ids)
    return total
