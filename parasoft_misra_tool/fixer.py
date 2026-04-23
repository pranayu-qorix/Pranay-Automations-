"""
fixer.py — Automated patch engine.

For each open violation that has a non-NULL fix_template, this module
attempts to apply a deterministic source-level fix.  Violations that cannot
be automatically fixed are marked "manual-review".

Design
------
Each fixer is a plain function registered with ``@fixer_for("RULE_ID")``.
It receives the original list of lines and the violation record, and returns
either a modified copy of the lines or ``None`` (= cannot fix automatically).

The engine writes patched files back to disk and updates the violation status
in the database.
"""

import os
import re
import shutil
from typing import Callable, Dict, List, Optional, Tuple

from .config import Config, DEFAULT_CONFIG
from .rules_db import RulesDatabase


FixerFn = Callable[[List[str], Dict], Optional[List[str]]]

_FIXERS: Dict[str, FixerFn] = {}


def fixer_for(rule_id: str) -> Callable[[FixerFn], FixerFn]:
    """Decorator: register a fixer for *rule_id*."""
    def decorator(fn: FixerFn) -> FixerFn:
        _FIXERS[rule_id] = fn
        return fn
    return decorator


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _leading_ws(line: str) -> str:
    """Return the leading whitespace of a line."""
    return line[: len(line) - len(line.lstrip())]


def _replace_line(lines: List[str], ln: int, new_content: str) -> List[str]:
    """Return a new lines list with line *ln* (1-based) replaced."""
    result = lines[:]
    result[ln - 1] = new_content + "\n"
    return result


# ---------------------------------------------------------------------------
# Per-rule fixers
# ---------------------------------------------------------------------------

@fixer_for("M15.6")
def fix_M15_6(lines: List[str], v: Dict) -> Optional[List[str]]:
    """Add braces around a single-statement body."""
    ln = v["line_number"]
    if ln < 1 or ln > len(lines):
        return None
    raw = lines[ln - 1]
    indent = _leading_ws(raw)
    # Find the next non-blank line to wrap
    next_ln = ln  # 0-indexed next statement line
    while next_ln < len(lines) and not lines[next_ln].strip():
        next_ln += 1
    if next_ln >= len(lines):
        return None
    stmt = lines[next_ln].rstrip()
    result = lines[:]
    # Replace the control-flow line to add opening brace
    ctrl = raw.rstrip()
    if not ctrl.endswith("{"):
        result[ln - 1] = ctrl + " {\n"
    # Add closing brace after the statement
    result[next_ln] = stmt + "\n" + indent + "}\n"
    return result


@fixer_for("M15.7")
def fix_M15_7(lines: List[str], v: Dict) -> Optional[List[str]]:
    """Append a trailing else {} after the last else-if."""
    # Find the closing brace of the last else-if block
    ln = v["line_number"]
    indent = _leading_ws(lines[ln - 1])
    # Walk forward to find the last else-if's closing brace
    depth = 0
    last_close = ln
    for i in range(ln - 1, min(ln + 100, len(lines))):
        depth += lines[i].count("{") - lines[i].count("}")
        if depth == 0 and i >= ln:
            last_close = i + 1  # 1-based
            break
    result = lines[:]
    result.insert(last_close, indent + "else {\n" + indent + "    /* intentionally empty */\n" + indent + "}\n")
    return result


@fixer_for("M16.4")
def fix_M16_4(lines: List[str], v: Dict) -> Optional[List[str]]:
    """Append a default: clause before the closing brace of the switch."""
    ln = v["line_number"]
    # Find the closing brace of the switch
    depth = 0
    for i in range(ln - 1, len(lines)):
        depth += lines[i].count("{") - lines[i].count("}")
        if depth == 0 and i >= ln:
            indent = _leading_ws(lines[i])
            result = lines[:]
            result.insert(i, indent + "    default:\n" + indent + "        break;\n")
            return result
    return None


@fixer_for("M16.3")
def fix_M16_3(lines: List[str], v: Dict) -> Optional[List[str]]:
    """Add a missing break at end of a case clause."""
    ln = v["line_number"]
    # Find the next case/default/closing brace
    for i in range(ln, min(ln + 50, len(lines))):
        stripped = lines[i].strip()
        if re.match(r"(case\b|default\s*:|\})", stripped):
            indent = _leading_ws(lines[i - 1]) if i > 0 else "    "
            result = lines[:]
            result.insert(i, indent + "break;\n")
            return result
    return None


@fixer_for("M7.3")
def fix_M7_3(lines: List[str], v: Dict) -> Optional[List[str]]:
    """Replace lowercase 'l' suffix with 'L'."""
    ln = v["line_number"]
    raw = lines[ln - 1]
    fixed = re.sub(r"(\b\d+)l\b", r"\1L", raw)
    return _replace_line(lines, ln, fixed.rstrip())


@fixer_for("M7.1")
def fix_M7_1(lines: List[str], v: Dict) -> Optional[List[str]]:
    """Replace octal literal with decimal equivalent."""
    ln = v["line_number"]
    raw = lines[ln - 1]

    def octal_to_dec(m: re.Match) -> str:
        try:
            return str(int(m.group(), 8))
        except ValueError:
            return m.group()

    fixed = re.sub(r"\b0[0-7]+\b", octal_to_dec, raw)
    return _replace_line(lines, ln, fixed.rstrip())


@fixer_for("M11.9")
def fix_M11_9(lines: List[str], v: Dict) -> Optional[List[str]]:
    """Replace integer null pointer 0 with NULL."""
    ln = v["line_number"]
    raw = lines[ln - 1]
    fixed = re.sub(r"(=\s*)0(\s*;)", r"\1NULL\2", raw)
    fixed = re.sub(r"(==\s*)0(\s*)", r"\1NULL\2", fixed)
    return _replace_line(lines, ln, fixed.rstrip())


@fixer_for("D4.10")
def fix_D4_10(lines: List[str], v: Dict) -> Optional[List[str]]:
    """Add include guards to a header file."""
    if not lines:
        return None
    # Derive guard macro from filename
    filename = v.get("file_path", "HEADER_H")
    guard = re.sub(r"[^A-Z0-9]", "_", os.path.basename(filename).upper())
    if not guard.endswith("_"):
        guard += "_"
    result = [f"#ifndef {guard}\n", f"#define {guard}\n", "\n"] + lines + ["\n", f"#endif  /* {guard} */\n"]
    return result


@fixer_for("A4-10-1")
def fix_A4_10_1(lines: List[str], v: Dict) -> Optional[List[str]]:
    """Replace NULL with nullptr."""
    ln = v["line_number"]
    raw = lines[ln - 1]
    fixed = re.sub(r"\bNULL\b", "nullptr", raw)
    return _replace_line(lines, ln, fixed.rstrip())


@fixer_for("A7-1-6")
def fix_A7_1_6(lines: List[str], v: Dict) -> Optional[List[str]]:
    """Convert 'typedef T Name;' to 'using Name = T;'."""
    ln = v["line_number"]
    raw = lines[ln - 1]
    m = re.match(r"(\s*)typedef\s+(.*?)\s+(\w+)\s*;", raw.rstrip())
    if m:
        ws, typ, name = m.group(1), m.group(2), m.group(3)
        fixed = f"{ws}using {name} = {typ};"
        return _replace_line(lines, ln, fixed)
    return None


@fixer_for("A7-1-4")
def fix_A7_1_4(lines: List[str], v: Dict) -> Optional[List[str]]:
    """Remove the register keyword."""
    ln = v["line_number"]
    raw = lines[ln - 1]
    fixed = re.sub(r"\bregister\s+", "", raw)
    return _replace_line(lines, ln, fixed.rstrip())


@fixer_for("A7-2-3")
def fix_A7_2_3(lines: List[str], v: Dict) -> Optional[List[str]]:
    """Convert plain enum to enum class."""
    ln = v["line_number"]
    raw = lines[ln - 1]
    fixed = re.sub(r"\benum\s+(?!class\b)(?!struct\b)", "enum class ", raw)
    return _replace_line(lines, ln, fixed.rstrip())


@fixer_for("M21.3")
def fix_M21_3(lines: List[str], v: Dict) -> Optional[List[str]]:
    """Flag dynamic memory — can only add a comment (non-deterministic fix)."""
    ln = v["line_number"]
    raw = lines[ln - 1]
    indent = _leading_ws(raw)
    comment = indent + "/* MISRA M21.3: replace with static allocation */\n"
    result = lines[:]
    result.insert(ln - 1, comment)
    return result


@fixer_for("A18-5-1")
def fix_A18_5_1(lines: List[str], v: Dict) -> Optional[List[str]]:
    """Flag malloc/free in C++ — add advisory comment."""
    ln = v["line_number"]
    raw = lines[ln - 1]
    indent = _leading_ws(raw)
    comment = indent + "/* AUTOSAR A18-5-1: use new/delete or smart pointers */\n"
    result = lines[:]
    result.insert(ln - 1, comment)
    return result


@fixer_for("M21.6")
def fix_M21_6(lines: List[str], v: Dict) -> Optional[List[str]]:
    """Flag stdio usage — add advisory comment."""
    ln = v["line_number"]
    raw = lines[ln - 1]
    indent = _leading_ws(raw)
    comment = indent + "/* MISRA M21.6: remove stdio from production code */\n"
    result = lines[:]
    result.insert(ln - 1, comment)
    return result


@fixer_for("M18.8")
def fix_M18_8(lines: List[str], v: Dict) -> Optional[List[str]]:
    """Flag VLA usage — add advisory comment."""
    ln = v["line_number"]
    raw = lines[ln - 1]
    indent = _leading_ws(raw)
    comment = indent + "/* MISRA M18.8: replace VLA with fixed-size array */\n"
    result = lines[:]
    result.insert(ln - 1, comment)
    return result


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

def fix_file(
    file_path: str,
    db: RulesDatabase,
    config: Config = DEFAULT_CONFIG,
) -> Tuple[int, int]:
    """
    Apply all available automatic fixes to *file_path*.

    Returns
    -------
    (auto_fixed, manual_review) counts for this file.
    """
    violations = db.get_violations(file_path=file_path, status="open")
    if not violations:
        return 0, 0

    try:
        with open(file_path, encoding="utf-8", errors="replace") as fh:
            original_lines = fh.readlines()
    except OSError:
        return 0, 0

    lines = list(original_lines)
    auto_fixed = 0
    manual_review = 0
    # Apply fixes from last line to first to keep line numbers stable
    violations_sorted = sorted(violations, key=lambda v: v["line_number"], reverse=True)

    for v in violations_sorted:
        rule_id = v["rule_id"]
        fixer = _FIXERS.get(rule_id)
        if fixer is None:
            db.update_violation_status(v["id"], "manual-review")
            manual_review += 1
            continue

        new_lines = fixer(lines, v)
        if new_lines is None:
            db.update_violation_status(v["id"], "manual-review")
            manual_review += 1
        else:
            fixed_snippet = "".join(
                new_lines[max(0, v["line_number"] - 2): v["line_number"] + 2]
            )
            db.update_violation_status(v["id"], "auto-fixed", fixed_snippet)
            lines = new_lines
            auto_fixed += 1

    if config.apply_fixes and lines != original_lines:
        if config.backup_before_fix:
            shutil.copy2(file_path, file_path + ".orig")
        with open(file_path, "w", encoding="utf-8") as fh:
            fh.writelines(lines)

    return auto_fixed, manual_review


def fix_all(
    file_paths: List[str],
    db: RulesDatabase,
    config: Config = DEFAULT_CONFIG,
) -> Tuple[int, int]:
    """Apply fixes to every file and return aggregate (auto_fixed, manual_review)."""
    total_auto = 0
    total_manual = 0
    for fp in file_paths:
        a, m = fix_file(fp, db, config)
        total_auto += a
        total_manual += m
    return total_auto, total_manual
