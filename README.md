# Pranay-Automations — Parasoft MISRA / AUTOSAR Violation Analyzer & Auto-Fix Tool

A Python-based static analysis tool that reads local C/C++ source files,
checks them against a built-in database of **MISRA C:2012** and
**AUTOSAR C++14** rules, records every violation, applies deterministic
auto-fixes where possible, and generates JSON / HTML / CSV reports — all
working directly inside your local VS Code repository.

---

## Features

| Capability | Details |
|---|---|
| **Rules database** | ~170 MISRA C:2012 rules + ~200 AUTOSAR C++14 guidelines stored in SQLite |
| **Static analysis** | Regex-based checks for the most common rule violations |
| **Auto-fix engine** | Deterministic fixes applied back to source files (with `.orig` backup) |
| **Reports** | JSON · HTML (styled diff view) · CSV |
| **VS Code friendly** | Works on any local project directory; respects `.git`, `build/`, etc. |
| **Zero dependencies** | Standard-library Python only (3.8+) |

---

## Quick Start

```bash
# 1. Clone / open your project in VS Code
cd /path/to/my_project

# 2. Run a scan (reports written to ./reports/)
python -m parasoft_misra_tool --input .

# 3. Run scan AND apply auto-fixes
python -m parasoft_misra_tool --input . --fix

# 4. Scan a single file
python -m parasoft_misra_tool --input src/motor_ctrl.c

# 5. Try the bundled sample violations
python -m parasoft_misra_tool --input samples/ --fix --fresh
```

---

## Project Layout

```
parasoft_misra_tool/
├── __init__.py      # Public API
├── config.py        # Paths, file extensions, runtime defaults
├── rules_db.py      # SQLite schema + full MISRA/AUTOSAR rules catalogue + query API
├── scanner.py       # Walk directory tree, collect .c/.cpp/.h files
├── analyzer.py      # Pattern-based violation detection engine
├── fixer.py         # Auto-fix engine — patches source files in-place
├── reporter.py      # JSON / HTML / CSV report generator
└── main.py          # CLI entry-point

samples/
├── sample_violations.c    # C file with intentional MISRA violations
└── sample_violations.cpp  # C++ file with AUTOSAR violations
```

---

## CLI Reference

```
python -m parasoft_misra_tool [OPTIONS]

Options:
  --input  PATH         Root dir or single file to scan (default: cwd)
  --output DIR          Report output directory (default: ./reports)
  --db     FILE         SQLite DB path (auto-created)
  --standards STD[,STD] MISRA_C_2012 | AUTOSAR_CPP14 | both (default)
  --min-severity SEV    Critical | Major | Minor (default: Minor)
  --fix                 Apply auto-fixes to source files
  --no-backup           Skip .orig backup when using --fix
  --fresh               Clear previous violations before scan
  --list-rules STD      Print all rules for a standard and exit
  --no-html             Skip HTML report
  --no-csv              Skip CSV report
  --quiet / -q          Suppress progress output
```

---

## Database Schema

```sql
-- All MISRA C:2012 and AUTOSAR C++14 rules
CREATE TABLE rules (
    rule_id      TEXT PRIMARY KEY,   -- e.g. "M15.5", "A5-0-2"
    standard     TEXT,               -- "MISRA_C_2012" | "AUTOSAR_CPP14"
    category     TEXT,               -- "Mandatory" | "Required" | "Advisory"
    description  TEXT,
    rationale    TEXT,
    severity     TEXT,               -- "Critical" | "Major" | "Minor"
    fix_template TEXT                -- automated fix description or NULL
);

-- Violations recorded during each scan
CREATE TABLE violations (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    file_path    TEXT,
    line_number  INTEGER,
    col_number   INTEGER,
    rule_id      TEXT REFERENCES rules(rule_id),
    snippet      TEXT,
    status       TEXT,               -- "open" | "auto-fixed" | "manual-review"
    fixed_snippet TEXT,
    scan_ts      DATETIME
);
```

---

## Sample Report Output

```json
{
  "summary": { "total": 12, "open": 4, "auto_fixed": 6, "manual_review": 2 },
  "violations": [
    {
      "file": "samples/sample_violations.c",
      "line": 22,
      "rule_id": "M7.1",
      "description": "Octal constants shall not be used.",
      "severity": "Major",
      "status": "auto-fixed",
      "original":  "int permissions = 0755;",
      "fixed":     "int permissions = 493;"
    }
  ]
}
```

---

## Python API

```python
from parasoft_misra_tool import Config, RulesDatabase, collect_files, analyse_all, fix_all, write_all_reports

config = Config(repo_root="/path/to/project", apply_fixes=True)
db     = RulesDatabase(config.db_path)
db.clear_violations()

files  = collect_files(config=config)
analyse_all(files, db, config)
fix_all(files, db, config)
paths  = write_all_reports(db, config)
print(paths)  # {'json': '...', 'csv': '...', 'html': '...'}
```

---

## Extending the Tool

* **Add a new rule check** — Decorate a function with `@check` in `analyzer.py`.
* **Add a new auto-fix** — Decorate a function with `@fixer_for("RULE_ID")` in `fixer.py`.
* **Add more rules to the DB** — Append a tuple to the `RULES` list in `rules_db.py`.
