"""
main.py — CLI entry-point for the Parasoft MISRA/AUTOSAR Violation Analyzer.

Usage
-----
    python -m parasoft_misra_tool [OPTIONS]

or, if the tool is installed as a script:

    misra-check [OPTIONS]

Examples
--------
    # Scan the current directory; write reports to ./reports/
    python -m parasoft_misra_tool

    # Scan a specific VS Code project and apply fixes
    python -m parasoft_misra_tool --input /home/user/my_project --fix

    # Limit to MISRA C only and Critical violations
    python -m parasoft_misra_tool --standards MISRA_C_2012 --min-severity Critical

    # Scan a single file
    python -m parasoft_misra_tool --input /home/user/src/motor.c

    # Print rules summary for a standard
    python -m parasoft_misra_tool --list-rules AUTOSAR_CPP14
"""

import argparse
import os
import sys
import textwrap
from typing import List

from .config import Config
from .rules_db import RulesDatabase
from .scanner import collect_files
from .analyzer import analyse_all
from .fixer import fix_all
from .reporter import write_all_reports


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="misra-check",
        description="Parasoft MISRA / AUTOSAR C++ Violation Analyzer & Auto-Fix Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(__doc__ or ""),
    )

    parser.add_argument(
        "--input", "-i",
        metavar="PATH",
        default="",
        help=(
            "Root directory or single file to scan. "
            "Defaults to the current working directory."
        ),
    )
    parser.add_argument(
        "--output", "-o",
        metavar="DIR",
        default="reports",
        help="Directory where reports are written (default: ./reports).",
    )
    parser.add_argument(
        "--db",
        metavar="FILE",
        default="",
        help="Path to the SQLite rules/violations database (auto-created if absent).",
    )
    parser.add_argument(
        "--standards",
        metavar="STD[,STD]",
        default="MISRA_C_2012,AUTOSAR_CPP14",
        help=(
            "Comma-separated list of standards to enable. "
            "Choices: MISRA_C_2012, AUTOSAR_CPP14 (default: both)."
        ),
    )
    parser.add_argument(
        "--min-severity",
        metavar="SEV",
        default="Minor",
        choices=["Critical", "Major", "Minor"],
        help="Minimum severity to include (Critical | Major | Minor, default: Minor).",
    )
    parser.add_argument(
        "--fix",
        action="store_true",
        default=False,
        help="Apply auto-fixes to source files (creates .orig backup by default).",
    )
    parser.add_argument(
        "--no-backup",
        action="store_true",
        default=False,
        help="Do not create .orig backups when --fix is specified.",
    )
    parser.add_argument(
        "--list-rules",
        metavar="STD",
        default="",
        help="Print all rules for a given standard then exit (MISRA_C_2012 | AUTOSAR_CPP14).",
    )
    parser.add_argument(
        "--fresh",
        action="store_true",
        default=False,
        help="Clear previous violations before scanning.",
    )
    parser.add_argument(
        "--no-html",
        action="store_true",
        default=False,
        help="Skip HTML report generation.",
    )
    parser.add_argument(
        "--no-csv",
        action="store_true",
        default=False,
        help="Skip CSV report generation.",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        default=False,
        help="Suppress progress output.",
    )
    return parser


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _log(msg: str, quiet: bool = False) -> None:
    if not quiet:
        print(msg, flush=True)


def _list_rules(db: RulesDatabase, standard: str, quiet: bool) -> None:
    rules = db.get_rules(standard=standard)
    if not rules:
        print(f"No rules found for standard '{standard}'.", file=sys.stderr)
        sys.exit(1)
    print(f"\n{'Rule ID':<12} {'Category':<12} {'Severity':<10} Description")
    print("-" * 90)
    for r in rules:
        desc = r["description"]
        if len(desc) > 60:
            desc = desc[:57] + "..."
        print(f"{r['rule_id']:<12} {r['category']:<12} {r['severity']:<10} {desc}")
    print(f"\nTotal: {len(rules)} rules for {standard}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv: List[str] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    # ------------------------------------------------------------------
    # Build Config
    # ------------------------------------------------------------------
    input_path = os.path.abspath(args.input) if args.input else os.getcwd()
    config = Config(
        repo_root=input_path if os.path.isdir(input_path) else os.path.dirname(input_path),
        output_dir=args.output,
        db_path=args.db or os.path.join(args.output, "misra_autosar.db"),
        enabled_standards=[s.strip() for s in args.standards.split(",")],
        min_severity=args.min_severity,
        apply_fixes=args.fix,
        backup_before_fix=not args.no_backup,
    )

    os.makedirs(config.output_dir, exist_ok=True)

    # ------------------------------------------------------------------
    # Initialise database
    # ------------------------------------------------------------------
    _log(f"[DB]      Initialising rules database: {config.db_path}", args.quiet)
    db = RulesDatabase(config.db_path)

    # ------------------------------------------------------------------
    # --list-rules early exit
    # ------------------------------------------------------------------
    if args.list_rules:
        _list_rules(db, args.list_rules, args.quiet)
        return 0

    # ------------------------------------------------------------------
    # Optional: clear previous violations
    # ------------------------------------------------------------------
    if args.fresh:
        _log("[DB]      Clearing previous violations.", args.quiet)
        db.clear_violations()

    # ------------------------------------------------------------------
    # Scan
    # ------------------------------------------------------------------
    if os.path.isfile(input_path):
        files = [input_path]
    else:
        _log(f"[SCAN]    Walking '{input_path}' for source files ...", args.quiet)
        files = collect_files(input_path, config)

    _log(f"[SCAN]    Found {len(files)} source file(s).", args.quiet)

    if not files:
        _log("[WARN]    No source files found. Nothing to analyse.", args.quiet)
        return 0

    # ------------------------------------------------------------------
    # Analyse
    # ------------------------------------------------------------------
    _log("[ANALYSE] Running MISRA / AUTOSAR checks ...", args.quiet)
    total_violations = analyse_all(files, db, config)
    _log(f"[ANALYSE] {total_violations} violation(s) recorded.", args.quiet)

    # ------------------------------------------------------------------
    # Fix
    # ------------------------------------------------------------------
    if args.fix:
        _log("[FIX]     Applying automatic fixes ...", args.quiet)
        auto_fixed, manual_review = fix_all(files, db, config)
        _log(f"[FIX]     Auto-fixed: {auto_fixed}  |  Manual review: {manual_review}", args.quiet)
    else:
        _log("[FIX]     Skipping fix phase (use --fix to enable).", args.quiet)

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------
    _log("[REPORT]  Generating reports ...", args.quiet)
    from .reporter import write_json_report, write_csv_report, write_html_report

    paths = {}
    paths["json"] = write_json_report(db, config)
    if not args.no_csv:
        paths["csv"] = write_csv_report(db, config)
    if not args.no_html:
        paths["html"] = write_html_report(db, config)

    _log("[REPORT]  Reports written:", args.quiet)
    for fmt, p in paths.items():
        _log(f"          {fmt.upper()}: {p}", args.quiet)

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    summary = db.violation_summary()
    _log(
        f"\n{'='*60}\n"
        f"  SUMMARY\n"
        f"  Total violations : {summary['total']}\n"
        f"  Open             : {summary['open']}\n"
        f"  Auto-fixed       : {summary['auto_fixed']}\n"
        f"  Manual review    : {summary['manual_review']}\n"
        f"{'='*60}",
        args.quiet,
    )

    return 0 if summary["open"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
