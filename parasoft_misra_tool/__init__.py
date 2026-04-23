"""
parasoft_misra_tool — MISRA / AUTOSAR Violation Analyzer & Auto-Fix Tool.

Import the public API:

    from parasoft_misra_tool import Config, RulesDatabase, analyse_all, fix_all, write_all_reports
"""

from .config import Config, DEFAULT_CONFIG
from .rules_db import RulesDatabase
from .scanner import scan_files, collect_files
from .analyzer import analyse_file, analyse_all
from .fixer import fix_file, fix_all
from .reporter import write_json_report, write_csv_report, write_html_report, write_all_reports

__all__ = [
    "Config",
    "DEFAULT_CONFIG",
    "RulesDatabase",
    "scan_files",
    "collect_files",
    "analyse_file",
    "analyse_all",
    "fix_file",
    "fix_all",
    "write_json_report",
    "write_csv_report",
    "write_html_report",
    "write_all_reports",
]
