"""
reporter.py — Multi-format report generator.

Reads violations from the database and produces:
  * violations_report.json   — machine-readable, full detail
  * violations_report.html   — human-readable, styled diff view
  * violations_report.csv    — spreadsheet-compatible flat table

All output files are written to ``config.output_dir``.
"""

import csv
import json
import os
from datetime import datetime
from typing import Dict, List, Optional

from .config import Config, DEFAULT_CONFIG
from .rules_db import RulesDatabase


# ---------------------------------------------------------------------------
# JSON report
# ---------------------------------------------------------------------------

def _build_json_report(db: RulesDatabase) -> Dict:
    summary = db.violation_summary()
    violations = db.get_violations()
    return {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "summary": summary,
        "violations": [
            {
                "id": v["id"],
                "file": v["file_path"],
                "line": v["line_number"],
                "col": v["col_number"],
                "rule_id": v["rule_id"],
                "standard": v["standard"],
                "category": v["category"],
                "description": v["description"],
                "severity": v["severity"],
                "status": v["status"],
                "original": v["snippet"],
                "fixed": v.get("fixed_snippet"),
                "fix_template": v.get("fix_template"),
            }
            for v in violations
        ],
    }


def write_json_report(
    db: RulesDatabase,
    config: Config = DEFAULT_CONFIG,
    filename: str = "violations_report.json",
) -> str:
    """Write the JSON report and return the output path."""
    report = _build_json_report(db)
    path = config.output_path(filename)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    return path


# ---------------------------------------------------------------------------
# CSV report
# ---------------------------------------------------------------------------

_CSV_FIELDS = [
    "id", "file", "line", "col", "rule_id", "standard", "category",
    "description", "severity", "status", "original", "fixed",
]


def write_csv_report(
    db: RulesDatabase,
    config: Config = DEFAULT_CONFIG,
    filename: str = "violations_report.csv",
) -> str:
    """Write the CSV report and return the output path."""
    violations = db.get_violations()
    path = config.output_path(filename)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=_CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for v in violations:
            writer.writerow({
                "id": v["id"],
                "file": v["file_path"],
                "line": v["line_number"],
                "col": v["col_number"],
                "rule_id": v["rule_id"],
                "standard": v["standard"],
                "category": v["category"],
                "description": v["description"],
                "severity": v["severity"],
                "status": v["status"],
                "original": v["snippet"],
                "fixed": v.get("fixed_snippet", ""),
            })
    return path


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

_SEVERITY_COLOR = {
    "Critical": "#c0392b",
    "Major":    "#e67e22",
    "Minor":    "#2980b9",
}

_STATUS_BADGE = {
    "open":           '<span class="badge open">open</span>',
    "auto-fixed":     '<span class="badge fixed">auto-fixed</span>',
    "manual-review":  '<span class="badge manual">manual-review</span>',
}

_HTML_HEAD = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MISRA / AUTOSAR Violations Report</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #f5f6fa; margin: 0; padding: 20px; }}
  h1 {{ color: #2c3e50; }}
  .summary {{ background: #fff; border-radius: 6px; padding: 16px 24px; margin-bottom: 20px;
              box-shadow: 0 1px 4px rgba(0,0,0,0.1); display: flex; gap: 32px; }}
  .stat {{ text-align: center; }}
  .stat .num {{ font-size: 2em; font-weight: bold; }}
  .stat .label {{ font-size: 0.85em; color: #666; }}
  table {{ width: 100%; border-collapse: collapse; background: #fff;
           border-radius: 6px; overflow: hidden;
           box-shadow: 0 1px 4px rgba(0,0,0,0.1); }}
  th {{ background: #2c3e50; color: #fff; padding: 10px 12px; text-align: left; font-size: 0.85em; }}
  td {{ padding: 8px 12px; font-size: 0.82em; border-bottom: 1px solid #eee; vertical-align: top; }}
  tr:hover td {{ background: #f0f4ff; }}
  .sev {{ font-weight: bold; }}
  code {{ background: #eef; padding: 2px 4px; border-radius: 3px; font-size: 0.9em; white-space: pre-wrap; word-break: break-all; }}
  .badge {{ padding: 2px 8px; border-radius: 10px; font-size: 0.78em; font-weight: bold; }}
  .badge.open {{ background: #ffeaa7; color: #856404; }}
  .badge.fixed {{ background: #d4edda; color: #155724; }}
  .badge.manual {{ background: #f8d7da; color: #721c24; }}
  .diff {{ display: flex; gap: 8px; }}
  .diff-orig, .diff-fixed {{ flex: 1; }}
  .diff-orig code {{ background: #fff0f0; }}
  .diff-fixed code {{ background: #f0fff0; }}
  .ts {{ color: #888; font-size: 0.78em; }}
</style>
</head>
<body>
<h1>&#128202; MISRA / AUTOSAR Violations Report</h1>
<p class="ts">Generated: {ts}</p>
"""

_HTML_SUMMARY = """\
<div class="summary">
  <div class="stat"><div class="num">{total}</div><div class="label">Total</div></div>
  <div class="stat"><div class="num" style="color:#c0392b">{open}</div><div class="label">Open</div></div>
  <div class="stat"><div class="num" style="color:#27ae60">{auto_fixed}</div><div class="label">Auto-Fixed</div></div>
  <div class="stat"><div class="num" style="color:#e67e22">{manual_review}</div><div class="label">Manual Review</div></div>
</div>
"""

_HTML_TABLE_OPEN = """\
<table>
<thead>
<tr>
  <th>#</th><th>File</th><th>Line</th><th>Rule</th><th>Standard</th>
  <th>Severity</th><th>Description</th><th>Status</th><th>Original / Fixed</th>
</tr>
</thead>
<tbody>
"""

_HTML_TABLE_CLOSE = "</tbody></table></body></html>\n"


def _esc(text: Optional[str]) -> str:
    if not text:
        return ""
    return (
        text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
    )


def write_html_report(
    db: RulesDatabase,
    config: Config = DEFAULT_CONFIG,
    filename: str = "violations_report.html",
) -> str:
    """Write the HTML report and return the output path."""
    summary = db.violation_summary()
    violations = db.get_violations()
    path = config.output_path(filename)

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(_HTML_HEAD.format(ts=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")))
        fh.write(_HTML_SUMMARY.format(**summary))
        fh.write(_HTML_TABLE_OPEN)

        for v in violations:
            sev = v["severity"]
            color = _SEVERITY_COLOR.get(sev, "#333")
            badge = _STATUS_BADGE.get(v["status"], v["status"])
            orig = _esc(v.get("snippet", ""))
            fixed = _esc(v.get("fixed_snippet", ""))
            diff_html = (
                f'<div class="diff">'
                f'<div class="diff-orig"><small>Original</small><br><code>{orig}</code></div>'
                f'<div class="diff-fixed"><small>Fixed</small><br><code>{fixed or "<em>—</em>"}</code></div>'
                f"</div>"
            )
            fh.write(
                f"<tr>"
                f"<td>{v['id']}</td>"
                f"<td><small>{_esc(v['file_path'])}</small></td>"
                f"<td>{v['line_number']}</td>"
                f"<td><strong>{_esc(v['rule_id'])}</strong></td>"
                f"<td><small>{_esc(v['standard'])}</small></td>"
                f"<td class='sev' style='color:{color}'>{sev}</td>"
                f"<td>{_esc(v['description'])}</td>"
                f"<td>{badge}</td>"
                f"<td>{diff_html}</td>"
                f"</tr>\n"
            )

        fh.write(_HTML_TABLE_CLOSE)

    return path


# ---------------------------------------------------------------------------
# Convenience: write all three formats
# ---------------------------------------------------------------------------

def write_all_reports(
    db: RulesDatabase,
    config: Config = DEFAULT_CONFIG,
) -> Dict[str, str]:
    """Write JSON, CSV and HTML reports; return dict of format → path."""
    return {
        "json": write_json_report(db, config),
        "csv":  write_csv_report(db, config),
        "html": write_html_report(db, config),
    }
