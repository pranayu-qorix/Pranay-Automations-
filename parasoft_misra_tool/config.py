"""
config.py — Central configuration for the Parasoft MISRA/AUTOSAR tool.

All paths, file-extension filters, and runtime defaults are defined here.
Override any value via environment variables or by passing a Config instance
to the individual modules.
"""

import os
from dataclasses import dataclass, field
from typing import List


@dataclass
class Config:
    # Root of the local VS Code / source repository to analyse
    repo_root: str = os.environ.get("MISRA_REPO_ROOT", os.getcwd())

    # File extensions to include in the scan
    source_extensions: List[str] = field(
        default_factory=lambda: [".c", ".cpp", ".cxx", ".cc", ".h", ".hpp"]
    )

    # Directories to skip while walking the tree
    exclude_dirs: List[str] = field(
        default_factory=lambda: [
            ".git", ".svn", "build", "cmake-build-debug",
            "cmake-build-release", "out", "bin", "obj", "__pycache__",
        ]
    )

    # Where the SQLite rules/violations database lives
    db_path: str = os.environ.get(
        "MISRA_DB_PATH",
        os.path.join(os.path.dirname(__file__), "misra_autosar.db"),
    )

    # Directory where reports are written
    output_dir: str = os.environ.get("MISRA_OUTPUT_DIR", "reports")

    # Comma-separated list of standards to enable: MISRA_C_2012, AUTOSAR_CPP14
    enabled_standards: List[str] = field(
        default_factory=lambda: ["MISRA_C_2012", "AUTOSAR_CPP14"]
    )

    # Minimum severity to report: Critical, Major, Minor
    min_severity: str = "Minor"

    # Whether the fixer should write patched files back to disk
    apply_fixes: bool = False

    # Create a backup (<file>.orig) before overwriting during fix
    backup_before_fix: bool = True

    def output_path(self, filename: str) -> str:
        """Return absolute path inside the configured output directory."""
        os.makedirs(self.output_dir, exist_ok=True)
        return os.path.join(self.output_dir, filename)


# Module-level default instance — most callers can just import this.
DEFAULT_CONFIG = Config()
