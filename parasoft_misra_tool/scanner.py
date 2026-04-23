"""
scanner.py — File-system walker that collects C/C++ source files.

Given a root directory it walks the tree, respects exclude-directory
configuration, and returns an iterable of absolute file paths whose
extension matches the configured set.
"""

import os
from typing import Generator, List

from .config import Config, DEFAULT_CONFIG


def scan_files(
    root: str = "",
    config: Config = DEFAULT_CONFIG,
) -> Generator[str, None, None]:
    """
    Yield absolute paths of every source file found under *root*.

    Parameters
    ----------
    root:
        Directory to walk.  Defaults to ``config.repo_root``.
    config:
        A :class:`Config` instance.  Defaults to :data:`DEFAULT_CONFIG`.
    """
    root = os.path.abspath(root or config.repo_root)
    extensions = {ext.lower() for ext in config.source_extensions}
    exclude = {d.lower() for d in config.exclude_dirs}

    for dirpath, dirnames, filenames in os.walk(root, topdown=True):
        # Prune excluded directories in-place so os.walk doesn't descend.
        dirnames[:] = [
            d for d in dirnames
            if d.lower() not in exclude and not d.startswith(".")
        ]

        for fname in filenames:
            _, ext = os.path.splitext(fname)
            if ext.lower() in extensions:
                yield os.path.join(dirpath, fname)


def collect_files(
    root: str = "",
    config: Config = DEFAULT_CONFIG,
) -> List[str]:
    """Return a sorted list of all source files (convenience wrapper)."""
    return sorted(scan_files(root, config))
