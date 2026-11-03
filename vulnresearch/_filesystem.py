"""Filesystem durability primitives for atomically published audit artifacts."""
from __future__ import annotations

import os
from pathlib import Path


def fsync_directory(path: str | Path) -> None:
    """Persist directory-entry changes after staging or publishing audit artifacts.

    Directory fsync is required in addition to fsyncing file contents: a successful
    rename/link is atomic for concurrent readers, but its name is not guaranteed to
    survive a sudden power loss until the containing directory is synchronized.
    """
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
