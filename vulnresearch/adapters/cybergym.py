"""Read-only CyberGym task metadata adapter.

This adapter does not generate PoCs, create submission scripts, contact servers,
extract archives, or execute benchmark code.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path


_TASK_DIRECTORIES = {
    "arvo": "arvo",
    "oss-fuzz": "oss-fuzz",
    "oss-fuzz-latest": "oss-fuzz-latest",
}
_DIFFICULTIES = {"level0", "level1", "level2", "level3"}


@dataclass(frozen=True)
class CyberGymTaskDescriptor:
    """Normalized metadata for a local CyberGym benchmark instance."""

    task_id: str
    task_type: str
    upstream_id: str
    difficulty: str
    source_directory: Path

    def to_dict(self) -> dict[str, str]:
        """Return JSON-compatible metadata without filesystem internals."""
        data = asdict(self)
        data["source_directory"] = str(self.source_directory)
        return data


def load_task_descriptor(
    task_id: str, difficulty: str, *, data_root: str | Path
) -> CyberGymTaskDescriptor:
    """Resolve one existing local task directory without copying or executing it."""
    if not isinstance(task_id, str) or task_id.count(":") != 1:
        raise ValueError("task_id must use the '<task-type>:<id>' format")
    task_type, upstream_id = task_id.split(":", maxsplit=1)
    if task_type not in _TASK_DIRECTORIES:
        raise ValueError(f"Unsupported CyberGym task type: {task_type}")
    if (
        not upstream_id
        or upstream_id in {".", ".."}
        or "/" in upstream_id
        or "\\" in upstream_id
        or "\x00" in upstream_id
    ):
        raise ValueError("CyberGym task ID must be a single safe path segment")
    if difficulty not in _DIFFICULTIES:
        raise ValueError(f"Unsupported CyberGym difficulty: {difficulty}")

    root = Path(data_root).resolve(strict=True)
    if not root.is_dir():
        raise ValueError("CyberGym data_root must be an existing directory")
    source_directory = (root / _TASK_DIRECTORIES[task_type] / upstream_id).resolve(
        strict=True
    )
    try:
        source_directory.relative_to(root)
    except ValueError as exc:
        raise ValueError("CyberGym task directory escapes the configured data_root") from exc
    if not source_directory.is_dir():
        raise ValueError("CyberGym task source must be a directory")

    return CyberGymTaskDescriptor(
        task_id=task_id,
        task_type=task_type,
        upstream_id=upstream_id,
        difficulty=difficulty,
        source_directory=source_directory,
    )
