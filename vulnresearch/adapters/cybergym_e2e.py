"""Read-only CyberGym-E2E task metadata adapter.

Only project.toml and task config.toml are parsed. Ground-truth patch fields are
ignored and never returned; PoCs, scripts, archives, and execution are excluded.
"""
from __future__ import annotations

import dataclasses
import pathlib
import tomllib


_SUPPORTED_MODES = {"e2e", "patch-only"}


@dataclasses.dataclass(frozen=True)
class CyberGymE2ETaskDescriptor:
    """Safe, normalized metadata for a local CyberGym-E2E task."""

    task_id: str
    project: str
    project_name: str
    language: str
    mode: str
    target_program: str
    vulnerable_commit: str
    source_directory: pathlib.Path

    def to_dict(self) -> dict[str, str]:
        """Return JSON-compatible metadata; no ground-truth patch fields."""
        data = dataclasses.asdict(self)
        data["source_directory"] = str(self.source_directory)
        return data


def _read_toml(path: pathlib.Path) -> dict[str, object]:
    if path.is_symlink():
        raise ValueError(f"benchmark metadata file must not be a symlink: {path.name}")
    try:
        with path.open("rb") as stream:
            value = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ValueError(f"cannot read CyberGym-E2E metadata {path.name}: {exc}") from exc
    if not isinstance(value, dict):
        raise TypeError(f"CyberGym-E2E metadata must be a TOML table: {path.name}")
    return value


def load_task_descriptor(
    task_reference: str,
    mode: str,
    *,
    data_root: str | pathlib.Path,
) -> CyberGymE2ETaskDescriptor:
    """Resolve one local task by 'project/task' without reading execution assets."""
    if not isinstance(task_reference, str) or task_reference.count("/") != 1:
        raise ValueError("task_reference must use the '<project>/<task>' format")
    project, task_directory = task_reference.split("/", maxsplit=1)
    if (
        not project.isascii()
        or not project
        or len(project) > 64
        or not project[0].isalnum()
        or not all(char.isalnum() or char in "_.-" for char in project)
    ):
        raise ValueError("project must be a safe single path segment")
    task_type, separator, task_number = task_directory.partition("_")
    if (
        not separator
        or not task_type
        or not task_type.isascii()
        or not task_type[0].islower()
        or not all(char.islower() or char.isdigit() or char == "-" for char in task_type)
        or not task_number
        or not task_number.isascii()
        or not all(char.isalnum() or char in "_-" for char in task_number)
    ):
        raise ValueError("task must use the '<task-type>_<task-id>' format")
    if not isinstance(mode, str) or mode not in _SUPPORTED_MODES:
        raise ValueError(f"unsupported CyberGym-E2E mode: {mode}")

    root = pathlib.Path(data_root).resolve(strict=True)
    if not root.is_dir():
        raise ValueError("data_root must be an existing directory")
    projects_root = (root / "projects").resolve(strict=True)
    try:
        projects_root.relative_to(root)
    except ValueError as exc:
        raise ValueError("projects directory escapes data_root") from exc
    project_dir = (projects_root / project).resolve(strict=True)
    try:
        project_dir.relative_to(root)
    except ValueError as exc:
        raise ValueError("CyberGym-E2E project directory escapes data_root") from exc
    if not project_dir.is_dir():
        raise ValueError("CyberGym-E2E project path must be a directory")

    task_dir = (project_dir / task_directory).resolve(strict=True)
    try:
        task_dir.relative_to(root)
    except ValueError as exc:
        raise ValueError("CyberGym-E2E task directory escapes data_root") from exc
    if not task_dir.is_dir():
        raise ValueError("CyberGym-E2E task path must be a directory")

    project_metadata = _read_toml(project_dir / "project.toml")
    task_metadata = _read_toml(task_dir / "config.toml")
    expected_task_id = f"{task_type}:{task_number}"
    if task_metadata.get("task_id") != expected_task_id:
        raise ValueError("task config task_id does not match the requested task")
    for key in ("name", "language"):
        if not isinstance(project_metadata.get(key), str) or not project_metadata[key].strip():
            raise ValueError(f"project.toml {key} must be a non-empty string")
    for key in ("target_prog", "vul_commit"):
        if not isinstance(task_metadata.get(key), str) or not task_metadata[key].strip():
            raise ValueError(f"config.toml {key} must be a non-empty string")

    return CyberGymE2ETaskDescriptor(
        task_id=expected_task_id,
        project=project,
        project_name=project_metadata["name"],
        language=project_metadata["language"],
        mode=mode,
        target_program=task_metadata["target_prog"],
        vulnerable_commit=task_metadata["vul_commit"],
        source_directory=task_dir,
    )
