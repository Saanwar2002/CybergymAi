"""Fail-closed authorization and execution-profile checks."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..task import ResearchTask


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str


def authorize_task(task: ResearchTask) -> PolicyDecision:
    """Allow only explicitly approved local fixtures in the offline prototype profile."""
    if task.authorization_status != "approved":
        return PolicyDecision(False, "Task authorization status is not approved.")
    if task.authorization_scope != "local_fixture_only":
        return PolicyDecision(False, "Prototype permits local_fixture_only scope only.")
    if task.source_kind != "local_fixture":
        return PolicyDecision(False, "Prototype permits local_fixture sources only.")
    if task.execution_profile != "offline_readonly":
        return PolicyDecision(False, "Only the offline_readonly profile is supported.")
    if not task.approved_by.strip() or not task.approval_reference.strip():
        return PolicyDecision(False, "Approval metadata is incomplete.")
    if not task.workspace_root:
        return PolicyDecision(False, "Task has no trusted workspace root; reload it from a manifest.")
    try:
        root = Path(task.workspace_root).resolve(strict=True)
        workspace = Path(task.workspace).resolve(strict=True)
        if not root.is_dir() or not workspace.is_dir():
            return PolicyDecision(
            False, "Trusted workspace root and workspace must be directories."
        )
        workspace.relative_to(root)
    except (OSError, RuntimeError, ValueError):
        return PolicyDecision(
            False,
            "Task workspace escapes or cannot be resolved beneath its trusted root.",
        )
    return PolicyDecision(True, "Approved local fixture; execution remains user-opt-in.")
