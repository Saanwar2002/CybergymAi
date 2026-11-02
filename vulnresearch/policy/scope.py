"""Fail-closed authorization and execution-profile checks."""
from __future__ import annotations

from dataclasses import dataclass

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
    return PolicyDecision(True, "Approved local fixture; execution remains user-opt-in.")
