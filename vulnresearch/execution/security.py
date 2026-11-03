"""Fail-closed independent security-review authorization for benchmark execution.

This module defines the verification boundary only. Deployments must inject a verifier
backed by an independently managed trust store; no permissive verifier is shipped.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from .base import BackendCapabilities, ExecutionSpec


class SecurityReviewError(RuntimeError):
    """Raised when an independent security-review approval is absent or invalid."""


@dataclass(frozen=True)
class SecurityReviewApproval:
    """Signed, scope-bound review attestation supplied by an independent reviewer."""

    review_id: str
    reviewer_id: str
    reviewer_organization: str
    scope: str
    reviewed_commit_sha: str
    execution_spec_sha256: str
    backend_capabilities_sha256: str
    evidence_sha256: str
    issued_at: datetime
    expires_at: datetime
    signature: str

    def __post_init__(self) -> None:
        for field in (
            "review_id",
            "reviewer_id",
            "reviewer_organization",
            "scope",
            "signature",
        ):
            value = getattr(self, field)
            if (
                not isinstance(value, str)
                or not value.strip()
                or value.strip() != value
                or len(value) > 8192
            ):
                raise ValueError(
                    f"{field} must be a trimmed non-empty string of at most 8192 characters"
                )
        if self.scope != "benchmark_execution":
            raise ValueError("security review scope must be benchmark_execution")
        if not re.fullmatch(r"(?:[a-f0-9]{40}|[a-f0-9]{64})", self.reviewed_commit_sha):
            raise ValueError("reviewed_commit_sha must be a lowercase Git commit digest")
        for field in (
            "execution_spec_sha256",
            "backend_capabilities_sha256",
            "evidence_sha256",
        ):
            value = getattr(self, field)
            if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value):
                raise ValueError(f"{field} must be a lowercase 64-character SHA-256 digest")
        for field in ("issued_at", "expires_at"):
            value = getattr(self, field)
            if (
                not isinstance(value, datetime)
                or value.tzinfo is None
                or value.utcoffset() is None
            ):
                raise ValueError(f"{field} must be a timezone-aware datetime")
        if self.expires_at <= self.issued_at:
            raise ValueError("security review expiry must be after its issue time")

    def to_manifest(self) -> dict[str, str]:
        """Return the signed review claims in a canonical JSON-compatible form."""
        return {
            "review_id": self.review_id,
            "reviewer_id": self.reviewer_id,
            "reviewer_organization": self.reviewer_organization,
            "scope": self.scope,
            "reviewed_commit_sha": self.reviewed_commit_sha,
            "execution_spec_sha256": self.execution_spec_sha256,
            "backend_capabilities_sha256": self.backend_capabilities_sha256,
            "evidence_sha256": self.evidence_sha256,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "signature": self.signature,
        }

    @classmethod
    def from_manifest(cls, manifest: dict[str, object]) -> SecurityReviewApproval:
        """Strictly reconstruct an approval record from a benchmark report."""
        expected = {
            "review_id",
            "reviewer_id",
            "reviewer_organization",
            "scope",
            "reviewed_commit_sha",
            "execution_spec_sha256",
            "backend_capabilities_sha256",
            "evidence_sha256",
            "issued_at",
            "expires_at",
            "signature",
        }
        if not isinstance(manifest, dict) or set(manifest) != expected:
            raise ValueError("security review approval has an unsupported schema")
        try:
            approval = cls(
                review_id=manifest["review_id"],
                reviewer_id=manifest["reviewer_id"],
                reviewer_organization=manifest["reviewer_organization"],
                scope=manifest["scope"],
                reviewed_commit_sha=manifest["reviewed_commit_sha"],
                execution_spec_sha256=manifest["execution_spec_sha256"],
                backend_capabilities_sha256=manifest["backend_capabilities_sha256"],
                evidence_sha256=manifest["evidence_sha256"],
                issued_at=datetime.fromisoformat(manifest["issued_at"]),
                expires_at=datetime.fromisoformat(manifest["expires_at"]),
                signature=manifest["signature"],
            )
        except (TypeError, ValueError) as exc:
            raise ValueError(f"security review approval is invalid: {exc}") from exc
        if approval.to_manifest() != manifest:
            raise ValueError("security review approval is not canonically encoded")
        return approval


class IndependentReviewVerifier(Protocol):
    """Trusted deployment adapter for verifying independent reviewer signatures.

    Implementations must verify the signature against an independently managed trust
    store, authenticate the reviewer, establish independence from project maintainers
    and the implementation author, check revocation, and validate the signed scope.
    A verifier must fail closed. The repository intentionally ships no concrete verifier.
    """

    def verify(self, approval: SecurityReviewApproval) -> bool:
        """Return true only when the approval signature and reviewer independence pass."""
        ...


def backend_capabilities_sha256(capabilities: BackendCapabilities) -> str:
    """Hash the canonical backend capability declaration."""
    encoded = json.dumps(
        capabilities.to_manifest(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _assert_review_approval_current(
    approval: SecurityReviewApproval,
    *,
    expired_message: str,
) -> None:
    """Fail closed if an approval is not valid at a trusted authorization boundary."""
    instant = datetime.now(UTC)
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise ValueError("review verification time must be timezone-aware")
    if instant < approval.issued_at:
        raise SecurityReviewError("security review approval is not yet valid")
    if instant >= approval.expires_at:
        raise SecurityReviewError(expired_message)


def verify_independent_review(
    approval: SecurityReviewApproval | None,
    verifier: IndependentReviewVerifier | None,
    *,
    spec: ExecutionSpec,
    capabilities: BackendCapabilities,
    software_commit_sha: str,
    now: datetime | None = None,
) -> SecurityReviewApproval:
    """Require a valid, current, independently verified approval for this exact run."""
    if not isinstance(approval, SecurityReviewApproval):
        raise SecurityReviewError(
            "Benchmark execution is disabled: an independent security-review approval is required."
        )
    if verifier is None or not callable(getattr(verifier, "verify", None)):
        raise SecurityReviewError(
            "Benchmark execution is disabled: no trusted independent-review verifier is configured."
        )
    if not isinstance(software_commit_sha, str) or not re.fullmatch(
        r"[a-f0-9]{40}|[a-f0-9]{64}", software_commit_sha
    ):
        raise SecurityReviewError("software_commit_sha must identify the exact deployed commit")
    if approval.reviewed_commit_sha != software_commit_sha:
        raise SecurityReviewError("security review approval does not cover the deployed commit")
    if approval.execution_spec_sha256 != spec.manifest_sha256:
        raise SecurityReviewError("security review approval does not cover this execution specification")
    if approval.backend_capabilities_sha256 != backend_capabilities_sha256(capabilities):
        raise SecurityReviewError("security review approval does not cover the backend capability claims")

    instant = now or datetime.now(UTC)
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise ValueError("review verification time must be timezone-aware")
    if instant < approval.issued_at or instant >= approval.expires_at:
        raise SecurityReviewError("security review approval is not currently valid")
    try:
        verified = verifier.verify(approval)
    except Exception as exc:
        raise SecurityReviewError("independent security-review verification failed closed") from exc
    if verified is not True:
        raise SecurityReviewError("independent security-review verification failed")
    # Signature/trust-store verification can be slow. Recheck the wall clock
    # immediately before returning authorization so an approval that expires
    # while the verifier is running cannot authorize a later dispatch.
    _assert_review_approval_current(
        approval,
        expired_message="security review approval expired during independent verification",
    )
    return approval
