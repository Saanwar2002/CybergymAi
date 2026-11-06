"""Regression tests for immutable CI action and container references."""

import re
from pathlib import Path


CI_WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ci.yml"


def test_github_actions_are_pinned_to_full_commit_shas():
    workflow = CI_WORKFLOW.read_text(encoding="utf-8")
    action_refs = re.findall(r"^\s*uses:\s*(\S+)", workflow, flags=re.MULTILINE)

    assert action_refs
    assert all(
        re.search(r"@[0-9a-f]{40}$", action_ref)
        for action_ref in action_refs
    )


def test_ci_container_images_are_pinned_to_sha256_digests():
    workflow = CI_WORKFLOW.read_text(encoding="utf-8")
    terraform_image = re.search(
        r"^\s*(hashicorp/terraform:\S+)\s*\\?$",
        workflow,
        flags=re.MULTILINE,
    )
    sandbox_image = re.search(
        r'^\s*approved_image="([^"]+)"$',
        workflow,
        flags=re.MULTILINE,
    )

    assert terraform_image is not None
    assert re.fullmatch(
        r"hashicorp/terraform:1\.9\.8@sha256:[0-9a-f]{64}",
        terraform_image.group(1),
    )
    assert sandbox_image is not None
    assert re.fullmatch(
        r"python:3\.11-slim@sha256:[0-9a-f]{64}",
        sandbox_image.group(1),
    )
    assert 'docker pull "$approved_image"' in workflow
    assert 'echo "VULNRESEARCH_SANDBOX_IMAGE=$approved_image" >> "$GITHUB_ENV"' in workflow
