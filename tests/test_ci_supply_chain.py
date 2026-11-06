"""Regression tests for immutable CI action and container references."""

CI_WORKFLOW = "/".join(
    __file__.replace("\\", "/").split("/")[:-2] + [".github", "workflows", "ci.yml"]
)


def test_github_actions_are_pinned_to_full_commit_shas():
    with open(CI_WORKFLOW, encoding="utf-8") as workflow_file:
        workflow = workflow_file.read()
    action_refs = [
        line.split("uses:", 1)[1].strip().split()[0]
        for line in workflow.splitlines()
        if line.lstrip().startswith("uses:")
    ]

    assert action_refs
    for action_ref in action_refs:
        commit_sha = action_ref.rsplit("@", 1)[-1]
        assert len(commit_sha) == 40
        assert all(character in "0123456789abcdef" for character in commit_sha)


def test_ci_container_images_are_pinned_to_sha256_digests():
    with open(CI_WORKFLOW, encoding="utf-8") as workflow_file:
        workflow = workflow_file.read()
    lines = workflow.splitlines()
    terraform_image = next(
        (
            line.strip().rstrip("\\").strip()
            for line in lines
            if line.strip().startswith("hashicorp/terraform:")
        ),
        None,
    )
    sandbox_assignment = next(
        (
            line.strip()
            for line in lines
            if line.strip().startswith('approved_image="')
        ),
        None,
    )

    assert terraform_image is not None
    assert terraform_image.startswith("hashicorp/terraform:1.9.8@sha256:")
    terraform_digest = terraform_image.split("@sha256:", 1)[1]
    assert len(terraform_digest) == 64
    assert all(character in "0123456789abcdef" for character in terraform_digest)

    assert sandbox_assignment is not None
    sandbox_image = sandbox_assignment[len('approved_image="') : -1]
    assert sandbox_image.startswith("python:3.11-slim@sha256:")
    sandbox_digest = sandbox_image.split("@sha256:", 1)[1]
    assert len(sandbox_digest) == 64
    assert all(character in "0123456789abcdef" for character in sandbox_digest)

    assert 'docker pull "$approved_image"' in workflow
    assert 'echo "VULNRESEARCH_SANDBOX_IMAGE=$approved_image" >> "$GITHUB_ENV"' in workflow
