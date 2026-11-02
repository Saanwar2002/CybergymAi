import subprocess
import sys
from pathlib import Path

from vulnresearch.policy.scope import authorize_task
from vulnresearch.task import ResearchTask


def test_demo_manifests_are_approved_local_fixtures():
    root = Path(__file__).resolve().parents[1]
    for filename in ("baseline_task.json", "candidate_task.json"):
        task = ResearchTask.from_file(
            root / "examples/fixtures/patch_demo" / filename,
            workspace_root=root,
        )
        assert authorize_task(task).allowed
        assert task.task_id == "local-patch-demo-001"


def test_demo_help_is_available_without_docker_execution():
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, str(root / "examples/demo_workflow.py"), "--help"],
        cwd=root,
        capture_output=True,
        check=False,
        text=True,
    )
    assert result.returncode == 0
    assert "--allow-execution" in result.stdout
    assert "--reviewer" in result.stdout
