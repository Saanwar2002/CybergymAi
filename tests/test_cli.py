"""CLI policy and explicit human execution-approval tests."""
import json
import sys
from types import SimpleNamespace

import pytest

from vulnresearch import cli


def _approved_task(monkeypatch):
    task = SimpleNamespace(name="approved fixture", description="safe local fixture")
    monkeypatch.setattr(cli.ResearchTask, "from_file", lambda _path: task)
    monkeypatch.setattr(
        cli,
        "authorize_task",
        lambda _task: SimpleNamespace(allowed=True, reason="approved local fixture"),
    )
    return task


def test_plan_action_is_advisory_and_never_executes(monkeypatch, capsys):
    _approved_task(monkeypatch)
    plan = SimpleNamespace(to_dict=lambda: {"objective": "advisory only"})
    monkeypatch.setattr(cli, "create_plan", lambda _name, _description: plan)
    monkeypatch.setattr(
        cli, "run_task", lambda _task: pytest.fail("plan must never execute a task")
    )
    monkeypatch.setattr(
        sys, "argv", ["vulnresearch", "plan", "task.json"]
    )

    cli.main()

    assert json.loads(capsys.readouterr().out) == {"objective": "advisory only"}


def test_run_without_explicit_opt_in_never_executes(monkeypatch):
    _approved_task(monkeypatch)
    monkeypatch.setattr(
        cli, "run_task", lambda _task: pytest.fail("execution opt-in is required")
    )
    monkeypatch.setattr(sys, "argv", ["vulnresearch", "run", "task.json"])

    with pytest.raises(SystemExit) as error:
        cli.main()

    assert error.value.code == 2


def test_policy_denial_blocks_run_even_with_explicit_opt_in(monkeypatch):
    task = SimpleNamespace(name="unapproved fixture", description="out of scope")
    monkeypatch.setattr(cli.ResearchTask, "from_file", lambda _path: task)
    monkeypatch.setattr(
        cli,
        "authorize_task",
        lambda _task: SimpleNamespace(allowed=False, reason="scope denied"),
    )
    monkeypatch.setattr(
        cli, "run_task", lambda _task: pytest.fail("denied task must not execute")
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["vulnresearch", "run", "task.json", "--allow-execution"],
    )

    with pytest.raises(SystemExit) as error:
        cli.main()

    assert error.value.code == 2


def test_run_executes_only_after_policy_and_explicit_opt_in(
    monkeypatch, capsys, tmp_path
):
    task = _approved_task(monkeypatch)
    calls = []
    result = SimpleNamespace(
        returncode=0,
        stdout="fixture passed",
        stderr="",
        stdout_truncated=False,
        stderr_truncated=False,
        duration_seconds=0.25,
    )
    monkeypatch.setattr(cli, "run_task", lambda selected: calls.append(selected) or result)
    report_path = tmp_path / "run-report.json"
    monkeypatch.setattr(
        cli,
        "write_run_report",
        lambda selected, run_result, output_dir: report_path,
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "vulnresearch",
            "run",
            "task.json",
            "--allow-execution",
            "--output-dir",
            str(tmp_path),
        ],
    )

    cli.main()

    output = json.loads(capsys.readouterr().out)
    assert calls == [task]
    assert output["returncode"] == 0
    assert output["stdout"] == "fixture passed"
    assert output["report"] == str(report_path)


def test_plan_policy_denial_prevents_provider_use_and_execution(monkeypatch):
    task = SimpleNamespace(name="unapproved fixture", description="out of scope")
    monkeypatch.setattr(cli.ResearchTask, "from_file", lambda _path: task)
    monkeypatch.setattr(
        cli,
        "authorize_task",
        lambda _task: SimpleNamespace(allowed=False, reason="scope denied"),
    )
    monkeypatch.setattr(
        cli,
        "create_plan",
        lambda *_args: pytest.fail("denied task must not reach the planner"),
    )
    monkeypatch.setattr(
        cli, "run_task", lambda _task: pytest.fail("plan must never execute")
    )
    monkeypatch.setattr(sys, "argv", ["vulnresearch", "plan", "task.json"])

    with pytest.raises(SystemExit) as error:
        cli.main()

    assert error.value.code == 2


def _image_manifest():
    return {
        "image_self_link": "projects/cybergym-canary/global/images/cybergym-canary-v1",
        "source_image_self_link": "projects/cybergym-base/global/images/ubuntu-2404-v1",
        "build_commit": "a" * 40,
        "build_id": "build-2026-11-06.1",
        "artifact_sha256": "b" * 64,
        "provenance_uri": "https://attestations.example.invalid/build-1",
        "vulnerability_scan": {
            "scanner": "approved-scanner",
            "scanned_at": "2026-11-06T12:00:00Z",
            "critical": 0,
            "high": 0,
        },
    }


def test_validate_image_manifest_cli_reports_approved_identity(monkeypatch, capsys, tmp_path):
    manifest_file = tmp_path / "image-release.json"
    manifest_file.write_text(json.dumps(_image_manifest()), encoding="utf-8")
    monkeypatch.setattr(
        sys, "argv", ["vulnresearch", "validate-image-manifest", str(manifest_file)]
    )
    monkeypatch.setattr(
        cli.ResearchTask,
        "from_file",
        lambda _path: pytest.fail("image validation must not parse a task"),
    )

    cli.main()

    output = json.loads(capsys.readouterr().out)
    assert output["valid"] is True
    assert output["image_self_link"] == _image_manifest()["image_self_link"]
    assert output["critical_findings"] == 0
    assert output["high_findings"] == 0


def test_validate_image_manifest_cli_fails_closed_on_high_findings(
    monkeypatch, capsys, tmp_path
):
    manifest = _image_manifest()
    manifest["vulnerability_scan"]["high"] = 1
    manifest_file = tmp_path / "image-release.json"
    manifest_file.write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setattr(
        sys, "argv", ["vulnresearch", "validate-image-manifest", str(manifest_file)]
    )

    with pytest.raises(SystemExit) as error:
        cli.main()

    assert error.value.code == 2
    assert "image release blocked" in capsys.readouterr().err


def test_validate_image_manifest_cli_rejects_invalid_json(monkeypatch, capsys, tmp_path):
    manifest_file = tmp_path / "image-release.json"
    manifest_file.write_text("{not-json", encoding="utf-8")
    monkeypatch.setattr(
        sys, "argv", ["vulnresearch", "validate-image-manifest", str(manifest_file)]
    )

    with pytest.raises(SystemExit) as error:
        cli.main()

    assert error.value.code == 2
    assert "error:" in capsys.readouterr().err
