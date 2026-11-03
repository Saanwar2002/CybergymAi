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
