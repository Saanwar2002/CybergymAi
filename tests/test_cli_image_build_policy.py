"""CLI tests for offline GCE image build policy validation."""
import json
import sys

import pytest

from vulnresearch import cli


def _policy():
    return {
        "schema_version": 1,
        "base_image_self_link": "projects/cybergym-base/global/images/ubuntu-2404-v20261001",
        "source_commit": "a" * 40,
        "input_lock_sha256": "b" * 64,
        "builder_id": "https://builder.example.invalid/production",
        "build_type": "https://build.example.invalid/gce-image/v1",
        "scanner_name": "approved-image-scanner",
        "scanner_version": "1.2.3",
        "max_critical_findings": 0,
        "max_high_findings": 0,
    }


def test_validate_image_build_policy_cli_reports_validated_inputs(monkeypatch, capsys, tmp_path):
    policy_file = tmp_path / "build-policy.json"
    policy_file.write_text(json.dumps(_policy()), encoding="utf-8")
    monkeypatch.setattr(
        sys, "argv", ["vulnresearch", "validate-image-build-policy", str(policy_file)]
    )
    monkeypatch.setattr(
        cli.ResearchTask,
        "from_file",
        lambda _path: pytest.fail("build policy validation must not parse a task"),
    )

    cli.main()

    output = json.loads(capsys.readouterr().out)
    assert output["valid"] is True
    assert output["schema_version"] == 1
    assert output["base_image_self_link"] == _policy()["base_image_self_link"]
    assert output["max_critical_findings"] == 0
    assert output["max_high_findings"] == 0


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("base_image_self_link", "projects/cybergym-base/global/images/family/ubuntu"),
        ("source_commit", "main"),
        ("input_lock_sha256", "not-a-digest"),
        ("builder_id", "http://builder.example.invalid/production"),
        ("scanner_version", ""),
        ("max_critical_findings", 1),
    ],
)
def test_validate_image_build_policy_cli_fails_closed(monkeypatch, capsys, tmp_path, field, value):
    policy = _policy()
    policy[field] = value
    policy_file = tmp_path / "build-policy.json"
    policy_file.write_text(json.dumps(policy), encoding="utf-8")
    monkeypatch.setattr(
        sys, "argv", ["vulnresearch", "validate-image-build-policy", str(policy_file)]
    )

    with pytest.raises(SystemExit) as error:
        cli.main()

    assert error.value.code == 2
    assert "error:" in capsys.readouterr().err


def test_validate_image_build_policy_cli_rejects_invalid_json(monkeypatch, capsys, tmp_path):
    policy_file = tmp_path / "build-policy.json"
    policy_file.write_text("{invalid", encoding="utf-8")
    monkeypatch.setattr(
        sys, "argv", ["vulnresearch", "validate-image-build-policy", str(policy_file)]
    )

    with pytest.raises(SystemExit) as error:
        cli.main()

    assert error.value.code == 2
    assert "error:" in capsys.readouterr().err


def test_validate_image_build_policy_cli_rejects_duplicate_json_keys(
    monkeypatch, capsys, tmp_path
):
    policy_file = tmp_path / "build-policy.json"
    policy_file.write_text(
        '{"scanner_name":"first","scanner_name":"second"}',
        encoding="utf-8",
    )
    monkeypatch.setattr(
        sys, "argv", ["vulnresearch", "validate-image-build-policy", str(policy_file)]
    )

    with pytest.raises(SystemExit) as error:
        cli.main()

    assert error.value.code == 2
    assert "duplicate JSON key" in capsys.readouterr().err


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_validate_image_build_policy_cli_rejects_nonstandard_json_constants(
    monkeypatch, capsys, tmp_path, constant
):
    policy_file = tmp_path / "build-policy.json"
    policy_file.write_text(
        '{"max_critical_findings":' + constant + '}',
        encoding="utf-8",
    )
    monkeypatch.setattr(
        sys, "argv", ["vulnresearch", "validate-image-build-policy", str(policy_file)]
    )

    with pytest.raises(SystemExit) as error:
        cli.main()

    assert error.value.code == 2
    assert "non-standard JSON constant" in capsys.readouterr().err


@pytest.mark.parametrize("version", [0, 2, "1", True])
def test_validate_image_build_policy_cli_rejects_unsupported_schema_version(
    monkeypatch, capsys, tmp_path, version
):
    policy = _policy()
    policy["schema_version"] = version
    policy_file = tmp_path / "build-policy.json"
    policy_file.write_text(json.dumps(policy), encoding="utf-8")
    monkeypatch.setattr(
        sys, "argv", ["vulnresearch", "validate-image-build-policy", str(policy_file)]
    )

    with pytest.raises(SystemExit) as error:
        cli.main()

    assert error.value.code == 2
    assert "schema_version" in capsys.readouterr().err
