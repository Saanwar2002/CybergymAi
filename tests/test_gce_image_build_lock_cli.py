import hashlib
import json

import pytest

from vulnresearch.cli import main
from vulnresearch.execution.gce_image_build import (
    GceImageBuildPolicyError,
    verify_gce_image_build_lock,
)


@pytest.fixture
def policy():
    lock = b"dependencies==1.2.3\\n"
    return lock, {
        "schema_version": 1,
        "base_image_self_link": "projects/cybergym-base/global/images/ubuntu-2404-v20261001",
        "source_commit": "a" * 40,
        "input_lock_sha256": hashlib.sha256(lock).hexdigest(),
        "builder_id": "https://builder.example.invalid/production",
        "build_type": "https://build.example.invalid/gce-image/v1",
        "scanner_name": "approved-image-scanner",
        "scanner_version": "1.2.3",
        "max_critical_findings": 0,
        "max_high_findings": 0,
    }


def test_verifies_exact_lock_bytes(policy):
    lock, data = policy
    result = verify_gce_image_build_lock(data, lock)
    assert result.input_lock_sha256 == hashlib.sha256(lock).hexdigest()


def test_rejects_lock_bytes_that_do_not_match_pin(policy):
    _, data = policy
    with pytest.raises(GceImageBuildPolicyError, match="does not match"):
        verify_gce_image_build_lock(data, b"dependencies==9.9.9\\n")


def test_rejects_non_byte_lock_input(policy):
    _, data = policy
    with pytest.raises(GceImageBuildPolicyError, match="must be bytes"):
        verify_gce_image_build_lock(data, "not bytes")


def test_cli_reports_verified_lock(tmp_path, monkeypatch, capsys, policy):
    lock, data = policy
    policy_file = tmp_path / "policy.json"
    lock_file = tmp_path / "requirements.lock"
    policy_file.write_text(json.dumps(data), encoding="utf-8")
    lock_file.write_bytes(lock)
    monkeypatch.setattr(
        "sys.argv",
        ["vulnresearch", "validate-image-build-lock", str(policy_file), str(lock_file)],
    )

    main()

    result = json.loads(capsys.readouterr().out)
    assert result["valid"] is True
    assert result["lock_verified"] is True
    assert result["lock_bytes"] == len(lock)
    assert result["input_lock_sha256"] == hashlib.sha256(lock).hexdigest()


def test_cli_fails_closed_when_lock_digest_differs(tmp_path, monkeypatch):
    lock_file = tmp_path / "requirements.lock"
    policy_file = tmp_path / "policy.json"
    lock_file.write_bytes(b"changed dependency input")
    policy_file.write_text(
        json.dumps({
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
        }),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "sys.argv",
        ["vulnresearch", "validate-image-build-lock", str(policy_file), str(lock_file)],
    )

    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 2
