"""CLI policy and explicit human execution-approval tests."""
import base64
import hashlib
import json
import sys
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

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


def _write_signed_cli_inputs(tmp_path, manifest):
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    payload = json.dumps(
        manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
    signature = base64.b64encode(private_key.sign(payload)).decode("ascii")
    manifest_file = tmp_path / "image-release.json"
    signature_file = tmp_path / "image-release.sig"
    public_key_file = tmp_path / "image-release.pub"
    manifest_file.write_text(json.dumps(manifest), encoding="utf-8")
    signature_file.write_text(signature, encoding="ascii")
    public_key_file.write_bytes(public_key_pem)
    fingerprint = hashlib.sha256(public_key_der).hexdigest()
    return manifest_file, signature_file, public_key_file, fingerprint


def test_verify_image_manifest_cli_authenticates_release(monkeypatch, capsys, tmp_path):
    manifest = _image_manifest()
    manifest_file, signature_file, public_key_file, fingerprint = _write_signed_cli_inputs(
        tmp_path, manifest
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "vulnresearch",
            "verify-image-manifest",
            str(manifest_file),
            str(signature_file),
            str(public_key_file),
            "--trusted-key-sha256",
            fingerprint,
        ],
    )

    cli.main()

    output = json.loads(capsys.readouterr().out)
    assert output["valid"] is True
    assert output["signature_verified"] is True
    assert output["image_self_link"] == manifest["image_self_link"]


def test_verify_image_manifest_cli_rejects_wrong_trust_anchor(
    monkeypatch, capsys, tmp_path
):
    manifest_file, signature_file, public_key_file, _ = _write_signed_cli_inputs(
        tmp_path, _image_manifest()
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "vulnresearch",
            "verify-image-manifest",
            str(manifest_file),
            str(signature_file),
            str(public_key_file),
            "--trusted-key-sha256",
            "0" * 64,
        ],
    )

    with pytest.raises(SystemExit) as error:
        cli.main()

    assert error.value.code == 2
    assert "fingerprint" in capsys.readouterr().err


def test_verify_image_manifest_cli_rejects_tampered_manifest(
    monkeypatch, capsys, tmp_path
):
    manifest_file, signature_file, public_key_file, fingerprint = _write_signed_cli_inputs(
        tmp_path, _image_manifest()
    )
    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    manifest["build_id"] = "tampered-build"
    manifest_file.write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "vulnresearch",
            "verify-image-manifest",
            str(manifest_file),
            str(signature_file),
            str(public_key_file),
            "--trusted-key-sha256",
            fingerprint,
        ],
    )

    with pytest.raises(SystemExit) as error:
        cli.main()

    assert error.value.code == 2
    assert "signature is invalid" in capsys.readouterr().err


def _write_dsse_provenance_cli_inputs(tmp_path, manifest):
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{
            "name": manifest["image_self_link"],
            "digest": {"sha256": manifest["artifact_sha256"]},
        }],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://builder.example.invalid/build-type/v1",
                "resolvedDependencies": [{
                    "uri": "git+https://github.com/example/repository",
                    "digest": {"gitCommit": manifest["build_commit"]},
                }],
            },
            "runDetails": {
                "builder": {"id": "https://builder.example.invalid/production"}
            },
        },
    }
    payload = json.dumps(statement, sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload_type = b"application/vnd.in-toto+json"
    pae = (
        b"DSSEv1 " + str(len(payload_type)).encode("ascii") + b" "
        + payload_type + b" " + str(len(payload)).encode("ascii") + b" " + payload
    )
    fingerprint = hashlib.sha256(public_key_der).hexdigest()
    envelope = {
        "payloadType": payload_type.decode("ascii"),
        "payload": base64.b64encode(payload).decode("ascii"),
        "signatures": [{
            "keyid": fingerprint,
            "sig": base64.b64encode(private_key.sign(pae)).decode("ascii"),
        }],
    }
    manifest_file = tmp_path / "image-release.json"
    envelope_file = tmp_path / "provenance.dsse.json"
    public_key_file = tmp_path / "builder.pub"
    manifest_file.write_text(json.dumps(manifest), encoding="utf-8")
    envelope_file.write_text(json.dumps(envelope), encoding="utf-8")
    public_key_file.write_bytes(public_key_pem)
    return manifest_file, envelope_file, public_key_file, fingerprint


def test_verify_image_provenance_cli_authenticates_slsa_statement(
    monkeypatch, capsys, tmp_path
):
    manifest = _image_manifest()
    manifest_file, envelope_file, public_key_file, fingerprint = (
        _write_dsse_provenance_cli_inputs(tmp_path, manifest)
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "vulnresearch",
            "verify-image-provenance",
            str(manifest_file),
            str(envelope_file),
            str(public_key_file),
            "--trusted-key-sha256",
            fingerprint,
            "--expected-builder-id",
            "https://builder.example.invalid/production",
        ],
    )

    cli.main()

    output = json.loads(capsys.readouterr().out)
    assert output["valid"] is True
    assert output["provenance_verified"] is True
    assert output["image_self_link"] == manifest["image_self_link"]


def test_verify_image_provenance_cli_rejects_untrusted_builder(
    monkeypatch, capsys, tmp_path
):
    manifest_file, envelope_file, public_key_file, fingerprint = (
        _write_dsse_provenance_cli_inputs(tmp_path, _image_manifest())
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "vulnresearch",
            "verify-image-provenance",
            str(manifest_file),
            str(envelope_file),
            str(public_key_file),
            "--trusted-key-sha256",
            fingerprint,
            "--expected-builder-id",
            "https://attacker.example.invalid/builder",
        ],
    )

    with pytest.raises(SystemExit) as error:
        cli.main()

    assert error.value.code == 2
    assert "builder identity" in capsys.readouterr().err
