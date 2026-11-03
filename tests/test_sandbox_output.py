import io

from vulnresearch.sandbox import _read_bounded


def test_read_bounded_caps_retained_output_and_drains_stream():
    content = b"abcdefghij"
    retained, truncated = _read_bounded(io.BytesIO(content), 4)
    assert retained == b"abcd"
    assert truncated


def test_run_task_decodes_arbitrary_output_with_reversible_surrogateescape(
    tmp_path, monkeypatch
):
    import io
    from pathlib import Path

    from vulnresearch.sandbox import run_task
    from vulnresearch.task import ResearchTask

    class FakeProcess:
        stdout = io.BytesIO(b"out\\xff")
        stderr = io.BytesIO(b"err\\x80")

        def wait(self, timeout=None):
            return 0

    task = ResearchTask(
        schema_version="1.0",
        task_id="fixture-non-utf8",
        name="non UTF-8 fixture",
        description="Preserve raw process bytes",
        source_kind="local_fixture",
        source_reference="fixture",
        authorization_status="approved",
        authorization_scope="local_fixture_only",
        approved_by="developer",
        approval_reference="test",
        workspace=str(tmp_path),
        workspace_root=str(tmp_path),
        execution_profile="offline_readonly",
        command=["python", "-c", "pass"],
    )
    monkeypatch.setenv(
        "VULNRESEARCH_SANDBOX_IMAGE",
        "python:3.11-slim@sha256:" + "a" * 64,
    )
    original_exists = Path.exists

    def exists(path):
        if str(path) == "/var/run/docker.sock":
            return True
        return original_exists(path)

    monkeypatch.setattr(Path, "exists", exists)
    monkeypatch.setattr(
        "vulnresearch.sandbox.subprocess.Popen",
        lambda *args, **kwargs: FakeProcess(),
    )

    result = run_task(task)

    assert result.stdout.encode("utf-8", errors="surrogateescape") == b"out\\xff"
    assert result.stderr.encode("utf-8", errors="surrogateescape") == b"err\\x80"
