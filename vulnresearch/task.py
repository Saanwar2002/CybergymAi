"""Versioned task manifest parsing and trusted workspace validation."""
from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from .jsonutil import loads_unique

_MAX_TASK_MANIFEST_BYTES = 64 * 1024


@dataclass(frozen=True)
class ResearchTask:
    schema_version: str
    task_id: str
    name: str
    description: str
    source_kind: str
    source_reference: str
    authorization_status: str
    authorization_scope: str
    approved_by: str
    approval_reference: str
    workspace: str
    execution_profile: str
    command: tuple[str, ...]
    timeout_seconds: int = 120
    workspace_root: str | None = None

    def __post_init__(self) -> None:
        """Validate and freeze argv so it cannot change after manifest validation."""
        if not isinstance(self.command, (list, tuple)) or not self.command:
            raise ValueError("command must be a non-empty sequence of arguments")
        if not all(isinstance(part, str) and part for part in self.command):
            raise ValueError("every command argument must be a non-empty string")
        if any("\x00" in part for part in self.command):
            raise ValueError("command arguments must not contain NUL characters")
        if any(len(part) > 4096 for part in self.command) or sum(
            map(len, self.command)
        ) > 16384:
            raise ValueError("command arguments exceed the prototype size limits")
        object.__setattr__(self, "command", tuple(self.command))

    @classmethod
    def from_file(
        cls, path: str | Path, *, workspace_root: str | Path | None = None
    ) -> ResearchTask:
        manifest_path = Path(path).resolve()
        descriptor = os.open(
            manifest_path,
            os.O_RDONLY
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise ValueError("Task manifest must be a regular file")
            with os.fdopen(descriptor, "rb") as stream:
                descriptor = -1
                raw_manifest = stream.read(_MAX_TASK_MANIFEST_BYTES + 1)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        try:
            if len(raw_manifest) > _MAX_TASK_MANIFEST_BYTES:
                raise ValueError(
                    f"Task manifest exceeds {_MAX_TASK_MANIFEST_BYTES} bytes"
                )
            data = loads_unique(raw_manifest.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"Invalid JSON task manifest: {exc}") from exc
        if not isinstance(data, dict):
            raise TypeError("Task manifest must be a JSON object")

        allowed = {
            "schema_version", "task_id", "name", "description", "source",
            "authorization", "workspace", "execution_profile", "commands",
        }
        unknown = data.keys() - allowed
        if unknown:
            raise ValueError(
                f"Unknown task manifest fields: {', '.join(sorted(unknown))}"
            )
        missing = allowed - data.keys()
        if missing:
            raise ValueError(f"Missing required task fields: {', '.join(sorted(missing))}")
        if data["schema_version"] != "1.0":
            raise ValueError("Unsupported schema_version; expected '1.0'")

        source = data["source"]
        auth = data["authorization"]
        if not isinstance(source, dict) or not isinstance(auth, dict):
            raise TypeError("source and authorization must be JSON objects")
        if set(source) != {"kind", "reference"}:
            raise ValueError("source must contain only kind and reference")
        if set(auth) != {"status", "scope", "approved_by", "approval_reference"}:
            raise ValueError(
                "authorization must contain only status, scope, approved_by, and approval_reference"
            )

        text_limits = {
            "task_id": 128,
            "name": 256,
            "description": 8000,
            "workspace": 1024,
            "execution_profile": 64,
        }
        for field, maximum in text_limits.items():
            if not isinstance(data[field], str) or not data[field].strip():
                raise ValueError(f"{field} must be a non-empty string")
            if len(data[field]) > maximum:
                raise ValueError(f"{field} must not exceed {maximum} characters")
        source_limits = {"kind": 64, "reference": 1024}
        for field, maximum in source_limits.items():
            if not isinstance(source.get(field), str) or not source[field].strip():
                raise ValueError(f"source.{field} must be a non-empty string")
            if len(source[field]) > maximum:
                raise ValueError(f"source.{field} must not exceed {maximum} characters")
        authorization_limits = {
            "status": 64,
            "scope": 64,
            "approved_by": 256,
            "approval_reference": 256,
        }
        for field, maximum in authorization_limits.items():
            if not isinstance(auth.get(field), str) or not auth[field].strip():
                raise ValueError(f"authorization.{field} must be a non-empty string")
            if len(auth[field]) > maximum:
                raise ValueError(
                    f"authorization.{field} must not exceed {maximum} characters"
                )

        commands = data["commands"]
        if not isinstance(commands, list) or len(commands) != 1:
            raise ValueError("commands must contain exactly one command in prototype v1")
        command = commands[0]
        if not isinstance(command, dict):
            raise TypeError("commands[0] must be a JSON object")
        if set(command) - {"id", "argv", "timeout_seconds"}:
            raise ValueError("commands[0] contains unknown fields")
        if "id" in command and (
            not isinstance(command["id"], str)
            or not command["id"].strip()
            or len(command["id"]) > 64
        ):
            raise ValueError("commands[0].id must be a non-empty string of at most 64 characters")
        if not isinstance(command.get("argv"), list):
            raise TypeError("commands[0].argv must be a non-empty list")
        argv = command["argv"]
        if not argv or not all(isinstance(part, str) and part for part in argv):
            raise ValueError("every argv element must be a non-empty string")
        if any("\x00" in part for part in argv):
            raise ValueError("argv elements must not contain NUL characters")
        if any(len(part) > 4096 for part in argv) or sum(map(len, argv)) > 16384:
            raise ValueError("command arguments exceed the prototype size limits")
        timeout = command.get("timeout_seconds", 120)
        if type(timeout) is not int or not 1 <= timeout <= 3600:
            raise ValueError("timeout_seconds must be an integer between 1 and 3600")

        root = Path(workspace_root).resolve() if workspace_root else Path.cwd().resolve()
        raw_workspace = Path(data["workspace"])
        if raw_workspace.is_absolute():
            raise ValueError("workspace must be a relative path beneath the trusted workspace root")
        resolved_workspace = (root / raw_workspace).resolve()
        try:
            resolved_workspace.relative_to(root)
        except ValueError as exc:
            raise ValueError("workspace escapes the trusted workspace root") from exc
        if not resolved_workspace.is_dir():
            raise ValueError(f"workspace does not exist or is not a directory: {resolved_workspace}")

        return cls(
            schema_version=data["schema_version"],
            task_id=data["task_id"],
            name=data["name"],
            description=data["description"],
            source_kind=source["kind"],
            source_reference=source["reference"],
            authorization_status=auth["status"],
            authorization_scope=auth["scope"],
            approved_by=auth["approved_by"],
            approval_reference=auth["approval_reference"],
            workspace=str(resolved_workspace),
            workspace_root=str(root),
            execution_profile=data["execution_profile"],
            command=list(argv),
            timeout_seconds=timeout,
        )
