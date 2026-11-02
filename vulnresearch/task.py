"""Task manifest parsing and validation."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ResearchTask:
    name: str
    description: str
    workspace: str
    command: list[str]
    timeout_seconds: int = 120

    @classmethod
    def from_file(cls, path: str | Path) -> "ResearchTask":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        required = {"name", "description", "workspace", "command"}
        missing = required - data.keys()
        if missing:
            raise ValueError(f"Missing required task fields: {', '.join(sorted(missing))}")
        if not isinstance(data["command"], list) or not data["command"]:
            raise ValueError("command must be a non-empty list of strings")
        if not all(isinstance(part, str) and part for part in data["command"]):
            raise ValueError("every command element must be a non-empty string")
        timeout = data.get("timeout_seconds", 120)
        if not isinstance(timeout, int) or not 1 <= timeout <= 3600:
            raise ValueError("timeout_seconds must be an integer between 1 and 3600")
        for field in ("name", "description", "workspace"):
            if not isinstance(data[field], str) or not data[field].strip():
                raise ValueError(f"{field} must be a non-empty string")
        return cls(data["name"], data["description"], data["workspace"], data["command"], timeout)
