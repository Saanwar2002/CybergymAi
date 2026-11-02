"""Command-line entry point."""
from __future__ import annotations

import argparse
import json
import sys

from .llm import create_plan
from .policy.scope import authorize_task
from .sandbox import SandboxError, run_task
from .task import ResearchTask


def main() -> None:
    parser = argparse.ArgumentParser(prog="vulnresearch")
    sub = parser.add_subparsers(dest="action", required=True)
    for action in ("validate", "plan", "run"):
        item = sub.add_parser(action)
        item.add_argument("task_file")
        if action == "run":
            item.add_argument(
                "--allow-execution",
                action="store_true",
                help="Explicitly authorize running the approved local fixture in Docker",
            )
    args = parser.parse_args()
    try:
        task = ResearchTask.from_file(args.task_file)
        decision = authorize_task(task)
        if args.action == "validate":
            print(
                json.dumps(
                    {
                        "valid": True,
                        "task": task.name,
                        "policy_allowed": decision.allowed,
                        "policy_reason": decision.reason,
                    },
                    indent=2,
                )
            )
            if not decision.allowed:
                sys.exit(2)
        elif args.action == "plan":
            if not decision.allowed:
                parser.exit(2, f"blocked by policy: {decision.reason}\n")
            print(json.dumps(create_plan(task.name, task.description).to_dict(), indent=2))
        elif args.action == "run":
            if not decision.allowed:
                parser.exit(2, f"blocked by policy: {decision.reason}\n")
            if not args.allow_execution:
                parser.error("run requires --allow-execution; execution is opt-in")
            result = run_task(task)
            print(
                json.dumps(
                    {
                        "returncode": result.returncode,
                        "stdout": result.stdout,
                        "stderr": result.stderr,
                    },
                    indent=2,
                )
            )
            if result.returncode:
                sys.exit(result.returncode)
    except (ValueError, OSError, SandboxError, KeyError, RuntimeError) as exc:
        parser.exit(2, f"error: {exc}\n")


if __name__ == "__main__":
    main()
