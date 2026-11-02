"""Minimal OpenAI-compatible chat completion client."""
from __future__ import annotations

import os

import httpx


class LLMConfigError(RuntimeError):
    pass


def create_plan(task_name: str, description: str) -> str:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise LLMConfigError("Set OPENAI_API_KEY before requesting an AI plan.")
    base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    model = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")
    prompt = (
        "Create a defensive, non-destructive vulnerability research plan. "
        "Do not provide weaponization steps, persistence, exfiltration, or instructions "
        "against third-party systems. Include scope checks, reproduction strategy, "
        "evidence to collect, remediation ideas, and human-review gates.\n\n"
        f"Task: {task_name}\nDescription: {description}"
    )
    response = httpx.post(
        f"{base_url}/chat/completions",
        headers={"Authorization": f"Bearer {api_key}"},
        json={"model": model, "messages": [{"role": "user", "content": prompt}], "temperature": 0.2},
        timeout=60.0,
    )
    response.raise_for_status()
    payload = response.json()
    return payload["choices"][0]["message"]["content"]
