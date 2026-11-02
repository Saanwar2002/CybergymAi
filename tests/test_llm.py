import json

import httpx
import pytest

from vulnresearch.llm import (
    LLMConfigError,
    LLMProviderError,
    MockLLMProvider,
    OpenAICompatibleProvider,
    ResearchPlan,
    create_plan,
)


def valid_payload():
    return {
        "objective": "Reproduce the documented fixture behaviour.",
        "assumptions": ["The fixture is local and authorized."],
        "reproduction_strategy": ["Run the approved offline test."],
        "evidence_to_collect": ["Exit code and test output."],
        "remediation_ideas": ["Add a regression test."],
        "human_review_gates": ["Review evidence before accepting a finding."],
    }


def test_mock_provider_returns_structured_plan():
    plan = create_plan("fixture", "safe fixture", provider=MockLLMProvider())
    assert isinstance(plan, ResearchPlan)
    assert plan.objective
    assert plan.human_review_gates
    assert set(plan.to_dict()) == set(valid_payload())


def test_provider_requires_api_key():
    with pytest.raises(LLMConfigError, match="OPENAI_API_KEY"):
        OpenAICompatibleProvider("")


def test_provider_parses_valid_json(monkeypatch):
    payload = {"choices": [{"message": {"content": json.dumps(valid_payload())}}]}

    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return payload

    def fake_post(*args, **kwargs):
        assert kwargs["json"]["response_format"] == {"type": "json_object"}
        return Response()

    monkeypatch.setattr(httpx, "post", fake_post)
    plan = OpenAICompatibleProvider("test-key").generate_plan("fixture", "safe")
    assert plan.objective == valid_payload()["objective"]


@pytest.mark.parametrize(
    "content",
    [
        "not json",
        json.dumps({"objective": "missing fields"}),
        json.dumps({**valid_payload(), "unexpected": "field"}),
        json.dumps({**valid_payload(), "assumptions": ["ok", 3]}),
        json.dumps({**valid_payload(), "objective": ""}),
    ],
)
def test_provider_rejects_malformed_plan(monkeypatch, content):
    payload = {"choices": [{"message": {"content": content}}]}

    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return payload

    monkeypatch.setattr(httpx, "post", lambda *args, **kwargs: Response())
    with pytest.raises(LLMProviderError):
        OpenAICompatibleProvider("test-key").generate_plan("fixture", "safe")


def test_provider_wraps_http_errors(monkeypatch):
    def fail(*args, **kwargs):
        raise httpx.TimeoutException("timeout")

    monkeypatch.setattr(httpx, "post", fail)
    with pytest.raises(LLMProviderError, match="request or response failed"):
        OpenAICompatibleProvider("test-key").generate_plan("fixture", "safe")


def test_create_plan_uses_injected_provider():
    provider = MockLLMProvider()
    assert create_plan("fixture", "safe", provider=provider) == provider.generate_plan(
        "fixture", "safe"
    )


@pytest.mark.parametrize(
    "base_url",
    [
        "http://api.example.com/v1",
        "ftp://api.example.com/v1",
        "https://user:password@example.com/v1",
        "https://api.example.com/v1?token=secret",
        "https://api.example.com/v1#fragment",
        "https://",
    ],
)
def test_provider_rejects_insecure_or_ambiguous_base_urls(base_url):
    with pytest.raises(LLMConfigError, match="OPENAI_BASE_URL"):
        OpenAICompatibleProvider("test-key", base_url=base_url)


@pytest.mark.parametrize(
    "base_url",
    [
        "http://localhost:8000/v1",
        "http://127.0.0.1:8000/v1",
        "http://[::1]:8000/v1",
        "https://api.example.com/v1",
    ],
)
def test_provider_accepts_https_or_loopback_http(base_url):
    provider = OpenAICompatibleProvider("test-key", base_url=base_url)
    assert provider.base_url == base_url


def test_provider_rejects_duplicate_json_keys(monkeypatch):
    content = json.dumps(valid_payload()).replace(
        '"objective": "Reproduce the documented fixture behaviour."',
        '"objective": "first", "objective": "second"',
        1,
    )
    payload = {"choices": [{"message": {"content": content}}]}

    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return payload

    monkeypatch.setattr(httpx, "post", lambda *args, **kwargs: Response())
    with pytest.raises(LLMProviderError, match="unambiguous JSON"):
        OpenAICompatibleProvider("test-key").generate_plan("fixture", "safe")


@pytest.mark.parametrize("timeout", [0, -1, True, float("nan"), float("inf"), 3601, "60"])
def test_provider_rejects_invalid_timeout_values(timeout):
    with pytest.raises(LLMConfigError, match="timeout"):
        OpenAICompatibleProvider("test-key", timeout=timeout)


def test_provider_normalizes_whitespace_around_base_url():
    provider = OpenAICompatibleProvider(
        "test-key", base_url="  https://api.example.com/v1/  "
    )
    assert provider.base_url == "https://api.example.com/v1"


def test_provider_wraps_invalid_response_json(monkeypatch):
    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            raise ValueError("malformed response JSON")

    monkeypatch.setattr(httpx, "post", lambda *args, **kwargs: Response())
    with pytest.raises(LLMProviderError, match="request or response failed"):
        OpenAICompatibleProvider("test-key").generate_plan("fixture", "safe")
