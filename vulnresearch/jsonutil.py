"""Strict JSON decoding helpers for security-sensitive persisted records."""
from __future__ import annotations

import json
from typing import Any


def _unique_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build a JSON object while rejecting duplicate keys at every nesting level."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON object key: {key}")
        result[key] = value
    return result


def loads_unique(text: str) -> Any:
    """Decode JSON while rejecting ambiguous duplicate object keys."""
    return json.loads(text, object_pairs_hook=_unique_object_pairs)
