"""Regression check for the harmless patch demonstration."""

from solution import normalize_label


actual = normalize_label("  SAFE  ")
if actual != "safe":
    raise SystemExit(f"candidate mismatch: expected 'safe', got {actual!r}")
print("candidate regression check passed")
