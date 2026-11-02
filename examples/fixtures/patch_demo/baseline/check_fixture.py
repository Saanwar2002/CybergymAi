"""Expected-to-fail baseline check for the harmless patch demonstration."""

from solution import normalize_label


actual = normalize_label("  SAFE  ")
if actual != "safe":
    raise SystemExit(f"baseline mismatch: expected 'safe', got {actual!r}")
print("baseline fixture passed")
