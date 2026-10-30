"""The public /v1 error-code registry matches the spec and the contract design."""

from __future__ import annotations

import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
REGISTRY = REPO / "proto" / "kallara" / "v1" / "errors.json"
SPEC = REPO / "spec" / "ciphertext-v1.md"

# Codes the crypto core uses internally; they reach callers only as `unavailable` or `internal`.
INTERNAL = {"key_material_invalid", "custody_unavailable", "custody_failed", "wrapped_key_invalid"}


def _spec_codes() -> list[str]:
    section = SPEC.read_text(encoding="utf-8").split("## 5. Errors", 1)[1].split("\n## ", 1)[0]
    return re.findall(r"^\| `([a-z_]+)` \|", section, flags=re.M)


SPEC_CODES = _spec_codes()

EXPECTED = {
    **{c: (400, "INVALID_ARGUMENT") for c in SPEC_CODES},
    "plaintext_too_long": (400, "INVALID_ARGUMENT"),
    "context_mismatch": (400, "INVALID_ARGUMENT"),
    "invalid_request": (400, "INVALID_ARGUMENT"),
    "unauthenticated": (401, "UNAUTHENTICATED"),
    "permission_denied": (403, "PERMISSION_DENIED"),
    "not_found": (404, "NOT_FOUND"),
    "secret_scheduled_for_deletion": (409, "FAILED_PRECONDITION"),
    "rate_limited": (429, "RESOURCE_EXHAUSTED"),
    "unavailable": (503, "UNAVAILABLE"),
    "internal": (500, "INTERNAL"),
}


def _registry() -> list[dict[str, object]]:
    entries: list[dict[str, object]] = json.loads(REGISTRY.read_text(encoding="utf-8"))["codes"]
    return entries


def test_spec_has_nine_codes() -> None:
    assert len(SPEC_CODES) == 9


def test_registry_matches_design() -> None:
    assert {e["code"]: (e["http"], e["grpc"]) for e in _registry()} == EXPECTED


def test_codes_unique_and_snake_case() -> None:
    codes = [e["code"] for e in _registry()]
    assert len(codes) == len(set(codes))
    assert all(isinstance(c, str) and re.fullmatch(r"[a-z][a-z_]*", c) for c in codes)


def test_internal_codes_not_public() -> None:
    assert not INTERNAL & {e["code"] for e in _registry()}


def test_titles_present() -> None:
    assert all(isinstance(e["title"], str) and e["title"].strip() for e in _registry())
