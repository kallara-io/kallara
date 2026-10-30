"""The generated OpenAPI for /v1 keeps the contract's promises."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
OPENAPI = REPO / "proto" / "openapi" / "openapi.yaml"

OPS = {
    f"CryptoService_{r}"
    for r in [
        "Encrypt",
        "Decrypt",
        "Rewrap",
        "Sign",
        "Verify",
        "Hmac",
        "VerifyHmac",
        "IssueJwt",
        "GetPublicKey",
        "GetJwks",
        "Batch",
    ]
} | {
    f"SecretService_{r}"
    for r in ["GetSecret", "PutSecret", "ListSecrets", "ListSecretVersions", "DeleteSecret", "RestoreSecret"]
}

# Only resource names, versions and paging may appear in a URL; never values, plaintext or context.
ALLOWED_PARAMS = {
    "key",
    "version",
    "project",
    "environment",
    "secret",
    "pageSize",
    "pageToken",
    "recoveryDays",
}

KEY_MATERIAL = re.compile(r"material|private|kek|wrapped|secret_?key", re.I)
TENANT = {"org", "orgId", "organization", "tenant"}


@pytest.fixture(scope="module")
def spec() -> dict[str, Any]:
    data: dict[str, Any] = yaml.safe_load(OPENAPI.read_text(encoding="utf-8"))
    return data


def _operations(spec: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    return [
        (method, op)
        for item in spec["paths"].values()
        for method, op in item.items()
        if method in {"get", "post", "put", "patch", "delete"}
    ]


def _properties(spec: dict[str, Any]) -> list[str]:
    return [p for s in spec["components"]["schemas"].values() for p in s.get("properties", {})]


def test_all_operations_present(spec: dict[str, Any]) -> None:
    assert {op["operationId"] for _, op in _operations(spec)} == OPS


def test_no_sensitive_parameters(spec: dict[str, Any]) -> None:
    names = {p["name"] for _, op in _operations(spec) for p in op.get("parameters", [])}
    assert names <= ALLOWED_PARAMS


def test_reads_have_no_body(spec: dict[str, Any]) -> None:
    assert not [op["operationId"] for m, op in _operations(spec) if m in {"get", "delete"} and "requestBody" in op]


def test_no_key_material_fields(spec: dict[str, Any]) -> None:
    assert not [p for p in _properties(spec) if KEY_MATERIAL.search(p)]


def test_batch_result_can_carry_problem(spec: dict[str, Any]) -> None:
    error = spec["components"]["schemas"]["BatchResult"]["properties"]["error"]
    # OpenAPI 3.0 forbids siblings of $ref, so a described reference is wrapped in allOf.
    refs = [error.get("$ref")] + [a.get("$ref") for a in error.get("allOf", [])]
    assert "#/components/schemas/Problem" in refs


def test_no_tenant_in_requests(spec: dict[str, Any]) -> None:
    params = {p["name"] for _, op in _operations(spec) for p in op.get("parameters", [])}
    assert not TENANT & (params | set(_properties(spec)))


def _registry_codes() -> list[str]:
    registry = json.loads((REPO / "proto" / "kallara" / "v1" / "errors.json").read_text(encoding="utf-8"))
    return [e["code"] for e in registry["codes"]]


def test_every_operation_has_problem_default(spec: dict[str, Any]) -> None:
    for _, op in _operations(spec):
        content = op["responses"]["default"]["content"]
        assert list(content) == ["application/problem+json"], op["operationId"]
        assert content["application/problem+json"]["schema"] == {"$ref": "#/components/schemas/Problem"}


def test_problem_code_enum_matches_registry(spec: dict[str, Any]) -> None:
    assert spec["components"]["schemas"]["Problem"]["properties"]["code"]["enum"] == _registry_codes()


def test_problem_type_documents_urn(spec: dict[str, Any]) -> None:
    assert "urn:kallara:error:" in spec["components"]["schemas"]["Problem"]["properties"]["type"]["description"]


def test_bearer_auth(spec: dict[str, Any]) -> None:
    assert spec["components"]["securitySchemes"]["bearer"] == {"type": "http", "scheme": "bearer"}
    assert spec["security"] == [{"bearer": []}]
    ops = {op["operationId"]: op for _, op in _operations(spec)}
    assert ops["CryptoService_GetJwks"]["security"] == []
    assert all("security" not in op for name, op in ops.items() if name != "CryptoService_GetJwks")
