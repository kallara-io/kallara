"""Finish the generated /v1 OpenAPI: RFC 9457 errors and bearer auth.

    openapi_problem.py <openapi.yaml> <errors.json>

Rewrites openapi.yaml in place. Same input gives a byte-identical file, so the CI check can diff it.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

PROBLEM = {"$ref": "#/components/schemas/Problem"}
PUBLIC = {"CryptoService_GetJwks"}  # JWKS must be readable by anyone verifying Kallara-issued JWTs


def main(openapi_path: Path, errors_path: Path) -> None:
    spec = yaml.safe_load(openapi_path.read_text(encoding="utf-8"))
    codes = [e["code"] for e in json.loads(errors_path.read_text(encoding="utf-8"))["codes"]]

    for item in spec["paths"].values():
        for op in item.values():
            op["responses"]["default"] = {
                "description": "Error, as RFC 9457 problem details with a stable code.",
                "content": {"application/problem+json": {"schema": PROBLEM}},
            }
            if op["operationId"] in PUBLIC:
                op["security"] = []

    spec["components"]["schemas"]["Problem"]["properties"]["code"]["enum"] = codes
    spec["components"]["securitySchemes"] = {"bearer": {"type": "http", "scheme": "bearer"}}
    spec["security"] = [{"bearer": []}]

    openapi_path.write_text(yaml.safe_dump(spec, sort_keys=False, allow_unicode=True), encoding="utf-8")


if __name__ == "__main__":
    main(Path(sys.argv[1]), Path(sys.argv[2]))
