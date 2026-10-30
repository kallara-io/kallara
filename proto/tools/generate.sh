#!/usr/bin/env bash
# Generate proto/openapi/openapi.yaml from the /v1 proto files.
#   proto/tools/generate.sh           regenerate
#   proto/tools/generate.sh --check   fail if the committed file is out of date
set -euo pipefail

BUF_VERSION=1.75.0
PYYAML_VERSION=6.0.3

proto="$(cd "$(dirname "$0")/.." && pwd)"
cd "$proto"

out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT
npx --yes "@bufbuild/buf@${BUF_VERSION}" generate -o "$out"
uv run -q --python 3.13 --no-project --with "pyyaml==${PYYAML_VERSION}" \
  tools/openapi_problem.py "$out/openapi/openapi.yaml" kallara/v1/errors.json

if [[ "${1:-}" == "--check" ]]; then
  if ! diff -u openapi/openapi.yaml "$out/openapi/openapi.yaml"; then
    echo "openapi.yaml is out of date; run proto/tools/generate.sh" >&2
    exit 1
  fi
else
  cp "$out/openapi/openapi.yaml" openapi/openapi.yaml
fi
