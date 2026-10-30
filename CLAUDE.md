# kallara

Public, Apache-2.0. The code and contracts that run on customers' machines. Read `../CLAUDE.md`
first for the project, status and Phase 1 plan.

## Rules

- This repository owns the contract. Specs, conformance vectors and (Phase 1) `proto/` are defined
  here; the platform only consumes them.
- Vectors are generated, never hand-edited:
  `python conformance/tools/gen_ciphertext_v1.py` to regenerate, `--check` to verify.
- The generator is an independent reading of the spec. It must not import platform code.
- Adding vectors is always fine. Changing an existing vector's expected output is a breaking format
  change and needs a new format version (`kal:v2`).
- Everything here is public: no internal hostnames, customer names or platform internals.
- SDKs never hold keys. They run the `parse_invalid` and `context_invalid` vectors and the parse
  part of `valid`; only the crypto service runs `decrypt_invalid`.
- `proto/` is the `/v1` contract. Regenerate the OpenAPI with `proto/tools/generate.sh` (`--check` to
  verify); never hand-edit `proto/openapi/openapi.yaml`. Changes to `v1` are additive only. Public
  error codes live in `proto/kallara/v1/errors.json`.

## Planned layout (Phase 1)

`agent/` (Go agent and `kallara` CLI, one module) ·
`sdks/python`, `sdks/node`, `sdks/go`, each running the conformance vectors in CI.
