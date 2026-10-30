# Conformance vectors

Shared test data that every Kallara implementation runs in CI: the crypto service, the agent and
every SDK. If two implementations disagree about a vector, at least one of them is wrong.

| File | Covers |
| --- | --- |
| [`vectors/ciphertext-v1.json`](vectors/ciphertext-v1.json) | [`spec/ciphertext-v1.md`](../spec/ciphertext-v1.md): parsing, context rules, AAD and AES-256-GCM |
| [`schema/ciphertext-v1.schema.json`](schema/ciphertext-v1.schema.json) | JSON Schema for the file above |
| [`tools/gen_ciphertext_v1.py`](tools/gen_ciphertext_v1.py) | Deterministic generator, an independent reading of the spec |

## Who runs what

| Section | SDKs and agent | Crypto service |
| --- | --- | --- |
| `parse_invalid` | yes | yes |
| `context_invalid` | yes | yes |
| `valid` | parse only: key ID, version, payload length | full: AAD, encrypt with the given nonce, decrypt |
| `decrypt_invalid` | no, they hold no keys | yes |

Contexts are written as `context_pairs`, a list of `[key, value]`, so ordering and duplicate keys can
be expressed. An implementation whose native context type cannot hold a case (a map cannot hold
duplicate keys, a typed map cannot hold a number) skips vectors carrying that case's `tags`.

`error: null` in `parse_invalid` marks a boundary string that must parse successfully.

## Changing vectors

Vectors are generated, never hand-edited.

```bash
pip install "cryptography>=50.0.2,<51" "jsonschema>=4.23,<5"
python conformance/tools/gen_ciphertext_v1.py          # regenerate
python conformance/tools/gen_ciphertext_v1.py --check  # what CI runs
```

A change to an existing vector's expected output is a breaking change to the format and needs a new
format version (`kal:v2`), not an edit. Adding vectors is always allowed.

The key material in these files is public test data. Never use it to protect real data.
