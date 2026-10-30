# Kallara ciphertext format v1

Status: **Draft for Phase 0 sign-off** · Applies to keys of type `aead` with algorithm `AES-256-GCM`

Every value Kallara encrypts comes back as one ASCII string. The string names the key version that
produced it, so decrypt needs nothing but the string (and the encryption context, if one was used).
Rotation is invisible to callers, and the fixed `kal:v1:` prefix lets scanners and log filters find
Kallara ciphertext wherever it leaks.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. String form

```
kal:v1:<key_id>:<version>:<payload>
```

The string is split on `:` and MUST yield exactly five parts. No part may be empty.

| Part | Rule |
| --- | --- |
| `kal` | Literal, lowercase. |
| `v1` | Literal. A part matching `^v[1-9][0-9]{0,3}$` other than `v1` is a *future* format: parsers MUST report `format_unsupported_version`. Anything else (`v0`, `v01`, `vx`) is `format_invalid`. |
| `key_id` | `k_` followed by exactly 26 Crockford base32 characters, uppercase: `^k_[0-9A-HJKMNP-TV-Z]{26}$`. It is the 128-bit key UUID (UUIDv7) encoded as base32. |
| `version` | Decimal integer, 1 to 2147483647, no sign, no leading zeros: `^[1-9][0-9]{0,9}$` and ≤ 2147483647. |
| `payload` | Unpadded base64url (RFC 4648 §5) of `nonce ‖ ciphertext ‖ tag`. |

Payload encoding is **strict**. A parser MUST reject:

- any character outside `A–Z a–z 0–9 - _`, including `=` padding and whitespace;
- a length that is ≡ 1 (mod 4);
- non-canonical encodings, where the unused low bits of the last character are not zero.

Strictness matters: a lenient decoder accepts several strings for the same bytes, which breaks
equality checks, caching and deduplication of ciphertext.

## 2. Payload

For `AES-256-GCM`:

| Field | Size |
| --- | --- |
| `nonce` | 12 bytes, random from a CSPRNG for every encryption |
| `ciphertext` | same length as the plaintext, 0 to 65536 bytes |
| `tag` | 16 bytes |

So a decoded payload is 28 to 65564 bytes. Shorter is `payload_too_short`; longer is
`payload_too_long`.

The algorithm is **not** in the string. It is a property of the key version and is looked up from
`key_id` + `version`. A key version never changes algorithm.

**Nonce budget.** Random 96-bit nonces are safe for about 2³² encryptions under one key. Kallara
rotates an `aead` key automatically after 2³⁰ encryptions on its primary version, well inside that
limit, independent of the time-based rotation schedule.

## 3. Encryption context

A caller MAY pass a context: a flat map of string keys to string values, for example
`{"table": "customers", "row": "42"}`. It is not stored in the ciphertext. Decrypt succeeds only
when the caller supplies the identical context.

| Rule | Limit |
| --- | --- |
| Pairs | 0 to 16 |
| Key | 1 to 64 bytes, `^[A-Za-z0-9_.-]+$` |
| Value | 0 to 256 bytes of valid UTF-8 |
| Duplicate keys | not allowed |

Values are compared as exact bytes. Kallara does not apply Unicode normalization, so callers MUST
send the same bytes on encrypt and decrypt. A context that breaks a rule is `context_invalid`.

An empty map and an absent context are the same thing.

## 4. Associated data

The AEAD associated data binds the header and the context, so a payload cannot be moved to another
key, another version, or another row.

```
AAD = "kal:v1"                          6 ASCII bytes
    ‖ LP(key_id)                        ASCII
    ‖ U32(version)
    ‖ U32(pair_count)
    ‖ for each pair, sorted by key bytes ascending:
          LP(key) ‖ LP(value)           UTF-8
```

`U32(n)` is `n` as a 4-byte big-endian unsigned integer. `LP(x)` is `U32(len(x)) ‖ x`.

Length prefixes make the encoding injective: no two different (key_id, version, context) triples
produce the same AAD.

## 5. Errors

Implementations report these stable codes. API responses use the same strings.

| Code | Meaning |
| --- | --- |
| `format_invalid` | Not `kal:<ver>:…` with five non-empty parts |
| `format_unsupported_version` | Well-formed prefix with a version other than `v1` |
| `key_id_invalid` | `key_id` fails its pattern |
| `key_version_invalid` | `version` fails its pattern or range |
| `payload_encoding_invalid` | Payload is not strict, canonical, unpadded base64url |
| `payload_too_short` | Decoded payload under 28 bytes |
| `payload_too_long` | Decoded payload over 65564 bytes |
| `context_invalid` | Context breaks a rule in §3 |
| `decrypt_failed` | Authentication failed |

`decrypt_failed` is deliberately one code. Wrong context, wrong key material and tampered bytes are
cryptographically indistinguishable, and reporting them separately would only help an attacker. The
API reports `context_mismatch` only when policy *requires* a context and the request has none.

Parsers check in this order and report the first failure:

1. first part is `kal` (else `format_invalid`);
2. second part is a format version (else `format_invalid`), and is `v1` (else
   `format_unsupported_version`, whatever the rest of the string looks like, since a future format
   may have a different shape);
3. exactly five parts, none empty (else `format_invalid`);
4. `key_id`, then key `version`, then payload encoding, then payload length.

The conformance vectors depend on that order.

## 6. Conformance

[`conformance/vectors/ciphertext-v1.json`](../conformance/vectors/ciphertext-v1.json) holds:

- `valid` — key, nonce, plaintext and context, with the exact AAD and ciphertext they produce;
- `parse_invalid` — strings every parser must reject, with the expected code;
- `decrypt_invalid` — well-formed strings whose decryption must fail;
- `context_invalid` — contexts every implementation must reject.

Contexts appear as `context_pairs`, a list of `[key, value]`, so that ordering and duplicate keys can
be expressed. SDKs never hold keys, so they check only the parse and context vectors. The crypto service checks all
four. The key material in the vectors is published test data and must never be used for real data.
