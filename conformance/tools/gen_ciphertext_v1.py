#!/usr/bin/env python3
"""Generate conformance/vectors/ciphertext-v1.json.

This is an independent reference implementation of spec/ciphertext-v1.md. It shares no code
with the Kallara platform on purpose, so the platform is checked against a second reading of
the spec rather than against itself.

Everything is deterministic: key material and nonces are derived from fixed labels, so the
output is byte-identical on every run.

    python gen_ciphertext_v1.py            # rewrite the vectors file
    python gen_ciphertext_v1.py --check    # exit 1 if the file is stale

Requires: cryptography>=50
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import struct
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

OUT = Path(__file__).resolve().parents[1] / "vectors" / "ciphertext-v1.json"
SEED = "kallara-conformance/ciphertext-v1/"
CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
NONCE_LEN, TAG_LEN, MAX_PLAINTEXT = 12, 16, 65536


def derive(label: str, n: int) -> bytes:
    out, counter = b"", 0
    while len(out) < n:
        out += hashlib.sha256(f"{SEED}{label}/{counter}".encode()).digest()
        counter += 1
    return out[:n]


def key_id_from(raw16: bytes) -> str:
    """128 bits -> 26 Crockford base32 chars (2 leading zero bits)."""
    n = int.from_bytes(raw16, "big")
    chars = [CROCKFORD[(n >> (5 * i)) & 31] for i in range(26)]
    return "k_" + "".join(reversed(chars))


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def u32(n: int) -> bytes:
    return struct.pack(">I", n)


def lp(b: bytes) -> bytes:
    return u32(len(b)) + b


def aad(key_id: str, version: int, pairs: list[list[str]]) -> bytes:
    items = sorted((k.encode(), v.encode()) for k, v in pairs)
    out = b"kal:v1" + lp(key_id.encode("ascii")) + u32(version) + u32(len(items))
    for k, v in items:
        out += lp(k) + lp(v)
    return out


KEYS = {
    "key-a": {"version": 3},
    "key-b": {"version": 2147483647},
}
for name, k in KEYS.items():
    k["key_id"] = key_id_from(derive(f"key-id/{name}", 16))
    k["algorithm"] = "AES-256-GCM"
    k["material_hex"] = derive(f"key/{name}", 32).hex()


def seal(key: str, label: str, plaintext: bytes, pairs: list[list[str]], *,
         version: int | None = None) -> tuple[str, bytes, bytes]:
    k = KEYS[key]
    ver = k["version"] if version is None else version
    nonce = derive(f"nonce/{label}", NONCE_LEN)
    a = aad(k["key_id"], ver, pairs)
    body = AESGCM(bytes.fromhex(k["material_hex"])).encrypt(nonce, plaintext, a)
    return f"kal:v1:{k['key_id']}:{ver}:{b64u(nonce + body)}", nonce, a


def valid_vectors() -> list[dict]:
    limit_pairs = [[f"k{i:02d}", "v"] for i in range(15)] + [["K" * 64, "x" * 256]]
    cases = [
        ("empty-plaintext-no-context", "Zero-length plaintext, no context", "key-a", b"", []),
        ("phone-number-row-context", "The README example", "key-a", b"9876543210",
         [["table", "customers"], ["row", "42"]]),
        ("context-sorted-by-key-bytes", "Pairs given unsorted; AAD sorts them; empty value",
         "key-a", b"sort me", [["z", "1"], ["a", "2"], ["m", ""]]),
        ("context-sort-is-bytewise", "Uppercase sorts before lowercase", "key-a", b"case",
         [["b", "1"], ["B", "2"], ["_", "3"]]),
        ("utf8-plaintext-and-value", "Malayalam text in plaintext and context value", "key-a",
         "കല്ലറ".encode(), [["name", "ശരി"]]),
        ("binary-plaintext-1kib", "1024 bytes of binary data", "key-a",
         derive("pt/binary", 1024), [["file", "blob.bin"]]),
        ("max-version", "Largest allowed key version", "key-b", b"max version", []),
        ("context-at-limits", "16 pairs, 64-byte key, 256-byte value", "key-b", b"limits",
         limit_pairs),
        ("max-plaintext", "65536-byte plaintext, the largest allowed", "key-a",
         b"\x5a" * MAX_PLAINTEXT, []),
    ]
    out = []
    for vid, desc, key, pt, pairs in cases:
        ct, nonce, a = seal(key, vid, pt, pairs)
        v = {"id": vid, "description": desc, "key": key, "context_pairs": pairs,
             "nonce_hex": nonce.hex(), "aad_hex": a.hex(), "ciphertext": ct}
        if len(pt) > 4096:
            v["plaintext_fill"] = {"byte_hex": f"{pt[0]:02x}", "length": len(pt)}
        else:
            v["plaintext_hex"] = pt.hex()
        out.append(v)
    return out


def parse_invalid_vectors() -> list[dict]:
    kid = KEYS["key-a"]["key_id"]
    good, _, _ = seal("key-a", "parse-base", b"hello!", [])
    payload = good.rsplit(":", 1)[1]

    def with_payload(p: str) -> str:
        return f"kal:v1:{kid}:3:{p}"

    # A canonical payload whose last char carries non-zero unused bits.
    raw = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
    assert len(raw) % 3 != 0, "base payload must leave unused bits"
    last = payload[-1]
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    bumped = alphabet[alphabet.index(last) + 1]
    noncanonical = payload[:-1] + bumped

    too_long = b64u(derive("pt/too-long", NONCE_LEN + MAX_PLAINTEXT + TAG_LEN + 1))
    too_short = b64u(derive("pt/too-short", NONCE_LEN + TAG_LEN - 1))
    shortest_ok = b64u(derive("pt/shortest", NONCE_LEN + TAG_LEN))
    bad_kid = "k_" + "I" + kid[3:]

    cases = [
        ("empty-string", "", "format_invalid"),
        ("four-parts", f"kal:v1:{kid}:3", "format_invalid"),
        ("six-parts", f"{good}:extra", "format_invalid"),
        ("empty-key-id", f"kal:v1::3:{payload}", "format_invalid"),
        ("uppercase-prefix", good.replace("kal:", "KAL:", 1), "format_invalid"),
        ("wrong-prefix", good.replace("kal:", "kel:", 1), "format_invalid"),
        ("version-v0", good.replace(":v1:", ":v0:", 1), "format_invalid"),
        ("version-leading-zero", good.replace(":v1:", ":v01:", 1), "format_invalid"),
        ("version-not-numeric", good.replace(":v1:", ":vx:", 1), "format_invalid"),
        ("future-format-v2", good.replace(":v1:", ":v2:", 1), "format_unsupported_version"),
        ("future-format-v10", good.replace(":v1:", ":v10:", 1), "format_unsupported_version"),
        ("key-id-lowercase", f"kal:v1:{kid.lower()}:3:{payload}", "key_id_invalid"),
        ("key-id-excluded-letter", f"kal:v1:{bad_kid}:3:{payload}", "key_id_invalid"),
        ("key-id-too-short", f"kal:v1:{kid[:-1]}:3:{payload}", "key_id_invalid"),
        ("key-id-wrong-prefix", f"kal:v1:key_{kid[2:]}:3:{payload}", "key_id_invalid"),
        ("key-id-checked-before-version", f"kal:v1:{kid.lower()}:0:{payload}", "key_id_invalid"),
        ("key-version-zero", f"kal:v1:{kid}:0:{payload}", "key_version_invalid"),
        ("key-version-leading-zero", f"kal:v1:{kid}:03:{payload}", "key_version_invalid"),
        ("key-version-signed", f"kal:v1:{kid}:+3:{payload}", "key_version_invalid"),
        ("key-version-negative", f"kal:v1:{kid}:-3:{payload}", "key_version_invalid"),
        ("key-version-overflow", f"kal:v1:{kid}:2147483648:{payload}", "key_version_invalid"),
        ("payload-padded", with_payload(payload + "=" * (-len(payload) % 4 or 4)),
         "payload_encoding_invalid"),
        ("payload-standard-alphabet", with_payload("+" + payload[1:]), "payload_encoding_invalid"),
        ("payload-whitespace", with_payload(payload[:8] + " " + payload[8:]),
         "payload_encoding_invalid"),
        ("payload-non-ascii", with_payload(payload[:-1] + "é"), "payload_encoding_invalid"),
        ("payload-length-mod4-is-1", with_payload(payload + "A" * ((1 - len(payload)) % 4)),
         "payload_encoding_invalid"),
        ("payload-non-canonical-bits", with_payload(noncanonical), "payload_encoding_invalid"),
        ("payload-27-bytes", with_payload(too_short), "payload_too_short"),
        ("payload-over-max", with_payload(too_long), "payload_too_long"),
    ]
    out = [{"id": i, "ciphertext": c, "error": e} for i, c, e in cases]
    # One boundary case that must PARSE (it will fail later, at decrypt).
    out.append({"id": "payload-28-bytes-parses", "ciphertext": with_payload(shortest_ok),
                "error": None})
    return out


def decrypt_invalid_vectors() -> list[dict]:
    ctx = [["table", "customers"], ["row", "42"]]
    good, _, _ = seal("key-a", "decrypt-base", b"9876543210", ctx)
    head, payload = good.rsplit(":", 1)
    raw = bytearray(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))

    def flip(i: int) -> str:
        b = bytearray(raw)
        b[i] ^= 0x01
        return f"{head}:{b64u(bytes(b))}"

    kid_a, kid_b = KEYS["key-a"]["key_id"], KEYS["key-b"]["key_id"]
    cases = [
        ("tag-bit-flipped", "key-a", flip(len(raw) - 1), ctx),
        ("nonce-bit-flipped", "key-a", flip(0), ctx),
        ("ciphertext-bit-flipped", "key-a", flip(NONCE_LEN), ctx),
        ("byte-removed", "key-a", f"{head}:{b64u(bytes(raw[:-1]))}", ctx),
        ("wrong-context-value", "key-a", good, [["table", "customers"], ["row", "43"]]),
        ("context-missing", "key-a", good, []),
        ("context-extra-pair", "key-a", good, ctx + [["tenant", "x"]]),
        ("version-in-header-changed", "key-a", good.replace(f"{kid_a}:3:", f"{kid_a}:4:"), ctx),
        ("key-id-in-header-changed", "key-a", good.replace(kid_a, kid_b), ctx),
        ("wrong-key-material", "key-b", good, ctx),
    ]
    return [{"id": i, "key": k, "ciphertext": c, "context_pairs": p, "error": "decrypt_failed"}
            for i, k, c, p in cases]


def context_invalid_vectors() -> list[dict]:
    cases = [
        ("too-many-pairs", [[f"k{i:02d}", "v"] for i in range(17)], []),
        ("empty-key", [["", "v"]], []),
        ("key-65-bytes", [["k" * 65, "v"]], []),
        ("key-with-space", [["row id", "42"]], []),
        ("key-with-colon", [["a:b", "1"]], []),
        ("key-non-ascii", [["naïve", "1"]], []),
        ("value-257-bytes", [["k", "v" * 257]], []),
        ("value-258-utf8-bytes-86-chars", [["k", "ശ" * 86]], []),
        ("duplicate-key", [["row", "1"], ["row", "2"]], ["duplicate_keys"]),
    ]
    out = [{"id": i, "context_pairs": p, "error": "context_invalid", "tags": t}
           for i, p, t in cases]
    out.append({"id": "value-not-a-string", "context_pairs": [["row", 42]],
                "error": "context_invalid", "tags": ["non_string_value"]})
    out.append({"id": "value-lone-surrogate", "context_pairs": [["row", "\ud800"]],
                "error": "context_invalid", "tags": ["invalid_utf8"]})
    return out


def build() -> str:
    doc = {
        "$schema": "../schema/ciphertext-v1.schema.json",
        "spec": "spec/ciphertext-v1.md",
        "format": "kal:v1",
        "generator": "conformance/tools/gen_ciphertext_v1.py",
        "warning": "Published test keys. Never use this key material for real data.",
        "keys": KEYS,
        "valid": valid_vectors(),
        "parse_invalid": parse_invalid_vectors(),
        "decrypt_invalid": decrypt_invalid_vectors(),
        "context_invalid": context_invalid_vectors(),
    }
    return json.dumps(doc, indent=2, ensure_ascii=True) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="fail if the file is out of date")
    args = ap.parse_args()
    text = build()
    if args.check:
        if not OUT.exists() or OUT.read_text() != text:
            print(f"{OUT} is stale; run gen_ciphertext_v1.py", file=sys.stderr)
            return 1
        print(f"{OUT.name} is up to date")
        return 0
    OUT.write_text(text)
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
