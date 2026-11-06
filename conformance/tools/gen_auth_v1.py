#!/usr/bin/env python3
"""Generate conformance/vectors/auth-v1.json.

This is an independent reference implementation of spec/auth-v1.md. It shares no code with the
Kallara platform on purpose, so the platform is checked against a second reading of the spec
rather than against itself.

Everything is deterministic: keys, IDs and nonce keys are derived from fixed labels, Ed25519 is
deterministic, and ES256 uses RFC 6979 deterministic signing, so the output is byte-identical on
every run. Implementations still treat ES256 cases as verify-only: their own ES256 signatures are
randomized and will not match.

    python gen_auth_v1.py            # rewrite the vectors file
    python gen_auth_v1.py --check    # exit 1 if the file is stale

Requires: cryptography>=50
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import struct
import sys
import uuid
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

OUT = Path(__file__).resolve().parents[1] / "vectors" / "auth-v1.json"
SEED = "kallara-conformance/auth-v1/"
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

NOW = 1798000000  # pinned "now" for every time-dependent case
WINDOW = 300
ISSUER = "kallara-sts"
API_AUDIENCE = "kallara-api"
TOKEN_URL = "https://sts.example.com/oauth/token"
ENROLL_URL = "https://sts.example.com/oauth/enroll"
API_URL = "https://api.example.com/v1/encrypt"


def derive(label: str, n: int) -> bytes:
    out, counter = b"", 0
    while len(out) < n:
        out += hashlib.sha256(f"{SEED}{label}/{counter}".encode()).digest()
        counter += 1
    return out[:n]


def derive_uuid(label: str) -> str:
    return str(uuid.UUID(bytes=derive(f"uuid/{label}", 16), version=4))


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_json(obj: dict) -> str:
    return b64u(json.dumps(obj, separators=(",", ":")).encode())


# --- Keys ----------------------------------------------------------------------------------------

class Key:
    def __init__(self, label: str, alg: str) -> None:
        self.alg = alg
        if alg == "EdDSA":
            self.priv = Ed25519PrivateKey.from_private_bytes(derive(f"ed25519/{label}", 32))
            raw = self.priv.public_key().public_bytes(serialization.Encoding.Raw,
                                                      serialization.PublicFormat.Raw)
            self.raw_public = raw
            self.jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64u(raw)}
        else:
            scalar = int.from_bytes(derive(f"p256/{label}", 48), "big") % (P256_ORDER - 1) + 1
            self.priv = ec.derive_private_key(scalar, ec.SECP256R1())
            nums = self.priv.public_key().public_numbers()
            x, y = nums.x.to_bytes(32, "big"), nums.y.to_bytes(32, "big")
            self.raw_public = x + y
            self.jwk = {"kty": "EC", "crv": "P-256", "x": b64u(x), "y": b64u(y)}

    def sign(self, data: bytes) -> bytes:
        if self.alg == "EdDSA":
            return self.priv.sign(data)
        der = self.priv.sign(data, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
        r, s = decode_dss_signature(der)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def thumbprint(jwk: dict) -> str:
    """RFC 7638: required members only, sorted, no whitespace, SHA-256, base64url."""
    members = ("crv", "kty", "x") if jwk["kty"] == "OKP" else ("crv", "kty", "x", "y")
    canon = json.dumps({m: jwk[m] for m in members}, separators=(",", ":"), sort_keys=True)
    return b64u(hashlib.sha256(canon.encode()).digest())


# RFC 8037 Appendix A.3: an independent check of the thumbprint code.
assert thumbprint({"kty": "OKP", "crv": "Ed25519",
                   "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}) == \
    "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"

HOST_ED = Key("host-ed25519", "EdDSA")
HOST_P256 = Key("host-p256", "ES256")
OTHER_ED = Key("other-ed25519", "EdDSA")
STS_A = Key("sts-a", "EdDSA")
STS_B = Key("sts-b", "EdDSA")
STS_A_KID, STS_B_KID = "sts-test-a", "sts-test-b"

ORG = derive_uuid("org")
IDENTITY = derive_uuid("identity")
HOST_KEY_ID = derive_uuid("host-key")
OIDC_RULE_ID = derive_uuid("oidc-rule")
NONCE_KEY = derive("nonce-key/service", 32)
OTHER_NONCE_KEY = derive("nonce-key/other-service", 32)


def jwt(header: dict, claims: dict, key: Key | None, *, alg: str | None = None) -> str:
    """Compact JWS. alg overrides the header alg (for bad_alg cases); key=None leaves it unsigned."""
    h = {"alg": alg or (key.alg if key else "none"), **header}
    signing_input = f"{b64u_json(h)}.{b64u_json(claims)}"
    if h["alg"] == "HS256":  # key-confusion attempt: the public key bytes used as an HMAC key
        assert key is not None
        sig = hmac.new(key.raw_public, signing_input.encode(), hashlib.sha256).digest()
    elif key is None:
        sig = b""
    else:
        sig = key.sign(signing_input.encode())
    return f"{signing_input}.{b64u(sig)}"


def claims_of(token: str) -> dict:
    p = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))


def tamper(token: str, **changes: object) -> str:
    """Swap the payload for an edited one while keeping the original signature."""
    h, _, s = token.split(".")
    return f"{h}.{b64u_json({**claims_of(token), **changes})}.{s}"


def nonce(key: bytes, now: int, offset: int = 0) -> str:
    """HMAC-SHA256 of the window number as an 8-byte big-endian unsigned integer."""
    window = now // WINDOW + offset
    return b64u(hmac.new(key, struct.pack(">Q", window), hashlib.sha256).digest())


def ath(token: str) -> str:
    return b64u(hashlib.sha256(token.encode("ascii")).digest())


def case(name: str, inp: dict, expect: str, output: dict | None = None) -> dict:
    c: dict = {"name": name, "input": inp, "expect": expect}
    if expect == "ok":
        assert output is not None, name
        c["output"] = output
    return c


# --- Access tokens -------------------------------------------------------------------------------

def access_claims(key: Key, *, iat: int = NOW - 100, lifetime: int = 900, aud: str = API_AUDIENCE,
                  amr: str = "host_key", label: str = "at") -> dict:
    return {
        "iss": ISSUER, "aud": aud, "sub": IDENTITY, "org": ORG, "iat": iat, "exp": iat + lifetime,
        "jti": derive_uuid(f"jti/{label}"), "cnf": {"jkt": thumbprint(key.jwk)},
        "kal_amr": amr, "kal_cred": HOST_KEY_ID if amr == "host_key" else OIDC_RULE_ID,
    }


def sts_jwk(key: Key, kid: str) -> dict:
    return {**key.jwk, "kid": kid, "alg": "EdDSA", "use": "sig"}


JWKS_A = {"keys": [sts_jwk(STS_A, STS_A_KID)]}
JWKS_AB = {"keys": [sts_jwk(STS_A, STS_A_KID), sts_jwk(STS_B, STS_B_KID)]}

AT_ED = jwt({"kid": STS_A_KID}, access_claims(HOST_ED, label="at-ed"), STS_A)
AT_P256 = jwt({"kid": STS_A_KID}, access_claims(HOST_P256, label="at-p256"), STS_A)


def access_token_vectors() -> list[dict]:
    def inp(token: str, jwks: dict = JWKS_A) -> dict:
        return {"access_token": token, "jwks": jwks, "audience": API_AUDIENCE, "now": NOW}

    oidc_claims = access_claims(HOST_ED, amr="oidc", label="at-oidc")
    next_key_claims = access_claims(HOST_ED, label="at-next-key")
    expired_claims = access_claims(HOST_ED, iat=NOW - 1000, label="at-expired")
    # Access tokens get exactly 30 s of leeway on exp and iat.
    leeway = {name: access_claims(HOST_ED, iat=NOW + off, label=f"at-{name}") for name, off in
              [("exp-30", -930), ("exp-31", -931), ("iat-30", 30), ("iat-31", 31)]}
    hk = access_claims(HOST_ED, label="at-bad")
    return [
        case("host-key-token", inp(AT_ED), "ok", {"claims": access_claims(HOST_ED, label="at-ed")}),
        case("oidc-token", inp(jwt({"kid": STS_A_KID}, oidc_claims, STS_A)), "ok",
             {"claims": oidc_claims}),
        case("signed-by-second-published-key", inp(jwt({"kid": STS_B_KID}, next_key_claims, STS_B),
                                                   JWKS_AB), "ok", {"claims": next_key_claims}),
        case("signed-by-wrong-key", inp(jwt({"kid": STS_A_KID}, hk, STS_B)), "bad_signature"),
        case("unknown-kid", inp(jwt({"kid": STS_B_KID}, hk, STS_B)), "bad_signature"),
        case("claims-tampered", inp(tamper(AT_ED, org=derive_uuid("other-org"))), "bad_signature"),
        case("alg-none", inp(jwt({"kid": STS_A_KID}, hk, None)), "bad_alg"),
        case("alg-hs256-key-confusion", inp(jwt({"kid": STS_A_KID}, hk, STS_A, alg="HS256")),
             "bad_alg"),
        case("alg-es256-on-eddsa-key", inp(jwt({"kid": STS_A_KID}, hk, STS_A, alg="ES256")),
             "bad_alg"),
        case("expired", inp(jwt({"kid": STS_A_KID}, expired_claims, STS_A)), "expired"),
        case("expired-30s-ago-within-leeway", inp(jwt({"kid": STS_A_KID}, leeway["exp-30"], STS_A)),
             "ok", {"claims": leeway["exp-30"]}),
        case("expired-31s-ago", inp(jwt({"kid": STS_A_KID}, leeway["exp-31"], STS_A)), "expired"),
        case("iat-30s-in-future-within-leeway", inp(jwt({"kid": STS_A_KID}, leeway["iat-30"], STS_A)),
             "ok", {"claims": leeway["iat-30"]}),
        case("iat-31s-in-future", inp(jwt({"kid": STS_A_KID}, leeway["iat-31"], STS_A)),
             "iat_out_of_window"),
        case("audience-manage", inp(jwt({"kid": STS_A_KID}, access_claims(
            HOST_ED, aud="kallara-manage", label="at-manage"), STS_A)), "wrong_audience"),
        case("audience-other-service", inp(jwt({"kid": STS_A_KID}, access_claims(
            HOST_ED, aud="kallara-sts-internal", label="at-internal"), STS_A)), "wrong_audience"),
        case("lifetime-901s", inp(jwt({"kid": STS_A_KID}, access_claims(
            HOST_ED, lifetime=901, label="at-901"), STS_A)), "lifetime_too_long"),
        case("lifetime-1h", inp(jwt({"kid": STS_A_KID}, access_claims(
            HOST_ED, lifetime=3600, label="at-3600"), STS_A)), "lifetime_too_long"),
    ]


# --- DPoP proofs ---------------------------------------------------------------------------------

def proof_claims(label: str, *, htm: str = "POST", htu: str = TOKEN_URL, iat: int = NOW,
                 nonce_value: str | None = "", access_token: str | None = None) -> dict:
    c: dict = {"jti": derive_uuid(f"proof/{label}"), "htm": htm, "htu": htu, "iat": iat}
    if nonce_value is not None:
        c["nonce"] = nonce_value or nonce(NONCE_KEY, NOW)
    if access_token is not None:
        c["ath"] = ath(access_token)
    return c


def proof(key: Key, claims: dict, *, typ: str | None = "dpop+jwt", alg: str | None = None,
          signer: Key | None = None) -> str:
    header: dict = {} if typ is None else {"typ": typ}
    header["jwk"] = key.jwk
    return jwt(header, claims, None if alg == "none" else signer or key, alg=alg)


def dpop_proof_vectors() -> list[dict]:
    def at_token(p: str, *, url: str = TOKEN_URL, now: int = NOW) -> dict:
        return {"proof": p, "method": "POST", "url": url, "now": now, "nonce_key_hex": NONCE_KEY.hex()}

    def at_api(p: str, token: str = AT_ED, jkt: str | None = None, **kw: object) -> dict:
        d = at_token(p, url=API_URL, **kw)
        d["access_token"] = token
        d["cnf_jkt"] = jkt or thumbprint(HOST_ED.jwk)
        return d

    def ok(p: str, key: Key) -> dict:
        return {"jkt": thumbprint(key.jwk), "jti": claims_of(p)["jti"]}

    pc = proof_claims

    def api(label: str, token: str = AT_ED, **kw: object) -> dict:
        return proof_claims(label, htu=API_URL, access_token=token, **kw)

    # A request a few seconds into a new window, carrying the nonce of the window before.
    boundary_now = (NOW // WINDOW + 1) * WINDOW + 5
    prev_nonce = nonce(NONCE_KEY, boundary_now, -1)

    p_tok_ed = proof(HOST_ED, pc("tok-ed"))
    p_tok_p256 = proof(HOST_P256, pc("tok-p256"))
    p_api_ed = proof(HOST_ED, api("api-ed"))
    p_api_p256 = proof(HOST_P256, api("api-p256", token=AT_P256))
    p_prev = proof(HOST_ED, pc("prev-window", iat=boundary_now, nonce_value=prev_nonce))
    p_iat_past = proof(HOST_ED, pc("iat-minus-60", iat=NOW - 60))
    p_iat_future = proof(HOST_ED, pc("iat-plus-60", iat=NOW + 60))
    p_query = proof(HOST_ED, pc("htu-query", htu=TOKEN_URL + "?x=1#frag"))
    p_norm = proof(HOST_ED, pc("htu-normalized", htu="HTTPS://STS.Example.COM:443/oauth/token"))

    return [
        case("token-endpoint-ed25519", at_token(p_tok_ed), "ok", ok(p_tok_ed, HOST_ED)),
        case("token-endpoint-es256", at_token(p_tok_p256), "ok", ok(p_tok_p256, HOST_P256)),
        case("api-ed25519", at_api(p_api_ed), "ok", ok(p_api_ed, HOST_ED)),
        case("api-es256", at_api(p_api_p256, AT_P256, thumbprint(HOST_P256.jwk)), "ok",
             ok(p_api_p256, HOST_P256)),
        case("nonce-previous-window", at_token(p_prev, now=boundary_now), "ok",
             ok(p_prev, HOST_ED)),
        case("iat-60s-in-past", at_token(p_iat_past), "ok", ok(p_iat_past, HOST_ED)),
        case("iat-60s-in-future", at_token(p_iat_future), "ok", ok(p_iat_future, HOST_ED)),
        case("htu-query-and-fragment-ignored", at_token(p_query), "ok", ok(p_query, HOST_ED)),
        case("htu-case-and-default-port-normalized", at_token(p_norm), "ok", ok(p_norm, HOST_ED)),

        case("signed-by-other-key", at_token(proof(HOST_ED, pc("sig-other"), signer=OTHER_ED)),
             "bad_signature"),
        case("claims-tampered", at_token(tamper(p_tok_ed, jti=derive_uuid("proof/tampered"))), "bad_signature"),
        case("es256-claims-tampered", at_token(tamper(p_tok_p256, iat=NOW + 1)), "bad_signature"),
        case("typ-jwt", at_token(proof(HOST_ED, pc("typ-jwt"), typ="JWT")), "bad_typ"),
        case("typ-missing", at_token(proof(HOST_ED, pc("typ-missing"), typ=None)), "bad_typ"),
        case("typ-enrollment", at_token(proof(HOST_ED, pc("typ-enroll"), typ="kal-enroll+jwt")),
             "bad_typ"),
        case("alg-none", at_token(proof(HOST_ED, pc("alg-none"), alg="none")), "bad_alg"),
        case("alg-hs256-key-confusion", at_token(proof(HOST_ED, pc("alg-hs256"), alg="HS256")),
             "bad_alg"),
        case("alg-es256-on-okp-key", at_token(proof(HOST_ED, pc("alg-mismatch"), alg="ES256")),
             "bad_alg"),
        case("htm-get-for-post", at_token(proof(HOST_ED, pc("htm-get", htm="GET"))),
             "htm_mismatch"),
        case("htm-lowercase", at_token(proof(HOST_ED, pc("htm-lower", htm="post"))),
             "htm_mismatch"),
        case("htu-other-path", at_token(proof(HOST_ED, pc(
            "htu-path", htu="https://sts.example.com/oauth/enroll"))), "htu_mismatch"),
        case("htu-http-scheme", at_token(proof(HOST_ED, pc(
            "htu-http", htu="http://sts.example.com/oauth/token"))), "htu_mismatch"),
        case("htu-other-host", at_token(proof(HOST_ED, pc(
            "htu-host", htu="https://sts.example.net/oauth/token"))), "htu_mismatch"),
        case("htu-trailing-slash", at_token(proof(HOST_ED, pc(
            "htu-slash", htu=TOKEN_URL + "/"))), "htu_mismatch"),
        case("iat-61s-in-past", at_token(proof(HOST_ED, pc("iat-m61", iat=NOW - 61))),
             "iat_out_of_window"),
        case("iat-61s-in-future", at_token(proof(HOST_ED, pc("iat-p61", iat=NOW + 61))),
             "iat_out_of_window"),
        case("iat-one-hour-old", at_token(proof(HOST_ED, pc("iat-old", iat=NOW - 3600))),
             "iat_out_of_window"),
        case("ath-of-other-token", at_api(proof(HOST_ED, api("ath-other", token=AT_P256))),
             "ath_mismatch"),
        case("ath-missing", at_api(proof(HOST_ED, pc("ath-missing", htu=API_URL))), "ath_mismatch"),
        case("proof-key-not-token-key", at_api(proof(HOST_P256, api("jkt-other"))), "jkt_mismatch"),
        case("nonce-missing-token-endpoint",
             at_token(proof(HOST_ED, pc("nonce-missing", nonce_value=None))), "nonce_missing"),
        case("nonce-missing-api",
             at_api(proof(HOST_ED, api("nonce-missing-api", nonce_value=None))), "nonce_missing"),
        case("nonce-two-windows-old", at_token(proof(HOST_ED, pc(
            "nonce-old", nonce_value=nonce(NONCE_KEY, NOW, -2)))), "nonce_invalid"),
        case("nonce-next-window", at_token(proof(HOST_ED, pc(
            "nonce-next", nonce_value=nonce(NONCE_KEY, NOW, 1)))), "nonce_invalid"),
        case("nonce-from-other-service", at_token(proof(HOST_ED, pc(
            "nonce-other", nonce_value=nonce(OTHER_NONCE_KEY, NOW)))), "nonce_invalid"),
        case("nonce-garbage", at_token(proof(HOST_ED, pc("nonce-garbage", nonce_value="abc"))),
             "nonce_invalid"),
    ]


# --- Client assertions (RFC 7523) ----------------------------------------------------------------

def assertion_vectors() -> list[dict]:
    def inp(a: str, key: Key = HOST_ED, audience: str = TOKEN_URL) -> dict:
        return {"client_assertion": a, "client_id": IDENTITY, "audience": audience, "now": NOW,
                "host_key": {**key.jwk, "kid": HOST_KEY_ID}}

    def claims(label: str, *, iat: int = NOW, lifetime: int = 60, aud: str = TOKEN_URL) -> dict:
        return {"iss": IDENTITY, "sub": IDENTITY, "aud": aud, "iat": iat, "exp": iat + lifetime,
                "jti": derive_uuid(f"assert/{label}")}

    def sign(c: dict, key: Key = HOST_ED, typ: str | None = None, **kw: object) -> str:
        return jwt({"kid": HOST_KEY_ID} | ({"typ": typ} if typ else {}), c, key, **kw)

    c_ed, c_p256, c_short = claims("ed"), claims("p256"), claims("short", lifetime=1)
    a_ed = sign(c_ed)
    return [
        case("ed25519", inp(a_ed), "ok", {"jti": c_ed["jti"]}),
        case("es256", inp(sign(c_p256, HOST_P256), HOST_P256), "ok", {"jti": c_p256["jti"]}),
        case("one-second-lifetime", inp(sign(c_short)), "ok", {"jti": c_short["jti"]}),
        case("signed-by-other-key", inp(sign(claims("other"), OTHER_ED)), "bad_signature"),
        case("claims-tampered", inp(tamper(a_ed, exp=NOW + 30)), "bad_signature"),
        case("alg-none", inp(sign(claims("none"), None)), "bad_alg"),
        case("alg-hs256-key-confusion", inp(sign(claims("hs256"), alg="HS256")), "bad_alg"),
        case("alg-es256-on-okp-key", inp(sign(claims("alg-mismatch"), alg="ES256")), "bad_alg"),
        case("expired", inp(sign(claims("expired", iat=NOW - 120))), "expired"),
        case("exp-equals-now", inp(sign(claims("exp-now", iat=NOW - 60))), "expired"),
        case("iat-in-future", inp(sign(claims("iat-future", iat=NOW + 120))), "iat_out_of_window"),
        case("typ-dpop", inp(sign(claims("typ-dpop"), typ="dpop+jwt")), "bad_typ"),
        case("typ-enrollment", inp(sign(claims("typ-enroll"), typ="kal-enroll+jwt")), "bad_typ"),
        case("typ-rotation", inp(sign(claims("typ-rotate"), typ="kal-rotate+jwt")), "bad_typ"),
        case("audience-api", inp(sign(claims("aud-api", aud=API_URL))), "wrong_audience"),
        case("audience-issuer-name", inp(sign(claims("aud-iss", aud=ISSUER))), "wrong_audience"),
        case("audience-enroll-endpoint", inp(sign(claims("aud-enroll", aud=ENROLL_URL))),
             "wrong_audience"),
        case("lifetime-61s", inp(sign(claims("life-61", lifetime=61))), "lifetime_too_long"),
        case("lifetime-1h", inp(sign(claims("life-1h", iat=NOW - 10, lifetime=3600))),
             "lifetime_too_long"),
    ]


# --- Enrollment requests -------------------------------------------------------------------------

def enrollment_vectors() -> list[dict]:
    def inp(r: str) -> dict:
        return {"enrollment_jwt": r, "audience": ENROLL_URL, "now": NOW}

    def claims(label: str, *, iat: int = NOW, aud: str = ENROLL_URL) -> dict:
        # The code is published test data: 32 derived bytes, base64url.
        return {"code": b64u(derive(f"code/{label}", 32)), "aud": aud, "iat": iat,
                "jti": derive_uuid(f"enroll/{label}")}

    def req(c: dict, key: Key = HOST_ED, *, typ: str = "kal-enroll+jwt",
            signer: Key | None = None, alg: str | None = None) -> str:
        return jwt({"typ": typ, "jwk": key.jwk}, c, None if alg == "none" else signer or key, alg=alg)

    def ok(c: dict, key: Key) -> dict:
        return {"jkt": thumbprint(key.jwk), "code": c["code"], "jti": c["jti"]}

    c_ed, c_p256 = claims("ed"), claims("p256")
    r_ed = req(c_ed)
    return [
        case("ed25519", inp(r_ed), "ok", ok(c_ed, HOST_ED)),
        case("es256", inp(req(c_p256, HOST_P256)), "ok", ok(c_p256, HOST_P256)),
        case("signed-by-other-key", inp(req(claims("other"), signer=OTHER_ED)), "bad_signature"),
        case("code-tampered", inp(tamper(r_ed, code=b64u(derive("code/stolen", 32)))),
             "bad_signature"),
        case("typ-dpop", inp(req(claims("typ-dpop"), typ="dpop+jwt")), "bad_typ"),
        case("typ-rotate", inp(req(claims("typ-rotate"), typ="kal-rotate+jwt")), "bad_typ"),
        case("alg-none", inp(req(claims("none"), alg="none")), "bad_alg"),
        case("alg-hs256-key-confusion", inp(req(claims("hs256"), alg="HS256")), "bad_alg"),
        case("audience-token-endpoint", inp(req(claims("aud-token", aud=TOKEN_URL))),
             "wrong_audience"),
        case("iat-61s-in-past", inp(req(claims("iat-past", iat=NOW - 61))), "iat_out_of_window"),
        case("iat-61s-in-future", inp(req(claims("iat-future", iat=NOW + 61))),
             "iat_out_of_window"),
    ]


# --- Thumbprints (RFC 7638) ----------------------------------------------------------------------

def thumbprint_vectors() -> list[dict]:
    rfc8037 = {"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
    extra = {"kid": "host-1", "use": "sig", "alg": "ES256", **HOST_P256.jwk}
    return [
        case("rfc8037-appendix-a3", {"jwk": rfc8037}, "ok", {"jkt": thumbprint(rfc8037)}),
        case("ed25519", {"jwk": HOST_ED.jwk}, "ok", {"jkt": thumbprint(HOST_ED.jwk)}),
        case("p256", {"jwk": HOST_P256.jwk}, "ok", {"jkt": thumbprint(HOST_P256.jwk)}),
        case("p256-extra-members-ignored", {"jwk": extra}, "ok", {"jkt": thumbprint(extra)}),
    ]


def build() -> str:
    doc = {
        "$schema": "../schema/auth-v1.schema.json",
        "spec": "spec/auth-v1.md",
        "generator": "conformance/tools/gen_auth_v1.py",
        "warning": "Published test keys, codes and tokens. Never use them for real workloads.",
        "thumbprints": thumbprint_vectors(),
        "dpop_proofs": dpop_proof_vectors(),
        "client_assertions": assertion_vectors(),
        "enrollment_requests": enrollment_vectors(),
        "access_tokens": access_token_vectors(),
    }
    return json.dumps(doc, indent=2, ensure_ascii=True) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="fail if the file is out of date")
    args = ap.parse_args()
    text = build()
    if args.check:
        if not OUT.exists() or OUT.read_text() != text:
            print(f"{OUT} is stale; run gen_auth_v1.py", file=sys.stderr)
            return 1
        print(f"{OUT.name} is up to date")
        return 0
    OUT.write_text(text)
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
