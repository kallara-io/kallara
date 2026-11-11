# Kallara authentication v1

Status: **Draft** · Applies to the token service, the `/v1` API and the `/manage/v1` API

A workload proves who it is to the Kallara token service, with an enrolled host key or an OIDC
token from a platform it runs on, and gets back a 15-minute access token. Every access token is
bound to a key the workload holds (DPoP, RFC 9449), so a copied token is useless without that key.
There are no refresh tokens for workloads: when a token expires, the workload proves itself again.
People sign in with a browser and a passkey and get a refresh token (§11).

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Common rules

**JWTs** are compact JWS (RFC 7515), base64url without padding. Every JWT in this spec is signed
with one of:

| `alg` | Key | Signature |
| --- | --- | --- |
| `EdDSA` | Ed25519 (RFC 8037), JWK `kty=OKP`, `crv=Ed25519` | 64 bytes |
| `ES256` | ECDSA P-256 with SHA-256, JWK `kty=EC`, `crv=P-256` | 64 bytes, `r ‖ s`, not DER |

Access tokens use `EdDSA` only. A verifier MUST refuse `none`, every HMAC algorithm, every other
algorithm, and an `alg` that does not match the key's type. It MUST NOT let the token choose the
algorithm. It checks `alg` (allowed, and matching the key's type) **before** the signature, so a
JWT with a bad `alg` is refused as such whether or not its signature would verify.
A verifier MUST refuse an Ed25519 public key of small order (any encoding of one of the eight
points that multiplication by 8 sends to the identity, against which signatures can be forged without
a private key) wherever a JWT carries its key in a `jwk` header: DPoP proofs, enrollment JWTs and
new-key proofs.

**Thumbprints** (`jkt`) are RFC 7638 JWK thumbprints with SHA-256: the required members only
(`crv kty x` for OKP, `crv kty x y` for EC), in that order, no whitespace, hashed, base64url.

**Times** are seconds since the Unix epoch. DPoP proofs, client assertions, enrollment JWTs and
new-key proofs have their own exact windows (§3, §4.1, §5): a verifier adds no leeway to them.
Access tokens and OIDC tokens are checked with exactly 30 seconds of leeway (§4.2, §6).

**Identifiers.** The workload identity ID, the org ID and the host key ID are opaque strings
(today, lowercase UUIDs). Clients store and echo them; they never parse them.

## 2. Discovery

The token service publishes:

- `GET /.well-known/oauth-authorization-server`: RFC 8414 metadata.

  | Member | Value |
  | --- | --- |
  | `issuer` | the token service's public base URL |
  | `token_endpoint` | `<base>/oauth/token` |
  | `jwks_uri` | `<base>/.well-known/jwks.json` |
  | `authorization_endpoint` | `<base>/oauth/authorize` |
  | `revocation_endpoint` | `<base>/oauth/revoke` |
  | `grant_types_supported` | `client_credentials`, `urn:ietf:params:oauth:grant-type:token-exchange`, `authorization_code`, `refresh_token` |
  | `response_types_supported` | `code` |
  | `code_challenge_methods_supported` | `S256` |
  | `authorization_response_iss_parameter_supported` | `true` |
  | `token_endpoint_auth_methods_supported` | `private_key_jwt`, `none` |
  | `token_endpoint_auth_signing_alg_values_supported` | `EdDSA`, `ES256` |
  | `dpop_signing_alg_values_supported` | `EdDSA`, `ES256` |
  | `kallara_enrollment_endpoint` | `<base>/oauth/enroll` |
  | `kallara_host_key_rotation_endpoint` | `<base>/oauth/host-keys/rotate` |

  The metadata `issuer` is a URL as RFC 8414 requires. The `iss` claim of access tokens is the
  fixed string `kallara-sts` (§6).

- `GET /.well-known/jwks.json`: the public keys that sign access tokens, as a JWK Set. Each key has
  `kty=OKP`, `crv=Ed25519`, `x`, `kid`, `alg=EdDSA` and `use=sig`. Retired keys are not listed.
  The response carries `Cache-Control: max-age=60`.

A new signing key is published at least one hour before it signs anything, and an old one stays
published until an hour after its last token expires. In an emergency the service retires a key at
once; every token it signed stops working and clients simply fetch a new token.

## 3. DPoP proofs and nonces

Every request to the token endpoint, `/v1` and `/manage/v1` carries a `DPoP` header holding a proof
JWT (RFC 9449), signed by the workload's DPoP key. The exceptions are the unauthenticated
endpoints: the token service's discovery and JWKS documents (§2), `GET /v1/jwks/{key_id}`, and the
enrollment and rotation endpoints (§5), which take no proof.

**Header:** `typ` = `dpop+jwt`, `alg` = `EdDSA` or `ES256`, `jwk` = the public key (no private
members).

**Claims:**

| Claim | Rule |
| --- | --- |
| `jti` | unique per proof |
| `htm` | the request method, exactly as sent (`POST`, uppercase) |
| `htu` | the request URL without query and fragment |
| `iat` | within ±60 s of the server's clock: `abs(now - iat) <= 60` |
| `nonce` | a server nonce (below), always required |
| `ath` | base64url(SHA-256(ASCII access token)); required when an access token is presented |

**`htu` matching.** The server compares `htu` with the endpoint's *configured public URL*, not the
URL a proxy forwarded, after exactly these normalizations of `htu`, and no others:

1. lower-case the scheme and the host;
2. drop the port if it is the scheme's default (`443` for `https`, `80` for `http`);
3. drop the query and the fragment.

The path is compared byte for byte: no percent-decoding, no dot-segment removal, and a trailing
slash is a different URL.

**Nonces** are stateless and change every 300 seconds:

```
window = floor(now / 300)
nonce  = base64url(HMAC-SHA256(nonce_key, U64(window)))
```

`U64(n)` is `n` as an 8-byte big-endian unsigned integer. `nonce_key` is a per-service key; nonces
from one service are not valid at another. A server accepts the nonce of the current window and
of the previous one, and nothing else. Every response from the token service, `/v1` and
`/manage/v1` carries a `DPoP-Nonce` header with the current nonce; clients use the latest one they
received. Because a proof must carry a recent nonce, proofs cannot be made in advance.

**One use per proof.** A server accepts each proof `jti` once per key for at least 10 minutes. A
second use is refused.

## 4. Token endpoint

`POST /oauth/token`, `Content-Type: application/x-www-form-urlencoded`, with a `DPoP` proof for
`POST` and the token endpoint URL (no `ath`). The proof key's thumbprint becomes the token's
`cnf.jkt`.

### 4.1 Host-key grant (RFC 7523 client authentication)

```
grant_type=client_credentials
client_id=<workload identity ID>
client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
client_assertion=<JWT signed by the host key>
```

The client assertion:

- header: `alg` (`EdDSA` or `ES256`, matching the host key) and `kid` = the host key ID. No `typ`
  is required, but an assertion MUST NOT carry `typ` `dpop+jwt`, `kal-enroll+jwt` or
  `kal-rotate+jwt`; one that does is refused, so no other Kallara JWT can stand in for it.
- claims: `iss` and `sub` = `client_id`; `aud` = the URL of the endpoint it is sent to, as a
  string (here the token endpoint URL); `iat`; `exp`; `jti`.
- `exp - iat <= 60`, `iat <= now + 60`, and `now < exp`.
- Each `jti` is accepted once per identity.
- The key named by `kid` must belong to `client_id`, be active and not be expired.

### 4.2 OIDC grant (RFC 8693 token exchange)

```
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
client_id=<workload identity ID>
subject_token_type=urn:ietf:params:oauth:token-type:jwt
subject_token=<OIDC token>
```

The caller names the identity; Kallara never searches for one. The token is accepted if one of
that identity's trust rules matches:

- signed with `RS256`, `ES256` or `EdDSA` under the issuer's keys, fetched over HTTPS from the
  issuer's OpenID configuration, or pinned in the rule;
- `iss` equals the rule's issuer exactly;
- `aud` is a single string equal to the rule's audience (default `kallara:<org_id>`); an array is
  refused, even one holding only that value;
- `sub` and every extra claim in the rule are exactly equal;
- `exp` and `iat` present, `exp - iat <= 86400`, and, with 30 s of leeway: not expired
  (`exp + 30 >= now`), not issued in the future (`iat - 30 <= now`), and, when `nbf` is present,
  already valid (`nbf - 30 <= now`).

### 4.3 Both grants

The org must be active and the identity must be a workload.

**Success:** `200`, `Cache-Control: no-store`:

```json
{
  "access_token": "<JWT>",
  "token_type": "DPoP",
  "expires_in": 900,
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "renewal_due": false
}
```

`renewal_due` is present on host-key grants only. It is `true` when the host key's enrollment
limit (§5) is less than 30 days away: the machine needs a fresh enrollment code soon.

**Errors** use the OAuth format (RFC 6749 §5.2), not problem+json, so any OAuth library can read
them:

| Status | Body | When |
| --- | --- | --- |
| `400` | `{"error":"use_dpop_nonce"}` plus a `DPoP-Nonce` header | the proof has no nonce or a stale one (RFC 9449 §8). Retry once with the new nonce. |
| `401` | `{"error":"invalid_client"}` | `grant_type=client_credentials` and the request fails for any reason other than the nonce, the rate limit or an unavailable backend: a bad assertion, a bad DPoP proof, an unknown identity, a revoked, pending or expired key, an inactive org |
| `400` | `{"error":"invalid_grant"}` | any other `grant_type` (including a missing or unknown one) and the request fails for any reason other than the nonce, the rate limit or an unavailable backend |
| `429` | `{"error":"slow_down"}` | too many requests for this identity or from this client address. Back off before retrying. |
| `503` | `{"error":"temporarily_unavailable"}` | a backend the service needs is down. Retry with backoff. |

The token endpoint is rate-limited per identity and per client address. The body is the same whatever the cause: a bad signature, an unknown identity, a revoked key, a
replayed proof and a malformed request all look alike, and take about the same time. The cause is
recorded only in Kallara's audit log. The nonce is checked before the credentials, so
`use_dpop_nonce` says nothing about them.

## 5. Host keys

A host key is an `Ed25519` or `P-256` key pair made on the machine, ideally in hardware. It
expires at most 90 days after it is made, and never later than 365 days after the machine was
first enrolled (the *enrollment limit*), however often it is rotated.

### 5.1 Enrollment

An admin creates a single-use enrollment code for one workload identity. It is 32 random bytes,
base64url, and expires within an hour.

`POST /oauth/enroll`, `Content-Type: application/x-www-form-urlencoded`, one parameter:

```
enrollment_jwt=<JWT signed by the new host key>
```

- header: `typ` = `kal-enroll+jwt`, `alg` (`EdDSA` or `ES256`), `jwk` = the new public key.
- claims: `code` (the enrollment code), `aud` = the enrollment endpoint URL, `iat` within ±60 s,
  `jti`.

The signature proves the caller holds the private key. On success the code is used up and the
response is `200`:

```json
{"key_id": "<host key ID>", "expires": "2027-02-04T10:00:00Z", "state": "active"}
```

`expires` is RFC 3339, UTC. `state` is `active`, or `pending` when a second admin must approve the
key before it can be used (for workloads with production access). The approver compares the key's
thumbprint with the one the machine printed. A pending key gets `invalid_client` at the token
endpoint until it is approved.

Every failure, including an unknown, used or expired code, answers `400 {"error":"invalid_grant"}`.
An unavailable backend answers `503 {"error":"temporarily_unavailable"}`. This endpoint takes no
DPoP proof. Enrollment and rotation (§5.2) are rate-limited per client address, and rotation also per
identity once its assertion verifies; too many requests answer `429 {"error":"slow_down"}`.

### 5.2 Rotation

`POST /oauth/host-keys/rotate`, form-encoded:

```
client_id=<workload identity ID>
client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
client_assertion=<JWT signed by the current host key, aud = the rotation endpoint URL>
new_key_proof=<JWT signed by the new host key>
```

The client assertion follows §4.1, with `aud` = the rotation endpoint URL and one more claim,
`new_jkt` = the RFC 7638 thumbprint (§1) of the new public key. The service refuses the request
unless `new_jkt` equals the thumbprint of the key in the new-key proof, so an assertion intercepted on
its way cannot be paired with someone else's key. The new-key proof:

- header: `typ` = `kal-rotate+jwt`, `alg`, `jwk` = the new public key.
- claims: `key_id` = the current key's ID (the assertion's `kid`), `aud` = the rotation endpoint
  URL, `iat` within ±60 s, `jti`.

On success the current key is retired in the same step, and the response has the enrollment
shape: `{"key_id", "expires", "state"}`. The new key's `expires` is at most 90 days away and never
past the enrollment limit.

| Status | Body | When |
| --- | --- | --- |
| `401` | `{"error":"invalid_client"}` | the assertion or the current key fails, including a key that has already expired |
| `400` | `{"error":"invalid_grant","error_description":"reenroll_required"}` | the assertion verifies, and less than one day remains before the enrollment limit |
| `400` | `{"error":"invalid_grant"}` | any other failure, such as a bad new-key proof or a `new_jkt` that does not match it |
| `429` | `{"error":"slow_down"}` | too many requests from this client address or for this identity |
| `503` | `{"error":"temporarily_unavailable"}` | a backend is down |

`reenroll_required` is the one error that names its cause, because the SDK must act on it: the
machine needs a fresh enrollment code from an admin. It is returned only after the client assertion
has verified, so it reveals nothing to someone without the current key. This endpoint takes no DPoP
proof.

## 6. Access tokens

Header: `alg` = `EdDSA`, `kid` = the signing key's ID in the JWKS.

| Claim | Value |
| --- | --- |
| `iss` | `kallara-sts` |
| `aud` | `kallara-api` |
| `sub` | the workload identity ID |
| `org` | the org ID |
| `iat`, `exp` | `exp - iat = 900` |
| `jti` | unique per token |
| `cnf` | `{"jkt": <thumbprint of the DPoP key>}` |
| `kal_amr` | `host_key` or `oidc` |
| `kal_cred` | the ID of the credential used: the host key or the OIDC trust rule |

A verifier accepts a token only if: `alg` is `EdDSA`; `kid` names a key in the current JWKS; the
signature verifies; `iss` is `kallara-sts`; `aud` is `kallara-api`; `exp - iat <= 900`; and, with
exactly 30 s of leeway, the token is not expired (`exp + 30 >= now`), not issued in the future
(`iat - 30 <= now`) and, if it has `nbf`, already valid (`nbf - 30 <= now`). Clients treat the token
as opaque.

Management tokens for `/manage/v1` are issued to people (§11). They carry `aud` = `kallara-manage`
and the same core claims, plus the people claims in §11.4. The verifier's rules are the same, with
`kallara-manage` as the expected audience.

## 7. Resource servers

### 7.1 Requests

```
Authorization: DPoP <access token>
DPoP: <proof for this method and URL, with ath>
```

The `Bearer` scheme is refused. The server checks the token (§6), the proof (§3) with `ath` equal
to the hash of this token, and that the proof key's thumbprint equals the token's `cnf.jkt`. Tokens
whose credential or identity has been revoked stop working on the next request, not when they
expire.

### 7.2 Errors

The APIs answer with problem+json as for every other `/v1` error:

| Status | Code | Headers |
| --- | --- | --- |
| `401` | `unauthenticated` | `WWW-Authenticate: DPoP error="use_dpop_nonce"` and `DPoP-Nonce`, when the nonce is missing or stale |
| `401` | `unauthenticated` | `WWW-Authenticate: DPoP algs="EdDSA ES256"`, for every other token or proof failure |
| `503` | `unavailable` | the service cannot check replay or revocation; it never lets a request through unchecked |

A client that gets `use_dpop_nonce` retries once with the new nonce. A client that gets any other
`401` fetches a new access token and retries once.

### 7.3 Verifying keys

Verifiers fetch the JWKS at startup and cache it, choose the key by `kid`, re-fetch on an unknown
`kid` at most once every 30 seconds, re-fetch every 5 minutes, and drop any key that is no longer
in the set. Until they hold keys they answer `503 unavailable`.

## 8. SDK duties

- Keep the host key and the DPoP key in hardware when the platform offers it (TPM, Secure Enclave,
  Windows CNG, PKCS#11). Use `ES256` there if `EdDSA` is not available. Otherwise store the key
  readable only by the workload's user. Never export it.
- At enrollment, print the key's thumbprint so an admin can compare it.
- Rotate the host key once two-thirds of its life (from when it was made to `expires`) has passed.
- On `reenroll_required`, stop rotating and report that the machine needs a new enrollment code.
  Report `renewal_due: true` the same way, early. If the host key has already expired, the token
  and rotation endpoints answer `401 invalid_client`; the only way back is to enroll a new key with
  a fresh code.
- On `429 slow_down` or `503 temporarily_unavailable`, back off exponentially, with jitter, before
  retrying.
- Fetch a new access token shortly before `expires_in` runs out, and on any `401` other than
  `use_dpop_nonce`. Never cache tokens on disk.
- Make a fresh proof for every request, and use the latest `DPoP-Nonce`.
- Never log, print or report access tokens, assertions, proofs, enrollment codes, OIDC tokens or
  private keys.

## 9. Security considerations

- **Sender-constrained tokens.** A stolen access token is useless without the DPoP private key.
  Required nonces stop proofs made in advance, and one-use `jti` stops replay within a window.
- **Host-key theft** is bounded: an admin revokes the key and its live tokens stop at once, and
  even a thief who keeps rotating loses the key at the enrollment limit.
- **Enrollment-code theft:** whoever uses the code first wins, and the real machine sees the code
  refused. The audit log and the thumbprint shown to admins expose it; production keys also wait
  for a second admin.
- **OIDC trust:** the caller names the identity, so two orgs that trust the same issuer never
  collide. The default audience names the org, so a token minted for another service is useless
  here. Issuer keys are fetched only over HTTPS from public addresses; private, loopback,
  link-local, multicast, reserved and cloud metadata addresses are refused.
- **Uniform errors.** Clients learn nothing from a refusal except where the format above says so.
- **Fail closed.** If replay or revocation state cannot be read, requests are refused.
- **Clocks.** Proofs allow ±60 s of skew and access tokens 30 s. A client with a badly wrong clock
  cannot authenticate.
- **Phishing resistance.** Passkeys are bound to the sign-in page's origin, so a look-alike site
  cannot get a usable assertion. The authorization code is single use, lives 60 seconds and is bound
  to the PKCE verifier and the client's DPoP key, so a code taken from the redirect is useless.
- **Refresh-token theft.** Refresh tokens are bound to the DPoP key, rotate on every use and end
  the session when an old one is presented. A session never outlives 12 hours from the passkey tap.
- **Retired keys** are dropped by verifiers within 5 minutes, and at once when the service
  announces an emergency rotation.

## 10. Conformance

[`conformance/vectors/auth-v1.json`](../conformance/vectors/auth-v1.json) holds:

- `thumbprints`: JWKs and their `jkt`;
- `dpop_proofs`: proofs with the method, configured URL, `now`, nonce key and, at a resource
  server, the access token and its `cnf.jkt`;
- `client_assertions`: assertions with `client_id`, audience, `now` and the host key;
- `enrollment_requests`: enrollment JWTs with the audience and `now`;
- `access_tokens`: tokens with the JWKS, audience and `now`, for workloads and for people;
- `pkce`: code verifiers and the S256 challenge each one gives, or `bad_verifier` (§11.2).

Each case has `name`, `input`, and either `expect: "ok"` with an `output`, or `expect: "<reason>"`.
Each invalid case has one defect, so the order of checks does not matter, with one exception: a case
with a bad `alg` (such as `none`, or `HS256` keyed with the public key) also has a signature that
does not verify, and reports `bad_alg` because `alg` is checked first (§1). The reasons are for
tests and audit only; clients only ever see the errors in §4, §5 and §7.

| Reason | Meaning |
| --- | --- |
| `bad_signature` | the signature does not verify, or `kid` names no known key |
| `bad_typ` | `typ` is missing or wrong |
| `bad_alg` | `alg` is not allowed, or does not match the key |
| `bad_jwk` | the header `jwk` is not an acceptable public key: a private member, another key type, or a small-order Ed25519 point |
| `htm_mismatch` | `htm` is not the request method |
| `htu_mismatch` | `htu` is not the endpoint's configured URL |
| `iat_out_of_window` | `iat` outside the allowed window (for access tokens: more than 30 s in the future) |
| `ath_mismatch` | `ath` missing or not the hash of the presented token |
| `jkt_mismatch` | the proof key is not the token's `cnf.jkt` |
| `nonce_missing` | the proof has no `nonce` |
| `nonce_invalid` | the nonce is not from the current or previous window under this service's key |
| `expired` | `now >= exp`; for access tokens, `exp + 30 < now` |
| `wrong_audience` | `aud` is not the expected value |
| `bad_verifier` | a PKCE verifier is not 43 to 128 characters of `[A-Za-z0-9._~-]` |
| `malformed` | a claim has the wrong type: `auth_time` is not an integer |
| `lifetime_too_long` | `exp - iat` above the limit (60 s for assertions, 900 s for access tokens) |

SDKs and the agent run `thumbprints`, and check that the proofs, assertions and enrollment JWTs
they build pass these rules. The token service runs `dpop_proofs`, `client_assertions` and
`enrollment_requests`; every resource server runs `dpop_proofs` and `access_tokens`. The token service and every client
that builds a challenge run `pkce`. Replay and
revocation need server state and are not in the vectors.

ES256 signatures in the vectors are deterministic (RFC 6979) only so the file is reproducible.
Implementations sign ES256 with random nonces and only verify these cases. The keys, codes and
tokens in the vectors are published test data and must never be used for real workloads.

## 11. People

A person signs in with a browser. The Go CLI (`kallara login`) and SDKs run an OAuth 2.0 authorization
code flow for native apps (RFC 8252) with PKCE (RFC 7636) and DPoP (RFC 9449), and get a 15-minute
management access token and a refresh token. The sign-in pages themselves are not part of this
contract; the endpoints below are.

### 11.1 Authorization endpoint

`GET /oauth/authorize`, opened in the person's browser:

| Parameter | Rule |
| --- | --- |
| `response_type` | `code` |
| `client_id` | `kallara-cli`, a public client with no secret |
| `redirect_uri` | `http://127.0.0.1:<port>/callback`, port 1024 to 65535, exactly this path, no query |
| `code_challenge`, `code_challenge_method` | `S256` only (§11.2) |
| `state` | required, opaque |
| `dpop_jkt` | required: the thumbprint (§1) of the DPoP key the client will use. It binds the code to that key (RFC 9449 §10). |
| `max_age` | optional, seconds. `300` forces a new passkey tap (§11.6). |

When the person has signed in, the browser is redirected to `redirect_uri` with `code`, `state` and
`iss` (RFC 9207). The client MUST check that `state` is the value it sent and that `iss` equals the
metadata `issuer`, before it uses the code. The code is 32 random bytes, base64url, valid for 60
seconds and for one redemption.

Errors: once `redirect_uri` is valid, the service redirects to it with `error=invalid_request`
(plus `state` and `iss`) for any other defect, and shows no detail. When `client_id` or
`redirect_uri` is itself invalid, the service shows an error page and redirects nowhere.

### 11.2 PKCE

The verifier is 43 to 128 characters from `[A-Za-z0-9._~-]`, made from random bytes. The challenge is
`base64url(SHA-256(verifier))` without padding. `plain` is refused. The `pkce` vectors give verifiers
and their challenges, and the verifiers that are refused.

### 11.3 Token endpoint grants

Both grants are `POST /oauth/token` as in §4, with a DPoP proof (§3) for the endpoint. The proof key's
thumbprint becomes the token's `cnf.jkt`.

`authorization_code`:

```
grant_type=authorization_code
client_id=kallara-cli
code=<code>
code_verifier=<verifier>
redirect_uri=<the redirect_uri of the authorization request>
```

The code is accepted once, only with the verifier whose challenge was sent, the same `redirect_uri`,
and a proof whose key thumbprint equals the `dpop_jkt` sent to the authorization endpoint. The
service re-reads the person at this point: someone removed or reset since signing in gets
`invalid_grant`.

`refresh_token`:

```
grant_type=refresh_token
client_id=kallara-cli
refresh_token=<refresh token>
```

The proof key MUST be the key the session was started with. Success returns a new access token and a
new refresh token; the presented refresh token stops working. Presenting a refresh token that was
already replaced ends the whole session (§11.5). Refreshing never moves `auth_time`.

Success for both grants: `200`, `Cache-Control: no-store`:

```json
{
  "access_token": "<JWT>",
  "token_type": "DPoP",
  "expires_in": 900,
  "refresh_token": "<opaque>"
}
```

Errors are as in §4.3. Every failure of these grants other than the nonce, the rate limit or an
unavailable backend is `400 {"error":"invalid_grant"}` with the same body whatever the cause: a wrong
code or verifier, a reused code, another DPoP key, a removed person, an ended or expired session.

A session ends 12 hours (43200 s) after `auth_time`, and 2 hours (7200 s) after its last refresh,
whichever comes first. Both are checked on every refresh.

### 11.4 People's access tokens

The format of §6, with these differences:

| Claim | Value |
| --- | --- |
| `aud` | `kallara-manage` |
| `sub` | the person's identity ID |
| `kal_amr` | a string: `passkey+pwd` (passkey and password). Later versions add `passkey+sso`. |
| `kal_cred` | the session ID |
| `auth_time` | integer, seconds: when the passkey was last tapped. A token whose `auth_time` is not an integer is `malformed`. |

The control plane reads the person's role from its database on every request.

### 11.5 Revocation and ending sessions

`POST /oauth/revoke` (RFC 7009), `application/x-www-form-urlencoded` with `token=<refresh token>`
and a DPoP proof for the endpoint. It ends the session and answers `200` whatever the token was, so
nothing leaks. Access tokens of an ended session stop working on the next request (§7.1), as do all
of a person's sessions when they are removed, reset, or have their role changed.

### 11.6 Step-up

Some actions need a recent passkey tap: approving or rejecting a request, and listing or removing
one's own passkeys. When `now - auth_time > 300`, `/manage/v1` answers `401` with

```
WWW-Authenticate: DPoP error="insufficient_user_authentication", max_age=300
```

(RFC 9470). The client runs the authorization flow again with `max_age=300`, which forces a new
passkey tap, and retries the request with the new token.

### 11.7 Client duties

- Listen on `127.0.0.1` only (never `localhost` or `0.0.0.0`), on a random port, for one request.
- Use a fresh `state` and PKCE verifier per login. Check `state` and `iss` (§11.1).
- Serialise refreshes per session with a lock (a file lock across processes). A second client that
  presents the refresh token a first one just replaced looks like theft, and ends the session.
  After taking the lock, re-read the stored token: it may already be new.
- Store the refresh token readable only by the person (mode 0600) or in the OS keychain, and the DPoP
  key as in §8. Never log it.
- On `invalid_grant` from a refresh, delete the stored session and run login again.
- On `insufficient_user_authentication`, step up (§11.6) once.
