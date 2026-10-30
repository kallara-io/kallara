# Kallara

**Use the key. Never hold it.**

Kallara is crypto-as-a-service. Your application asks Kallara to encrypt, decrypt, sign, verify,
HMAC or issue JWTs with a key it names, such as `customer-pii`, and the key itself never leaves
Kallara's custody. Not in production, not on a developer's laptop, not in a debugger.

This repository holds everything that runs on **your** infrastructure, in the open:

| Path | What | Status |
| --- | --- | --- |
| [`spec/`](spec/) | Wire and data formats | Ciphertext v1 drafted |
| [`conformance/`](conformance/) | Test vectors every implementation must pass | Ciphertext v1 vectors |
| `proto/` | The `/v1` API contract (protobuf + OpenAPI) | Phase 1 |
| `agent/` | Kallara Agent and the `kallara` CLI (Go) | Phase 1 |
| `sdks/python`, `sdks/node`, `sdks/go` | SDKs | Phase 1 |
| `sdks/java`, `sdks/dotnet`, `sdks/php` | SDKs | Phase 2 |

The hosted platform (control plane, crypto service, console) lives in a separate private repository.

## What a Kallara ciphertext looks like

```
kal:v1:k_7SV221GG79B2V7T18T04YZHHZV:3:CYJWC6ScAwgMhXjJnbwv1IJpMvPLfeXYzTc7GZn9j_GX_smmafs
```

The key ID and version travel with the data, so decrypt needs nothing else and key rotation is
invisible to your code. See [`spec/ciphertext-v1.md`](spec/ciphertext-v1.md).

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
