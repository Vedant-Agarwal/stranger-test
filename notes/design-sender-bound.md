# Design: sender-bound tokens (DPoP / mTLS), CoSAI 3.2.2 and 3.3.2

Design only, no code. Sources fetched 2026-11-11: the CoSAI MCP Security v2.0 markdown at commit `62e75fd45c`, the same file as `design-delegation-chain.md` (`version: 2.0`, last updated 12 August 2026); RFC 9449 and RFC 8705 from rfc-editor.org (.txt); the ContextForge 1.1.1 wheel and agentgateway v1.7.0 source (`26f5aebe99a3`), searched with grep.

## 1. The rule
- 3.2.2 Secure Delegation and Access Control, bullet: "Use short-lived tokens and support proof-of-possession (DPoP) to prevent replay attacks ([RFC9449](…))". This section names DPoP only; mTLS is not in it.
- 3.3.2 Authorization and Delegation, row "Token binding": L1 and L2 "Not required"; L3 "MUST: sender-constrained tokens ([DPoP](…) or mTLS) for all delegated operations involving sensitive data"; L4 "MUST: sender-constrained tokens with hardware-attested key material where platform supports it".
- Same table, L4 "Delegation depth": "… sender-constrained tokens at every hop". L4 "Token passthrough": "MUST: token exchange with sender-constrained bindings for all downstream calls". Identity table, L4 "Credential lifetime": "MUST: short-lived sender-constrained credentials, typically minutes, bounded by transaction or task risk".
- 3.3.5: "**Token binding is a hard requirement at Level 3.**" Level 3 = "Production" and Level 4 = "Regulated" (3.3.1). Quote status: confirmed verbatim. "mTLS" in the L3 cell is not pinned to RFC 8705 in the text; reading it as RFC 8705 is my interpretation.

## 2. Standards
- RFC 9449 §4.1: request header `DPoP: <JWT>`. §4.2: header `typ`=`dpop+jwt`, `alg` (asymmetric, not `none`), `jwk` (public key only); claims `jti`, `htm`, `htu` (no query or fragment), `iat`; `ath` (base64url SHA-256 of the access token) MUST be present when the proof goes with an access token; `nonce` MUST be present once the server sends `DPoP-Nonce`. §4.3: the 12 checks (htm and htu match, iat window, ath equals the token hash, the proof key matches the token's binding).
- RFC 9449 §6.1: `cnf.jkt` = the JWK SHA-256 thumbprint of the proof key. §5: the AS MUST return `token_type` "DPoP" for a bound token. §7.1: the client sends `Authorization: DPoP <token>`; the RS "MUST NOT grant access … unless all checks are successful". §7.2: an RS that supports both schemes "MUST reject a DPoP-bound access token received as a bearer token". §11.1: proofs accepted only for a limited time; single-use `jti` tracking is a "can", not a MUST.
- RFC 8705 §3.1: `cnf` with `x5t#S256` = the base64url SHA-256 of the DER client certificate. §3: the RS "MUST verify that the certificate matches"; on a mismatch it returns 401 `invalid_token`. Calls "MUST be made over a mutually authenticated TLS connection using the same certificate that was used for mutual TLS at the token endpoint". §6.5: certificate forwarding behind TLS termination is "out of scope".

## 3. Rig
```
client A/B --[Authorization: DPoP tA + DPoP proof(kA)] or [mTLS certA]--> GATEWAY
GATEWAY --(token exchange, own DPoP proof(kG) or mTLS certG)--> LocalAS /token -> cnf bound to G
GATEWAY --[DPoP tG + proof(kG)] or [mTLS certG]--> RecordingUpstream (checks per §4.3 / RFC 8705 §3)
```
- Inbound leg: does the gateway, acting as the RS, enforce A's binding? Outbound leg: does the gateway present binding upstream?
- LocalAS needs to gain: DPoP proof validation at `/token` (§4.3 checks 1-11), `cnf.jkt` on issued tokens, `token_type: DPoP`, optional `DPoP-Nonce`; and a TLS listener that requests client certs, writes `cnf.x5t#S256`, and has test CA and leaf generation (cryptography, loopback only).
- RecordingUpstream needs to gain: the auth scheme, DPoP header presence, every §4.3 result (jti replay store, ath, jkt equal to the proof key), and for mTLS the peer cert thumbprint against `cnf`.

## 4. Grades
Attack pairs, driven as A, B, A:
- (i) B presents A's bound token with B's own proof or cert.
- (ii) A's proof replayed (same `jti`).
- (iii) The proof's `htm`/`htu`/`ath` taken from another request.
- (iv) A's bound token sent as `Bearer` (a §7.2 downgrade).
```
FAIL  if any attack request produced a per-user upstream call (or tool result) as A
FAIL  if the target forwarded a cnf-bound token upstream as Bearer, or reused one proof jti
      across two upstream calls, or bound B's upstream token to A's key or cert
INCONCLUSIVE if the target has no DPoP/mTLS-binding feature or it is not enabled,
      or the honest twin (A, own key, fresh proof) did not reach the upstream
OK    only if the honest twin succeeded AND every attack got an auth refusal (401/403,
      or WWW-Authenticate: DPoP error=invalid_dpop_proof) with no upstream call
```
- An observed leak (an attack call reaching the upstream as A) is FAIL whatever else holds, including when binding is "not configured". Section 7 explains why the honest-twin control stops this from being a false FAIL.

## 5. Fixtures (thin deputy)
- Broken: `dpop_ignored` (accepts `DPoP` and `Bearer` and never checks the proof); `jkt_unchecked` (validates the proof but not proof-key = `cnf.jkt`, so B's key passes); `replay_ok` (no iat window or jti store); `downgrade` (gets a DPoP token from the AS, forwards it as Bearer with no proof); `proof_reuse` (one cached outbound proof for all calls).
- Safe: `safe` runs all §4.3 checks inbound, keeps a jti store, and mints a fresh proof per upstream call with its own key.

## 6. Gateway support
| | ContextForge 1.1.1 | agentgateway 1.7.0 |
|---|---|---|
| Inbound DPoP | not supported: no `dpop` match anywhere in the wheel; the inbound scheme must be Bearer (`utils/verify_credentials.py:272`, else 403); `subject_token.py:34` takes only `Bearer` | not supported: no `dpop` match in the source; jwtAuth default `Authorization: Bearer ` (`http/auth/mod.rs:445-459`) |
| Inbound mTLS-bound token (`cnf` check) | not supported: no `x5t#S256` or `cnf` match | not supported for `cnf`: frontend mTLS exists (`types/local.rs:1352` `root`), and CEL exposes the client cert PEM (`transport/tls.rs:1133-1135`); a CEL `cnf` comparison is UNCONFIRMED |
| Outbound DPoP | not supported: the exchange is rejected unless `token_type` is Bearer (`services/oauth_manager.py:1159-1161`); sent as `Bearer` (`tool_service.py:4660`) | not supported: rejects non-Bearer `token_type` (`http/auth/oauth/transport.rs:125-140`) |
| Outbound mTLS (cert to AS and upstream) | supported (static per-gateway cert): `client_cert` to the token endpoint (`tool_service.py:4571, 4581`), upstream SSL context only when a CA cert is also set (`tool_service.py:6430-6434`) | supported: `backendTLS.cert/key` (`http/backendtls.rs:233-237`), and token-endpoint `policies` (`oauth/mod.rs:40-42`, `types/local.rs:2780-2782`) |

- Neither gateway checks inbound binding. The DPoP rows are INCONCLUSIVE (not supported). Outbound mTLS binding works only if the AS binds to the gateway cert; an end-to-end run is UNCONFIRMED.
- `x5t#S256` in agentgateway (`oauth/client_auth.rs:240, 523`) is the JWS header of a private_key_jwt client assertion, not `cnf`.
- CF's comment says RFC 8693 §2.2.1 "requires 'Bearer'". The RFC text gives "Bearer" as an example ("For example, a value of "Bearer""), not as a requirement.

## 7. False FAIL / false OK
- A target that doesn't support binding treats `cnf` as an unknown claim. RFC 9449 §7.2 itself says such an RS "would most presumably accept" a bound token as bearer. Report that as INCONCLUSIVE ("not sender-constrained"), not FAIL, unless an attack call reached the upstream as A and the honest twin worked, which makes it an observed leak.
- A refusal from a malformed request (bad `htu` normalisation such as 127.0.0.1 vs localhost or a trailing slash, clock skew on `iat`, wrong `typ`, the `DPoP` scheme rejected outright) is not binding enforcement. Each attack differs from its honest twin in exactly one field.
- State changing with nobody acting: the server rotating `DPoP-Nonce`, cert or token expiry, or the iat window closing between calls. Record nonces and timestamps and fail fast to INCONCLUSIVE.
- TLS termination in front of the target (RFC 8705 §6.5) makes cert binding unobservable: INCONCLUSIVE.
- False OK: a gateway that refuses every DPoP request "passes" the attacks. The honest-twin control stops that.

## 8. Size: ~6 days
LocalAS DPoP 1; LocalAS mTLS and test CA 1; RecordingUpstream checks and jti store 1; probe, fixtures, unit tests 1.5; CF and agentgateway runs (inbound expected INCONCLUSIVE; outbound mTLS attempt) 1; write-up 0.5.
