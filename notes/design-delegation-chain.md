# Design: delegation chain and maximum depth (CoSAI 3.3.2)

Design only, no code. Sources fetched 2026-11-11:
- CoSAI MCP Security v2.0: github.com/cosai-oasis/ws4-secure-design-agentic-systems, `whitepapers/model-context-protocol-security.md` at commit `62e75fd45c` (front matter `version: 2.0`, `last_updated: 12 August 2026`). The site PDF (coalitionforsecureai.org/wp-content/uploads/2026/03/model-context-protocol-security-1.pdf) says "Last updated on 12 August 2026"; I did not check its tables word for word, because the PDF text extraction splits table cells.
- RFC 8693: https://www.rfc-editor.org/rfc/rfc8693.txt
- ContextForge 1.1.1 wheel (`pip download mcp-contextforge-gateway==1.1.1 --no-deps`, sha256 `c9233f10…3ec3c`), searched with grep. agentgateway source at tag v1.7.0 (`26f5aebe99a3`, the same commit the gate runs).

## 1. The rule
- 3.3.2, Identity and Authentication, row "User identity propagation", L4: "MUST: token exchange with delegation chain preserved for audit. Prior delegation hops should be retained for forensics, but authorization decisions must be based on the token's current actor and subject claims."
- 3.3.2, Authorization and Delegation, row "Delegation depth": L2 "SHOULD: defined maximum depth for agent chains"; L3 "MUST: enforced depth limits with TTL constraints and audience restrictions"; L4 "MUST: enforced depth limits, audience restrictions, and sender-constrained tokens at every hop".
- "Level 4": 3.3.1 names it "Regulated", "Multi-tenant platforms, adversarial environments, regulatory scope". Section 3.3 says "levels are cumulative (Level 3 includes everything in Level 2)", so the L3 TTL wording also binds L4.
- Correction to the brief: "maximum depth with TTL and audience limits" is the **L3** wording. At L4 the cell names sender-constrained tokens instead of TTL. CoSAI gives **no number** for the maximum depth; a grep for "depth" finds none. The 3.3.6 bullet on draft-ietf-oauth-identity-chaining-08 says it is "Relevant to scope narrowing and delegation depth controls". UNCONFIRMED: whether that draft defines a limit (not read).

## 2. Standards (RFC 8693)
- §4.1 `act`: "A chain of delegation can be expressed by nesting one "act" claim within another. The outermost "act" claim represents the current actor while nested "act" claims represent prior actors." Then "the consumer of a token MUST only consider the token's top-level claims and the party identified as the current actor"; prior actors are "informational only". Figure 6 shows `act:{sub:service16, act:{sub:service77}}`.
- §4.4 `may_act`: the subject token's claim that names who "is authorized to become the actor"; the AS "can" use it. It is not a MUST.
- §2.1 `actor_token` is OPTIONAL: "the identity of the acting party". The **AS** writes `act`. The client (the gateway) only picks which `subject_token` and `actor_token` to send. So a gateway keeps the chain only by sending the inbound delegated token as `subject_token`; the nesting itself is the AS's job.
- **Maximum depth: confirmed absent.** A grep of RFC 8693 for "depth" and "maximum" returns nothing. §1.1 says only that `act` "can provide a representation of a chain of delegation". §5 suggests `scope` and "a limited token lifetime" against abuse. It sets no limit on chain length.

## 3. Rig
```
client A/B --(user JWT that ALREADY carries act:{sub:hop1})--> GATEWAY (deputy under test)
GATEWAY --(RFC 8693: subject_token = inbound JWT, actor_token = gw)--> LocalAS /token
GATEWAY --(exchanged token)--> RecordingUpstream    expect act:{sub:gw, act:{sub:hop1}}
two-hop variant: client --> thin deputy #1 --> GATEWAY or thin deputy #2 --> RecordingUpstream
```
- One real gateway is enough. We mint a "hop-1 output" token directly (LocalAS signs `sub`, `email`, `aud`=gateway API, `act`), so we do not have to chain two third-party gateways. The two-hop thin-deputy variant checks this shortcut against a real first hop.
- LocalAS already nests the chain (`local_as.py` `token_exchange`: `act["act"] = subject["act"]`). It needs to gain: (a) `/issue?act=` to mint pre-delegated tokens of depth k; (b) an exp cap, `min(subject.exp, now+ttl)`, so the TTL check means something; (c) no AS-side depth limit by default, so any refusal is the gateway's. An optional `max_depth` exists only for the AS-enforces control.
- RecordingUpstream must also record the whole `act` chain as a list of `sub`, outermost first, plus `exp`. Today it keeps only `act.sub`.

## 4. Grades (A, B, A; per-user calls only, as in XID-10)
Positive controls, run first: (c1) the safe deputy run against the same AS shows a nested chain at the upstream, which proves both the AS nesting and the observer; (c2) a depth N−1 request reaches the upstream.
```
chain(call) = [act.sub, act.act.sub, ...]            # outermost first
FAIL if chain(A1) != [gw] + inbound_chain(A)          # dropped, reordered or forged hop
FAIL if chain(A2) contains any hop only in B's chain  # cross-identity chain bleed
FAIL if a depth > N call reached the upstream AND the target is configured with limit N
INCONCLUSIVE if no limit is configurable, or c1/c2 failed, or a call is unparsed
OK only if c1 and c2 passed and every check held on A1, B, A2
```
- An observed leak (a lost or bled chain at the upstream) is FAIL whatever the controls say. The controls only decide whether OK is allowed. An over-depth refusal counts as "enforced" only per section 7.

## 5. Fixtures (thin deputy)
- Broken: `chain_drop` (exchanges a stored first-seen user token or its own token as the subject, so the prior `act` is lost); `chain_passthrough` (forwards the inbound token, so the upstream sees `act:{hop1}` and the wrong aud); `chain_cache_bleed` (caches by `sub`, so A2 gets B's chain); `no_depth_check` (forwards a depth N+1 token while claiming limit N).
- Safe: `safe` with the inbound JWT as `subject_token` plus the gateway actor, refusing depth > N with 403 before the exchange.

## 6. Gateway support
| | ContextForge 1.1.1 | agentgateway 1.7.0 |
|---|---|---|
| Inbound token sent as `subject_token` unchanged (chain kept if the AS nests) | supported: `utils/subject_token.py:17-35`, `services/tool_service.py:4519-4523, 4573-4584` | supported: `subjectToken.source` (repo config `jwt.rawToken.unredacted()`), `http/auth/oauth/mod.rs:764-772` |
| Reads or limits `act` depth | not supported: no `act`/`may_act`/depth match outside tests (grep) | not supported: no `act`/depth match outside tests (grep) |
| `may_act` check | not supported (no match) | supported, opt-in (Rust field `enforce_may_act` on `actorToken`; YAML spelling `enforceMayAct` UNCONFIRMED): `mod.rs:503-505, 787-808` (it decodes the actor token unverified, `mod.rs:840-846`) |
| Cache key includes the subject token | yes: `tool_service.py:4549` | yes: `oauth/cache.rs:79-90` |

UNCONFIRMED: whether an agentgateway CEL `authorization` rule can reach nested `jwt.act.act` and so approximate a depth cap. Not checked or run. So for both gateways the depth part is INCONCLUSIVE (not supported) and only chain preservation can be graded.

## 7. False FAIL / false OK
- State changing with nobody acting: a cache TTL expiring between A1 and A2, or the AS key rotating. Pin the TTLs and the key path, and record cache hits as the gates already do.
- A refusal from a malformed request (bad aud or email, an `act` the gateway's inbound validator rejects as a type, a JSON-RPC parse error) is not depth enforcement. Count a refusal only if the depth N−1 twin with identical claims succeeded in the same run.
- A missing feature (depth limit, `may_act`) is INCONCLUSIVE, never FAIL.
- An AS that drops the chain (LocalAS impersonation mode issues no `act` at all) is not the gateway's fault. Run only in delegation mode and keep control c1.
- Grading on `act.sub` alone would miss a hop that is reordered or forged. Compare the whole ordered list.
- False OK: a gateway that refuses everything passes the depth check. Control c2 prevents that.

## 8. Size: ~4 days
LocalAS (`act` minting, exp cap) 0.5; RecordingUpstream chain capture 0.25; probe and grading plus unit tests 1; thin-deputy fixtures and two-hop rig 1; CF and agentgateway runs (chain only) 0.75; write-up and RESULTS 0.5.
