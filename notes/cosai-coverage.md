# CoSAI MCP Security — coverage map for Stranger Test

Hand-written. Maps the normative requirements in the identity / authorization /
delegation / token / caching / state parts of the CoSAI MCP Security document to
the probes Stranger Test has **today**. Coverage is marked COVERED / PARTIAL /
NOT COVERED. No new probes are designed here; gaps are listed as a roadmap at
the end.

## Source (pinned)

- **Document:** *Model Context Protocol (MCP) Security*, CoSAI Workstream 4
  (Secure Design Patterns for Agentic Systems).
- **Version:** 2.0. Dated 8 January 2026; **last updated 12 August 2026** for the
  MCP 2026-07-28 release. The document states: *"Approved by the CoSAI Project
  Governing Board on 8 January 2026."*
- **Read from:** `whitepapers/model-context-protocol-security.md` in
  `github.com/cosai-oasis/ws4-secure-design-agentic-systems` (the markdown source
  of the published PDF `.../model-context-protocol-security.pdf`). This is the
  latest approved version; no newer one was found.
- The probe source and `integration/RESULTS.md` already call this "CoSAI MCP
  Security v2.0"; that matches this document.

## How this map is built

- The **leveled, auditable requirements** are in **§3.3.2 Control Requirements by
  Level**, which states each control as a MUST/SHOULD cell per level across eight
  dimensions. Levels (L1 Sandbox, L2 Internal, L3 Production, L4 Regulated) are
  defined in **§3.3.1**. This map uses §3.3.2 as the requirement list and §3.3.1
  for levels — the same numbering `RESULTS.md` uses.
- **In scope** (per the task): the §3.3.2 dimensions *Identity and
  Authentication*, *Authorization and Delegation*, the cross-identity rows of
  *Isolation and Sandboxing*, the *Cacheable result handling* row of *Tool
  Definition, Input, and Output Integrity*, and *State and Discovery Security*.
  Out of scope here: transport/network, supply chain, logging, input/output
  sanitization, schema validation (noted where they border an in-scope row).
- **§3.2.2 Secure Delegation and Access Control** is narrative (bulleted
  imperatives, no levels). Its bullets are the prose basis for several §3.3.2
  rows; they are cross-referenced in the table and listed separately at the end,
  and are **not** counted in the headline totals (to avoid double-counting the
  same control).
- "First MUST level" is the lowest level at which the control is a MUST; a lower
  SHOULD is noted as the document assigns it.
- Quotes from the document are kept to short phrases and cited by section.

## Coverage table

| ID | Section (§3.3.2 dimension — control) | First MUST | Requirement (plain language) | Coverage | Probe / RESULTS reference | Notes |
|---|---|---|---|---|---|---|
| CID-01 | Identity & Authentication — MCP client-server authentication | L2 | Remote client→server auth uses OAuth 2.1 with PKCE (short-lived creds, CIMD at L3). | NOT COVERED | — | Stranger Test probes the server→upstream delegation, not the inbound OAuth/PKCE handshake. Gateways validate inbound tokens in our runs, but we do not test the handshake itself. |
| CID-02 | Identity & Authentication — Authorization issuer validation | L2 | Validate issuer metadata; at L3 validate RFC 9207 `iss` and bind registration/token state to the issuing AS. | PARTIAL | `delegate.py` issuer-binding (`issuer_unregistered`, cross-provider email, `two_issuers`); RESULTS row "Tokens bound to the issuer that issued them" | Covered: a subject token from an unregistered/!=configured issuer is refused, and same-named users from different issuers are not conflated. Not tested: RFC 9207 `iss` in the OAuth **authorization response** (we don't exercise the browser auth-code leg). |
| CID-03 | Identity & Authentication — Agent identity | L3 (L2 SHOULD) | Workload identity (e.g. SPIFFE/SPIRE) tied to code version; attestation at L4. | NOT COVERED | — | No probe asserts a workload identity for the agent/gateway. |
| CID-04 | Identity & Authentication — User identity propagation | L3 (L2 SHOULD) | Token exchange carries distinct `actor` (agent) and `subject` (user). | COVERED | `delegate.py` delegation probe (`subject_preserved`, `actor_present`); RESULTS rows "Distinct actor and subject…" and "Own token per user" | Across ContextForge/agentgateway/LiteLLM/ToolHive/Kuadrant. Caveat already in RESULTS: where the gateway sends no `actor_token` it is graded NOT SUPPORTED/impersonation, and agentgateway's actor is caller-supplied. |
| CID-05 | Identity & Authentication — User identity propagation (L4 clause) | L4 | Delegation chain preserved for audit across hops. | NOT COVERED | RESULTS row "Delegation chain preserved for audit" = NOT TESTED (`notes/design-delegation-chain.md`) | Design note only. |
| CID-06 | Identity & Authentication — Credential storage | L2 | Store credentials in OS keychain / secrets manager (rotation at L3). | NOT COVERED | — | About where a deployment stores secrets; outside a cross-identity probe. |
| CID-07 | Identity & Authentication — Credential lifetime | L3 (L2 SHOULD) | Short-lived tokens; refresh tokens rotated and confidential. | NOT COVERED | — | We observe exchanged tokens but do not assert their lifetime. |
| CID-08 | Authorization & Delegation — Tool-level authorization | L3 (L2 SHOULD) | ABAC/PBAC + tool-based access control enforcing parameter-level constraints. | NOT COVERED | — | No probe for policy-based tool authorization. (ContextForge runs note external users got tool access via a team role — an observation, not a graded probe.) |
| CID-09 | Authorization & Delegation — Scope management | L3 (L2 SHOULD) | Least-privilege scopes; incremental consent via `WWW-Authenticate` step-up. | NOT COVERED | — | Distinct from scope **narrowing** (CID-12). Step-up/incremental consent is not exercised. |
| CID-10 | Authorization & Delegation — Delegation depth | L3 (L2 SHOULD) | Enforced maximum delegation depth with TTL and audience limits. | NOT COVERED | RESULTS row "Defined / enforced maximum delegation depth" = NOT TESTED (`notes/design-delegation-chain.md`) | Design note only. |
| CID-11 | Authorization & Delegation — Token binding | L3 | Sender-constrained tokens (DPoP or mTLS) for delegated ops on sensitive data. | NOT COVERED | RESULTS row "Sender-constrained tokens (DPoP or mTLS)" = NOT TESTED (`notes/design-sender-bound.md`) | Design note only. |
| CID-12 | Authorization & Delegation — Scope narrowing on delegation | L3 (L2 SHOULD) | Scope narrows at each hop and cannot exceed the delegating principal. | COVERED | `delegate.py` `scope_narrowing`; RESULTS row "Scope narrows at each hop…" | Narrowing is checked; the no-scope variant is recorded as NOT NARROWED. L4 "cryptographic binding to transaction path" NOT COVERED. |
| CID-13 | Authorization & Delegation — Audience restriction | L3 (L2 SHOULD) | `aud` validated on received tokens; at L3 Resource Indicators (RFC 8707), AS rejects wrong audience. | PARTIAL | `delegate.py` delegation probe (`audience_correct`); RESULTS row "Audience restriction on the upstream token" | Covered: the `aud` of the token sent **upstream** equals the target. Not tested (RESULTS says so): the gateway's own **inbound** `aud` check / AS rejection of a wrong-audience token (except a ToolHive inbound-validation observation). |
| CID-14 | Authorization & Delegation — Token passthrough | L2 | Server MUST NOT forward a token meant for itself upstream; at L3 downstream auth only via token exchange. | COVERED | `delegate.py` delegation probe (exchanged token upstream) + passthrough-detection fixtures (`broken_passthrough`, LiteLLM `passthrough`); RESULTS row "No token passthrough" | L4 "sender-constrained bindings for all downstream calls" NOT COVERED (see CID-11). |
| CID-15 | Authorization & Delegation — Human-in-the-loop | L2 | Explicit user confirmation for destructive/state-mutating actions. | NOT COVERED | — | Consent/approval UX; outside Stranger Test's scope. |
| CID-16 | Isolation & Sandboxing — Data isolation | L2 (per-user) → L3 (per-tenant) | Per-user data separation (L2); per-tenant isolation with encryption (L3). | PARTIAL | `concurrency.py` (no identity crossing under 50 concurrent sessions) + the whole XID-10 no-cross-user-reuse evidence | Runtime "one user's data/token does not reach another" is exercised; per-tenant storage **encryption / keys** is not. |
| CID-17 | Isolation & Sandboxing — Context isolation | L3 (L2 SHOULD) | Cached tool outputs and context scoped to user/tenant/task; no reuse across workflows without policy. | COVERED | `cachescope.py`; RESULTS row "Private results never cached across users" | Cache-output scoping covered. The broader "context from one workflow not reused in another" (persistent memory across tasks/agents) is not separately tested → treat as PARTIAL for the full L3 clause. |
| CID-18 | Tool Definition, Input & Output Integrity — Cacheable result handling | L3 (L2 SHOULD) | Honor `ttlMs`/`cacheScope` (L2); prevent cross-user and cross-tenant caching (L3). | COVERED | `cachescope.py` (private not cached across users) + `credcache.py` (CVE-2026-110195 cache-key collision across one user's credentials); RESULTS "Private results never cached across users" + "Validation against CVE-2026-110195" | L4 "centralized cache policy with security-event invalidation" NOT COVERED. |
| CID-19 | State & Discovery Security — Explicit state handle integrity | L2 → L3 | Don't use transport session IDs as authenticators; authorize every request; scope handles to the principal (L2). Tenant-bound, expiring, revocable, enumerable-for-revocation (L3). | PARTIAL | `handle.py`; RESULTS row "Task handles scoped to the authenticated principal" (L2) | L2 (handle scoped to principal, authz per request) is covered. L3 extras — TTL/expiry, revocation on grant/consent/principal change, per-principal enumeration — are NOT tested. |
| CID-20 | State & Discovery Security — Request metadata trust | L2 | `_meta` identity/capability claims are untrusted; MUST NOT be an authorization input on their own; reconcile against the authenticated principal. | NOT COVERED | — | No probe plants a false `_meta`/`clientInfo` identity and checks the server reconciles it. The `actor_lies` / caller-supplied-actor observations are adjacent but are about forwarded actor tokens, not `_meta` identity claims. Central gap. |
| CID-21 | State & Discovery Security — Client-held state integrity | L2 | Server-sealed state echoed by the client (e.g. `requestState`) is HMAC/AEAD-protected and rejected on verification failure; client MUST NOT inspect/modify it. | NOT COVERED | — | No probe tampers with sealed client-held state. Central gap. |
| CID-22 | State & Discovery Security — Refresh tokens | L3 (L2 cond.) | Refresh tokens rotated, stored securely, not a substitute for runtime authz at the server. | NOT COVERED | — | Refresh-token lifecycle not exercised. |

Server/authorization **discovery** (`server/discover`, Protected Resource
Metadata) and **deprecated-feature migration** rows of §3.3.2 State & Discovery
are left out: they are not about one identity reaching another's data/authority.

### Related §3.2.2 bullets (narrative, no level) — cross-reference only

| §3.2.2 bullet (short) | Maps to | Coverage |
|---|---|---|
| "Bind … access tokens … to the authorization server `issuer`" | CID-02 | COVERED (issuer-binding probe) |
| "Do not passthrough the OAuth tokens" | CID-14 | COVERED |
| "Perform token exchange … full accountability (RFC 8693)" | CID-04 / CID-14 | COVERED |
| "Reduce scopes for least privilege" | CID-12 | COVERED (narrowing) / CID-09 incremental consent NOT COVERED |
| "support proof-of-possession (DPoP)" | CID-11 | NOT COVERED |
| Validate RFC 9207 `iss` in the authorization response | CID-02 | NOT COVERED (response leg not exercised) |

## Coverage counts

22 in-scope §3.3.2 requirement rows (CID-01…CID-22).

| | COVERED | PARTIAL | NOT COVERED |
|---|---|---|---|
| **Total** | 5 | 4 | 13 |

By first-MUST level:

| First MUST | rows | COVERED | PARTIAL | NOT COVERED |
|---|---|---|---|---|
| L2 | 9 | 1 (CID-14) | 3 (CID-02, CID-16, CID-19) | 5 (CID-01, CID-06, CID-15, CID-20, CID-21) |
| L3 | 12 | 4 (CID-04, CID-12, CID-17, CID-18) | 1 (CID-13) | 7 (CID-03, CID-07, CID-08, CID-09, CID-10, CID-11, CID-22) |
| L4 | 1 | 0 | 0 | 1 (CID-05) |

(CID-16 and CID-19 span L2→L3; counted at their first MUST, L2.)

## Gaps, by level — ranked by closeness to "one user must not affect another"

**Most central (a caller reaching another identity's data or authority):**

1. **CID-20 Request metadata trust** — §3.3.2 State, **L2 MUST** — NOT COVERED. A
   caller asserting another principal in `_meta`/`clientInfo` and having it
   honored is the confused-deputy pattern in a single hop. gap.
2. **CID-21 Client-held state integrity** — §3.3.2 State, **L2 MUST** — NOT
   COVERED. Tampering server-sealed `requestState` to act as/for another
   principal. gap.
3. **CID-10 Delegation depth** — §3.3.2 Authorization, **L3 MUST** — NOT COVERED
   (design note). Unbounded chains let authority fan out beyond the delegator.
4. **CID-11 Token binding (DPoP/mTLS)** — §3.3.2 Authorization, **L3 MUST** — NOT
   COVERED (design note). An unbound bearer token lifted by another party is
   replayable as that user.
5. **CID-08 Tool-level authorization (TBAC)** — §3.3.2 Authorization, **L3 MUST**
   — NOT COVERED. Without parameter-level authz, one principal can drive tools it
   should not.

**Also not fully covered (less central or partially covered):**

- CID-19 Explicit state handle integrity — L3 revocation/TTL/enumeration PARTIAL.
- CID-16 Data isolation — per-tenant storage encryption PARTIAL.
- CID-13 Audience restriction — inbound `aud` / AS rejection PARTIAL.
- CID-02 Authorization issuer validation — RFC 9207 response `iss` PARTIAL.
- CID-03 agent identity, CID-07 credential lifetime, CID-09 scope management
  (incremental consent), CID-22 refresh tokens — NOT COVERED.
- CID-01 client-server auth, CID-06 credential storage, CID-15 human-in-the-loop
  — NOT COVERED and largely outside Stranger Test's cross-identity focus.

## Cross-check against RESULTS.md section citations

Every requirement the RESULTS CoSAI table **grades OK (claims to test)** appears
above as COVERED/PARTIAL with a matching section:

| RESULTS row | RESULTS cite | This map | Match? |
|---|---|---|---|
| Distinct actor and subject | 3.3.2 Identity: User identity propagation | CID-04 | ✓ exact |
| Scope narrows at each hop | 3.3.2 Authorization: Scope narrowing on delegation | CID-12 | ✓ exact |
| Tokens bound to the issuer | 3.2.2 Secure Delegation | CID-02 | partial — see (c) below |
| No token passthrough | 3.3.2 Authorization: Token passthrough | CID-14 | ✓ exact |
| Audience restriction | 3.3.2 Authorization: Audience restriction | CID-13 | ✓ section; coverage PARTIAL (inbound aud) |
| Own token per user | 3.3.2 Identity: User identity propagation | CID-04 | ✓ (RESULTS notes "nearest row") |
| Task handles scoped to principal | 3.3.2 State: Explicit state handle integrity | CID-19 | ✓ exact (L2) |
| Private results never cached | 3.3.2 Tool output: Cacheable result handling | CID-18 | ✓ (label shorthand, see (b)) |

Findings:

- **(a) The generated RESULTS table's §3.3.2 / §3.2.2 citations are accurate**
  against v2.0. The sub-dimension and control names it cites exist at those
  numbers, and the levels it prints ("L3", "L2 SHOULD", etc.) match the §3.3.2
  cells. No numbering error in the generated table.
- **(b) Dimension labels are shorthand.** RESULTS writes "Identity",
  "Authorization", "Tool output", "State"; the document's dimension titles are
  "Identity and Authentication", "Authorization and Delegation", "Tool
  Definition, Input, and Output Integrity", "State and Discovery Security".
  Cosmetic, not a numbering mismatch.
- **(c) Probe docstrings cited §3.2.7 / §3.2.12 for caching and state handles
  where the leveled requirement is §3.3.2 — now standardized.** In v2.0, **§3.2.7
  is "Transport Layer Security"** and **§3.2.12 is "MCP Protocol Version
  Transition"**. Both sections *do* contain the supporting narrative (§3.2.7:
  "Caching is now explicit … honor `private` scope"; §3.2.12: server-held
  references "must be unguessable … scoped … revocable"), so the citations were
  not wrong, but they pointed at prose under broad titles rather than the
  auditable, leveled control, while the RESULTS **table** already cites the
  leveled §3.3.2 rows. The module docstrings of `strangertest/cachescope.py`,
  `strangertest/practice_cache_http.py`, `strangertest/handle.py` and
  `integration/cachescope_gateway_gate.py` now lead with the §3.3.2 rule
  (Cacheable result handling; Explicit state handle integrity) and keep §3.2.7 /
  §3.2.12 as "see also", so source and RESULTS use one numbering. The grade-data
  values (`cosai` in `cachescope_gateway_gate.py`, the `COSAI` constant in
  `handle_gateway_gate.py`) are left unchanged: they feed the generated run
  output, and RESULTS regenerates byte-identical. **This was the only real
  inconsistency found.**
- **(d) Issuer binding can be cited with a level.** RESULTS prints "no level in
  3.2.2" for the issuer-binding row. §3.3.2 "Authorization issuer validation"
  makes issuer binding an **L2/L3 MUST**, so the probe is exercising a leveled
  requirement; it can carry §3.3.2 (with §3.2.2 as narrative) and an L2/L3 label.
- **(e) Audience restriction is graded OK but is PARTIAL against the full row.**
  RESULTS grades gateways OK on the **upstream** token's `aud` and itself notes
  the gateway's **inbound** `aud` check is not tested; the §3.3.2 Audience
  restriction row also covers the AS rejecting a wrong-audience token. Coverage
  completeness point, not a numbering mismatch.
