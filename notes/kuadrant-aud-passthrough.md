# Kuadrant: the `aud == server` token is forwarded by design (a false positive we chased down)

While testing the exchange-failure behaviour of the minimally-adapted sample
AuthPolicy, a request briefly looked like a fail-open: the user's own token
reached the upstream. We investigated it to ground and it is **not** a security
issue — it is the sample's documented pass-through for a token already scoped to
the target server. This note records what happened and why, so we don't re-raise
it.

## What we first saw, and why it was a false positive

When the token exchange "failed" and the inbound user token's `aud` equalled the
server name (`x-mcp-servername`), the user token was forwarded upstream. The
mistake was assuming this was caused by the exchange failing.

It is not. The exchange evaluator's `when` is
`auth.identity.aud != request.headers['x-mcp-servername']`. For an `aud == server`
token that predicate is **false**, so the exchange is **skipped — the token
endpoint is never called**.

**Decisive test:** an `aud == server` request with the token endpoint in `forward`
mode (exchange would succeed if it ran) produced **0 token-endpoint hits** and
forwarded the user token — **identical** to the "failure" modes. So the
pass-through is independent of the exchange's state; it is the no-exchange path,
not a failure path.

## What actually happens on a genuine exchange failure

For a token that **needs** exchange (`aud != server`), when the token endpoint
fails (`http_500`, non-JSON body, `200` without `access_token`, or `slow`/timeout):
**HTTP 403, nothing reaches the upstream — fail closed.** Verified for all four
modes with normal tokens; recorded in `integration/sample-runs/kuadrant-exchange_fail.json`
(`user_token_reached_upstream_any_mode` = `False`).

Confirmed on the **near-unadapted** sample too (`integration/kuadrant/
kuadrant-mcps-auth-policy-near-unadapted.yaml`, which restores `tool-access-check`
and `prompt-access-check` exactly and only changes issuer/token-endpoint + drops
Vault; local_as issues the Keycloak-style `resource_access` roles via the `ra=`
param). For tool calls, `tool-access-check` adds a gate (a non-roled `aud=server`
token is refused); for requests without `x-mcp-toolname` (initialize, tools/list)
it is `when`-skipped, so only the `aud == server` pass-through applies.

## Why the fallback-to-bearer is intentional (documented)

The OPA `token` rule has two explicit branches — use the exchanged token if
present, else the inbound Bearer — which, with the exchange `when`, means
"exchange only when not already scoped to this server; otherwise use the token
directly." kagenti/mcp-gateway v1.0.2 `docs/design/security-architecture.md`:

> "The client's Authorization header is always forwarded to upstream servers,
> allowing them to authenticate and authorize access as needed. As a best
> practice, Authorino can be configured to perform OAuth2 token exchange
> (RFC 8693) ... replacing the client's token with one of reduced scope and
> specific audience ... This limits the blast radius if a backend server is
> compromised."

Threat-model table, same doc:

> "Client OAuth tokens forwarded to backends without token exchange | Medium |
> By design — all headers forwarded | Configure token exchange via AuthPolicy to
> replace client tokens with scoped tokens"

Token exchange is a **scope-reducing best practice**, not a fail-closed boundary.

## No access is gained

The forwarded token (the `aud == server` case) is the client's **own** token,
already scoped to that server. The holder could present it to the backend
directly; the gateway forwarding it grants nothing new. The only real questions
are upstream of the gateway — whether an IdP would mint a user a token whose `aud`
equals an internal MCP server name, and whether the backend trusts the gateway's
forward — both deployment choices.

## Disclosure

None needed — not a vulnerability. For the record, neither `kagenti/mcp-gateway`
nor `Kuadrant/kuadrant-operator` ships a `SECURITY.md`, but both have **GitHub
private vulnerability reporting enabled** (the "Report a vulnerability" button on
each repo's Security tab). Nothing was reported or opened.
