# Private-cache gate (CoSAI 3.2.7) against ContextForge and agentgateway

Drives the private-cached-results probe (`strangertest/cachescope.py`) through
two real MCP gateways, **IBM ContextForge 1.1.1** and **agentgateway 1.7.0**,
in front of a per-user practice upstream, with the practice caching proxy as
the broken / safe fixtures in the same run set. Driver:
`integration/cachescope_gateway_gate.py`. Sample runs:
`integration/sample-runs/{contextforge,agentgateway}-cachescope-{private,public}.json`.

## Result

| Gateway | MCP version (client->gw / gw->upstream) | Caches `resources/read`? | Reads upstream `cacheScope`? | Honouring | Pass-through at the client |
|---|---|---|---|---|---|
| ContextForge 1.1.1 | 2026-07-28 / 2026-07-28 (`server/discover`, no `initialize`) | **No** (1 origin read per gateway read, twice) | **No**: always answers `private` | **INCONCLUSIVE** (no cache to test) | `cacheScope` forced to `private` (`public` rewritten to `private`); `ttlMs` relayed unchanged (60000) |
| agentgateway 1.7.0 | 2026-07-28 / 2026-07-28 (no `initialize`, no `server/discover`) | **No** (1 origin read per gateway read, twice) | **No**: always answers `private` | **INCONCLUSIVE** (no cache to test) | `cacheScope` forced to `private` (`public` rewritten to `private`); `ttlMs` rewritten to `0` |

**The gateway is not graded on labelling.** The run field
`grade_labelling_origin` grades the **origin**, the practice upstream whose
label we set: `CS_UPSTREAM_SCOPE=private` gives **OK**, and `public` (per-user
content mislabelled) gives **LEAK**. That LEAK is the deliberately mislabelled
practice upstream, not a gateway finding. What the gateway showed the client is
a separate, ungraded observation, `gateway_label_at_client`. For this
user-specific resource, both gateways presented `private` in all four runs,
including the runs where the origin said `public`.

**No vulnerability was found in either gateway.** Neither caches
`resources/read` results, so there is nothing whose honouring of a `private`
label could be tested. Both gateways also make a mislabelled `public` result
safe for their downstream clients: they rewrite it to `private`.

### Controls (every run, same upstream, same users)

| Control | Expected | Observed (all 4 runs) |
|---|---|---|
| practice proxy `leaky`, upstream private | honouring LEAK | LEAK |
| practice proxy `safe`, upstream private | honouring OK | OK |
| upstream `public` on per-user content | labelling LEAK | LEAK |
| upstream `private` on per-user content | labelling OK | OK |

The gate keeps a gateway OK only if the matching broken control failed in the
same run set, and downgrades it to INCONCLUSIVE otherwise. **Limit:** neither
gateway has a cache, so there is no broken *gateway* configuration for
honouring. The honouring check is shown able to fail only through the practice
proxy.

## Evidence

### ContextForge 1.1.1 (pip `mcp-contextforge-gateway==1.1.1`, source read-only)

- **No result cache on the read path.** `main.py` builds a `ResourceCache`
  (`RESOURCE_CACHE_SIZE`=1000, `RESOURCE_CACHE_TTL`=3600 s, the defaults), but
  in 1.1.1 nothing calls `resource_cache.get/set`; it is only invalidated. The
  `gateway_mode` "cache" (default; `direct_proxy` is the other value) means
  *catalog* caching. Discovery stores the gateway resource with
  `text_content=None` (`gateway_service.py`), so `read_resource` gets a
  placeholder and federates every read through `invoke_resource`.
  `_template_cache` holds template *metadata*, not results.
- **Catalogued copy vs cached upstream result.** The gate reads CF's DB
  read-only after discovery. The catalogued resource has no stored text or
  blob (`cf_catalogued_content` in the run). The trial reads it twice as A:
  the origin served both reads. This is not a local copy and not a cached
  result. (In 1.0.6 a catalogued resource with stored content was served
  locally. That is a different thing from caching an upstream result; see
  RESULTS.md.)
- **`cacheScope` is not read.** `resource_service.set_upstream_cache_directive`
  keeps the upstream `ttlMs`, but sets `cacheScope` to `"private"` always ("a
  shared cache must never serve it to another"). The adapter
  `_adapt_read_resource` puts that on the modern `ReadResourceResult`. Content
  served from the DB would get `ttlMs` 0 and `private`. Observed: origin
  `public` reaches the client as `private`, and `ttlMs` 60000 is unchanged.
- **Protocol.** `MCP_CLIENT_CONNECT_MODE=auto`: CF's upstream client sent
  `server/discover` and `resources/read` with `MCP-Protocol-Version:
  2026-07-28`. It sent no `initialize`. The probe client spoke 2026-07-28 to CF
  (`HTTPTransport(modern=True)`). CF answered with `resultType: complete` and
  the cache fields. A legacy-version client was not tested.

### agentgateway 1.7.0 (official darwin-arm64 binary, sha256 `34bfc961…bfe`; source at tag v1.7.0, read-only)

- **No result cache.** `crates/agentgateway/src/mcp/` has no response cache
  ("TODO cache list results" in `handler.rs`). The only cache in the config
  schema near MCP backends is `backendAuth.oauthTokenExchange.cache`
  (`TokenCacheConfig`: token-exchange *responses*, by default 8192 entries
  with a 300 s TTL). It was left at its defaults.
- **`cacheScope` is not read.** `handler.rs::with_gateway_cache_policy` sets
  every `ReadResourceResult` (and the list/discover results) to `ttlMs: 0,
  cacheScope: private` ("Cache hints must describe the gateway-visible result,
  not the upstream's result"). `normalize_cache_fields` strips both fields for
  a legacy (pre-2026-07-28) downstream client. Observed: `public`/60000 at the
  origin arrives as `private`/0 at the client.
- **Protocol.** 2026-07-28 on both sides. agentgateway sends neither
  `initialize` nor `server/discover` upstream, and every upstream request
  carries `MCP-Protocol-Version: 2026-07-28`. With a single target, resource
  URIs are not rewritten (`resource_uri`). The URI is identical at the client
  and at the origin, so content comparison is exact.

## How the run guards against false results

- **Content keyed on verified identity.** The upstream's per-user content is
  keyed on the verified JWT `(orig_iss|iss, sub)`, not the raw token. So a
  direct read with the user's token and a gateway read with an exchanged token
  for the same user agree. An unverifiable token is keyed `unverified`, which
  makes A and B identical, so the result is INCONCLUSIVE and never a false
  LEAK. The count is recorded as `upstream_unverified_reads`, which is 0 in
  every run.
- **Content that changes with nobody acting.** The upstream is stable
  (`unstable: false`). The probe also re-reads each identity at the origin
  (`origin_stable: true`). Unstable content can produce neither a false LEAK
  nor a false "no caching" (`caching_observed` requires the repeat read to be
  equal *and* uncounted).
- **Refusal vs authorization.** B is an ordinary authorized user on both
  gateways (CF: a team developer role; agw: `jwtAuth`). B's read succeeded and
  B received B's own content (`b_received: own`), so the result does not rest
  on a refusal.
- **Unsupported feature.** Caching was not observed, so honouring is
  INCONCLUSIVE, never OK.

## Run JSON fields that are easy to misread

- `grade_labelling_origin`: the origin's labelling grade. `grade_labelling_subject` says
  so. It is never a grade of the gateway.
- `grade_honouring`: the gateway, graded as a cache (`grade_honouring_subject`).
- `gateway_label_at_client`: the `cacheScope`/`ttlMs` the gateway presented,
  next to the origin's, with `content_user_specific` and `graded: false`.
- `run_valid` / `run_problems`: false or non-empty when a control was not as
  expected, the gateway probe could not observe (ProbeError), the pass-through
  read failed, or the upstream saw an unverifiable token.

## Exit codes

| Exit | Meaning |
|---|---|
| 0 | the run completed, every control was as expected, and the run is saved |
| 1 | the run is saved with its grades, but `run_problems` is non-empty: a control was not as expected (detection unproven for this run set), the gateway probe raised ProbeError (cannot observe; the file keeps INCONCLUSIVE), the pass-through read failed, or `upstream_unverified_reads > 0`. Also exit 1 when the gate refuses (port policy, setup failure); then nothing is saved |
| 2 | cannot run: pyjwt[crypto] / local_as missing (ERROR on stderr) |

## Run it

Ports must come from the caller's block (4300-4399). The gate **refuses**
4444, 8790, any port outside the block, and any unset port; there are no
defaults. Ports and URLs are written into the run.

```
# agentgateway (the gate starts the binary on a port-substituted copy of
# integration/agentgateway/cachescope-tokenexchange.yaml in CS_SCRATCH)
CS_GATEWAY=agentgateway CS_UPSTREAM_SCOPE=private \
CS_AS_PORT=4390 CS_UPSTREAM_PORT=4380 CS_GW_PORT=4330 CS_AGW_ADMIN_PORT=4331 \
CS_FIXTURE_PORT=4381 CS_SCRATCH=<scratch> AGW_BIN=<agentgateway-darwin-arm64> \
  <venv>/bin/python integration/cachescope_gateway_gate.py

# ContextForge (start it yourself first: HOST=127.0.0.1 PORT=4344, plus the
# .env of CONTEXTFORGE_GATE.md; run from its home with .env sourced)
CS_GATEWAY=contextforge CS_UPSTREAM_SCOPE=private \
CS_AS_PORT=4390 CS_UPSTREAM_PORT=4380 CS_GW_PORT=4344 CS_FIXTURE_PORT=4381 \
CS_SCRATCH=<scratch> <venv>/bin/python integration/cachescope_gateway_gate.py
```

`CS_UPSTREAM_SCOPE` is `private`, `public` or `none`. `CS_OUT` sets the output
path. The default is `integration/runs/<gw>-cachescope-<scope>-<ts>.json`. The
gate starts its own local AS and upstream (the upstream on both loopback
families, since CF connects via `localhost`), and stops them when it ends. On
CF it deletes the gateway and virtual server it registered. The gate refuses to
save a run that contains anything JWT-shaped.
