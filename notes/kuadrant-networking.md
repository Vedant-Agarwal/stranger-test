# Kuadrant gate — cluster→host networking (st-kuadrant, 2026-11-14)

**Option used: 1 (local_as on host loopback, reached via `host.docker.internal`).**

Tested in the order the operator asked:

1. **local_as on `127.0.0.1` (loopback only), reached from a pod via
   `host.docker.internal` — WORKS.** A throwaway pod
   (`curlimages/curl`) resolved `host.docker.internal` (Docker Desktop maps it to
   its host gateway, `fdc4:f303:9324::254` here) and `GET
   http://host.docker.internal:4610/jwks` returned **HTTP 200** in ~0.01 s.
   So the AS is bound to loopback only — **not `0.0.0.0`, not any LAN interface** —
   and Docker Desktop forwards `host.docker.internal` traffic to the host's
   loopback. Pods reach it at `http://host.docker.internal:<port>`.
2. Not needed (option 1 worked): running local_as / the recording upstream as
   containers on the `kind` network, or as in-cluster pods.
3. Not needed: binding to a narrower host address.

**How the cluster reaches the host services** (both bound to `127.0.0.1` on the
Mac, nothing else exposed):
- `local_as` → `http://host.docker.internal:4610` (OIDC discovery, JWKS, `/token`
  RFC 8693 exchange).
- recording upstream → `http://host.docker.internal:<upstream-port>`.

Authorino's `metadata.http` evaluator and the mcp broker dial these via
`host.docker.internal`. The probe client reaches the Istio gateway from the host
via `kubectl port-forward` (no LoadBalancer / metallb, no NodePort exposed on the
LAN).
