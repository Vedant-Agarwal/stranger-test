# Kuadrant XID-10 gate — pinned versions (2026-11-14)

Exact versions for the Kuadrant / kagenti MCP Gateway Step 2 build. Chosen to
match what **kagenti/mcp-gateway v1.0.2** itself installs (its `Makefile` +
`build/*.mk`), so the stack is a known-compatible set rather than "latest of
everything". Localhost-only kind cluster `st-kuadrant`; tooling downloaded to a
scratch dir with checksum verification (no system-wide installs).

## Tooling (downloaded to scratch, checksum-verified)

| Tool | Pin | Why |
|---|---|---|
| kind | **v0.33.0** | latest stable; node image pinned below |
| kind node image | **kindest/node:v1.37.0** `@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5` | the default node image shipped with kind v0.33.0 (digest-pinned) |
| helm | **v3.22.1** | latest Helm **3** (the Kuadrant charts are Helm-3 charts; not Helm 4) |
| istioctl | **1.27.0** | matches the Istio version mcp-gateway installs (below) |

`kubectl` is already present on the host and is used as-is.

## Stack (installed into the kind cluster)

| Component | Pin | Source of the pin |
|---|---|---|
| Gateway API CRDs | **v1.4.1** | mcp-gateway v1.0.2 `Makefile`: `GATEWAY_API_VERSION ?= v1.4.1` |
| Istio | **1.27.0** | mcp-gateway v1.0.2 `build/istio.mk`: `ISTIO_VERSION = 1.27.0` |
| Sail operator (installs Istio) | **1.27.0** | `build/istio.mk`: `SAIL_VERSION = 1.27.0` (chart `sail-operator-1.27.0.tgz`) |
| cert-manager | **v1.16.2** | mcp-gateway v1.0.2 `CERT_MANAGER_VERSION := 1.16.2` (installs `cert-manager.yaml` for that tag) |
| Kuadrant operator (Helm chart) | **1.6.0** (appVersion 1.6.0) | `kuadrant/kuadrant-operator` chart from `https://kuadrant.io/helm-charts` — mcp-gateway installs it **unpinned**, so we pin the latest stable chart 1.6.0 explicitly (`--version 1.6.0`) |
| Authorino | **deployed by kuadrant-operator 1.6.0** | the Kuadrant operator deploys Authorino + Limitador; the exact Authorino image is resolved at install and will be recorded from the running pod (`Kuadrant/authorino` latest release is v0.26.4, `authorino-operator` v0.25.4 — the operator picks the matching one) |
| kagenti/mcp-gateway | **v1.0.2** | commit `e48ae51cfa52a57f93f334bdadbe8ce58ef5a9f6`, Apache-2.0 (the gateway under test) |

## Notes

- **Istio is 1.27.0, not the latest 1.32.0** — deliberately, to match mcp-gateway
  v1.0.2's pin. Running a newer Istio than the gateway was built against risks
  Gateway-API/EnvoyFilter incompatibilities that are not what we are testing.
- **Authorino performs the RFC 8693 exchange** (via a Kuadrant `AuthPolicy`
  `metadata.http` evaluator + `response` header rewrite), not the gateway broker.
  The authoritative `AuthPolicy` is `config/e2e/auth/mcps-auth-policy.yaml` in
  mcp-gateway v1.0.2 (and the Red Hat article); we adapt it to point `issuer`,
  `metadata.http.url` and the token endpoint at our local AS.
- The **actual** Authorino / Istio / mcp-controller image digests seen in the
  running cluster will be captured into each saved run and into
  `integration/KUADRANT_GATE.md` at run time, so the record reflects what ran,
  not only what was requested.

## Resolved at install (st-kuadrant, 2026-11-14) — actual image digests

The Kuadrant operator **chart 1.6.0** installed the whole MCP-gateway stack in one
Helm release (no separate kagenti/mcp-gateway install needed): Authorino,
Limitador, dns-operator, and the **mcp-controller v1.0.2** + its `mcp.kuadrant.io`
CRDs (`mcpserverregistrations`, `mcpvirtualservers`, `mcpgatewayextensions`).

| Component | Image @ digest (as running) |
|---|---|
| Istio (istiod/pilot) 1.27.0 | `docker.io/istio/pilot@sha256:502c5a57143e80f9d8731bf08a25f31f09dbe231284233b9e715b4e62f22639b` |
| Authorino **v0.28.0** | `quay.io/kuadrant/authorino@sha256:7cd154fd67782980cdfc4d38e26778371344ffd77bf230ca884cebac96b4b8c1` |
| mcp-controller **v1.0.2** | `ghcr.io/kuadrant/mcp-controller@sha256:8db84727bca72d1597d0ac2712b0b7dd07346dc28c57131403bbb1f236f29bef` |

Authorino resolved to **v0.28.0** (the Kuadrant 1.6.0 operator's choice — this
settles the feasibility note's v0.28.0-vs-v0.26.4 ambiguity: the operator deploys
v0.28.0). Gateway API v1.4.1 CRDs and cert-manager v1.16.2 installed and ready.

## Sources

- https://github.com/kagenti/mcp-gateway (tag v1.0.2): `Makefile`, `build/istio.mk`,
  `build/kuadrant.mk`, `build/cert-manager.mk`, `config/e2e/auth/mcps-auth-policy.yaml`
- Helm chart index: https://kuadrant.io/helm-charts/index.yaml
- kind v0.33.0 release (node image digests); helm v3.22.1; Istio 1.27.0.
