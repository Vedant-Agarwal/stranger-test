# Kuadrant XID-10 gate — reproduction recipe

Kuadrant 1.6.0 Authorino RFC 8693 token exchange, driven with the existing
probes. Results label: **"Kuadrant 1.6.0 Authorino token exchange (sample policy,
minimally adapted) on a direct route; the mcp router/broker was not in the path"**.
Loopback only; tokens stored as `sha256:` fingerprints.

Option **(b)**: the exchange is performed by **Authorino** via an `AuthPolicy`
(not the mcp broker), so this gate applies the minimally-adapted sample policy to
an Istio Gateway listener on a **direct HTTPRoute** to a recording upstream. The
mcp router/broker is **not** in the path, so the driver sets `x-mcp-servername`
itself, as the router would (client-supplied values of that header are not graded
or reported).

## Versions

Pinned in `notes/kuadrant-versions.md` (digests recorded): Istio 1.27.0, Gateway
API v1.4.1, cert-manager v1.16.2, Kuadrant operator chart 1.6.0 (which deploys
Authorino v0.28.0 + mcp-controller v1.0.2). Tooling kind v0.33.0 / istioctl 1.27.0
/ helm v3.22.1, downloaded to a scratch dir with sha256 verification (no
system-wide installs). Node image `kindest/node:v1.37.0` (digest-pinned).

## Cluster + stack

```
export PATH=<scratch>/bin:$PATH KUBECONFIG=<scratch>/kubeconfig
kind create cluster --name st-kuadrant --image kindest/node:v1.37.0@sha256:a1ed56... --kubeconfig $KUBECONFIG
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.4.1/standard-install.yaml
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.16.2/cert-manager.yaml   # wait ready
istioctl install --set profile=minimal -y
helm repo add kuadrant https://kuadrant.io/helm-charts && helm repo update
kubectl create namespace kuadrant-system
helm install kuadrant-operator kuadrant/kuadrant-operator --version 1.6.0 -n kuadrant-system --wait
kubectl apply -f -   # Kuadrant CR {apiVersion: kuadrant.io/v1beta1, kind: Kuadrant, name: kuadrant, ns: kuadrant-system}
```

## Networking (see `notes/kuadrant-networking.md`)

local_as stays on `127.0.0.1` only (not `0.0.0.0`); the cluster reaches it via
`host.docker.internal` (verified from a pod → HTTP 200). Start it with the
matching issuer so the `iss` claim matches `issuerUrl`:

```
python integration/local_as.py serve --port 4610 --key-path <scratch>/as.pem \
  --issuer http://host.docker.internal:4610
```

The recording upstream runs on `127.0.0.1:4612` (the gate's `KuaRecorder`); the
gateway routes to it via a no-selector Service + an EndpointSlice at the
Docker-Desktop host IP (`192.168.65.254` here, IPv4).

## Gateway + route + policy

Apply: a Gateway (`gatewayClassName: istio`, listener `mcps` port 8080); a Service
`upstream` + EndpointSlice → `192.168.65.254:4612`; an HTTPRoute (parent
`mcp-gateway`/`mcps`) → `upstream`; a Secret `token-exchange`
(`oauth-client-basic-auth`); and the AuthPolicy
`integration/kuadrant/kuadrant-mcps-auth-policy.yaml`. Two gotchas:

- The `token-exchange` Secret must be in **`kuadrant-system`** (where the generated
  AuthConfig lives) **with the label `authorino.kuadrant.io/managed-by=authorino`**
  (Authorino's filtered secret cache ignores unlabeled secrets).
- The sample's exchange requests `scope: openid`, so subject tokens must carry
  `openid` or `local_as` refuses with `invalid_scope`.

Wait for `AuthPolicy` `Enforced=True`, then `kubectl -n gateway-system
port-forward svc/mcp-gateway-istio 18080:8080`.

## Run the probes

```
export AS_BASE=http://127.0.0.1:4610 GW_URL=http://127.0.0.1:18080/ \
       UPSTREAM_PORT=4612 FIXTURE_BASE=4620
KUA_MODE=delegation    python integration/xid10_kuadrant_gate.py
# exchange_fail: point the AuthPolicy's exchange URL at a switchable endpoint and
#   set SWITCH_URL (host switchable token endpoint), then:
SWITCH_URL=http://127.0.0.1:4613 KUA_MODE=exchange_fail python integration/xid10_kuadrant_gate.py
```

delegation: `actor_present` FAIL (Authorino sends no `actor_token` → impersonation),
all other checks OK, each gated by an in-run thin-deputy fixture. exchange_fail:
**fails closed** (nothing reaches the upstream when a token that needs exchange
cannot be exchanged). The `aud == server` no-exchange pass-through is documented
and by design — see `notes/kuadrant-aud-passthrough.md`.

Runs are saved to `integration/runs/` (gitignored); committed fingerprint-only
copies are in `integration/sample-runs/kuadrant-*.json`, and the Kuadrant section
of `RESULTS.md` is generated from them by `gen_results.py` (regenerate twice —
byte-identical). Full suite: `python -m unittest discover`.

## Teardown

```
kind delete cluster --name st-kuadrant
docker rmi kindest/node@sha256:a1ed56...   # prune the pulled node image
```

Stop the `local_as` / switch / upstream host processes; confirm no 46xx listeners,
no kind containers, no pulled images left.
