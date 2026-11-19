"""A minimal but REAL local Authorization Server for the XID-10 gate.

This is the "local IdP such as Keycloak" the delegation gate needs, kept small
enough to read in one sitting but real where it counts: it signs RS256 JWTs with
an RSA key, publishes a JWKS, and implements the RFC 8693 token-exchange grant
(subject_token + optional actor_token -> a new signed token whose ``sub`` is the
end user, whose ``act`` names the acting client in delegation mode and is absent
in impersonation mode, and whose ``aud``/``scope`` are the exchange target's).

It exists so the delegation probe can be driven against genuine signed tokens
and a genuine token-exchange exchange, not the unsigned ``alg:none`` blobs of
the in-repo practice fixture. A real gateway (ContextForge) is the deputy under
test; this AS is only the identity provider behind it.

Per-issuer keys. Besides its own key (``/jwks``, used to sign exchanged and
client tokens), the AS holds one signing key per test login provider
(default ``provx`` -> ``https://provx.test``, ``provy`` -> ``https://provy.test``)
and publishes each at ``/jwks/<name>``. A subject token is validated with the
key belonging to ITS issuer; a subject token whose issuer is not registered is
refused (``lax_subject_issuer=True`` relaxes that, see below).

Scope cap. The exchange NEVER grants a scope the subject token lacks: the
issued scope is ``requested ∩ subject scope`` (requested order kept); with no
``scope`` parameter it is the subject's own scope; a request with no overlap is
refused (``invalid_scope``). So any scope at an upstream beyond the user's own
cannot have come from this AS — it came from the deputy.

Exchange log. Every exchange request is recorded in ``exchanges`` (and served
at ``GET /exchanges``) with the scope/audience it requested, whether an actor
token was present, what was issued and the outcome — keyed by ``sha256:``
fingerprints of the subject and issued tokens, never the tokens themselves.

``lax_subject_issuer`` (opt-in, default False): accept a subject token from any
issuer as long as its signature verifies under one of this AS's keys (picked by
``kid``). Used only by the issuer-binding probe, so that a gateway that lets an
unregistered issuer through is not masked by the AS refusing the exchange —
the probe then observes the gateway's decision, not the AS's.

Client authentication (token-exchange grant only; opt-in). ``clients`` registers
``client_id -> client_secret`` pairs. Every exchange record says whether client
credentials arrived (``client_auth_method``: ``client_secret_basic``,
``client_secret_post``, ``client_id_only``, ``multiple`` or None), which
``client_id`` was presented, and whether the credentials were valid
(``client_valid``: True/False, or None when no clients are registered, so nothing
was checked). The secret is never logged. ``client_auth`` decides what is
refused: ``none`` (default: nothing, exactly the old behaviour), ``optional``
(credentials that arrive must be valid) or ``strict`` (valid credentials are
required). A refusal is HTTP 401 ``invalid_client``.

``act_from_client`` (opt-in, default False): when an exchange carries VALID client
credentials and NO actor_token, the issued token gets ``act: {"sub": client_id}``
-- the actor is the authenticated gateway. Recorded per exchange as
``act_source`` (``actor_token`` / ``client_auth`` / None).

Needs pyjwt[crypto] to run. Run ``python integration/local_as.py`` for a
self-test, or ``python integration/local_as.py serve --port N`` to serve.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs

# pyjwt / cryptography are needed to sign and verify, but the pure helpers
# below (cap_scope, token_fingerprint, select_subject_key) are imported by the
# stdlib-only unit tests, so the module must import without them.
try:
    import jwt
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
except Exception:  # pragma: no cover - exercised by the stdlib test run
    jwt = None  # type: ignore[assignment]
    serialization = rsa = None  # type: ignore[assignment]

TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"

# The two test login providers (same-named users, different issuers).
DEFAULT_PROVIDERS = {"provx": "https://provx.test", "provy": "https://provy.test"}
AS_KEY_NAME = "as"


def _b64url_uint(n: int) -> str:
    import base64

    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


# -- pure helpers (stdlib only; unit-tested) ------------------------------

def token_fingerprint(token: Optional[str]) -> Optional[str]:
    """``sha256:<12 hex>`` — the same fingerprint the gates store for tokens."""
    if not token:
        return None
    return "sha256:" + hashlib.sha256(token.encode()).hexdigest()[:12]


def _scope_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value if v is not None]
    return str(value).split()


def cap_scope(requested: Optional[str], subject_scope: Any) -> str:
    """The scope to issue: ``requested ∩ subject`` (requested order kept).

    No ``requested`` (absent or blank) -> the subject's own scope, unchanged.
    Never contains a scope the subject lacks. Returns ``""`` when the request
    and the subject share nothing (the caller refuses that with invalid_scope).
    """
    subject = _scope_list(subject_scope)
    if requested is None or not str(requested).strip():
        return " ".join(subject)
    have = set(subject)
    granted: List[str] = []
    for s in str(requested).split():
        if s in have and s not in granted:
            granted.append(s)
    return " ".join(granted)


def select_subject_key(
    iss: Optional[str], kid: Optional[str], issuer_keys: Dict[str, str],
    kid_keys: Dict[str, str], *, lax: bool,
) -> Tuple[Optional[str], str]:
    """Pick the key NAME that must verify a subject token.

    ``issuer_keys`` maps issuer URL -> key name; ``kid_keys`` maps kid -> key
    name. Strict: the token's issuer must be registered, and its key is the
    one used (a token signed by another trusted key then fails signature
    verification). Lax: any key we hold, chosen by ``kid``. Returns
    ``(key_name or None, reason)``.
    """
    if not lax:
        if iss in issuer_keys:
            return issuer_keys[iss], "issuer registered"
        return None, f"unregistered issuer {iss!r}"
    if kid in kid_keys:
        return kid_keys[kid], "lax: key chosen by kid, issuer not checked"
    return None, f"lax: unknown kid {kid!r}"


CLIENT_AUTH_MODES = ("none", "optional", "strict")


class ClientAuthError(ValueError):
    """The token endpoint refuses the client (HTTP 401 ``invalid_client``)."""


def parse_client_auth(params: Dict[str, str], authorization: Optional[str]
                      ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """``(method, client_id, client_secret)`` from a token request (RFC 6749 2.3.1).

    ``client_secret_basic``: ``Authorization: Basic base64(urlenc(id):urlenc(secret))``.
    ``client_secret_post``: ``client_id`` + ``client_secret`` form parameters.
    ``client_id_only``: a ``client_id`` parameter and no secret anywhere.
    ``multiple``: Basic AND a ``client_secret`` parameter (RFC 6749 forbids
    more than one method). ``(None, None, None)``: no client credentials.
    A malformed Basic header is reported as ``client_secret_basic`` with no id.
    """
    import base64
    from urllib.parse import unquote_plus
    basic = None
    if authorization and authorization[:6].lower() == "basic ":
        try:
            raw = base64.b64decode(authorization[6:].strip(), validate=True).decode()
            cid, sep, sec = raw.partition(":")
            basic = (unquote_plus(cid), unquote_plus(sec)) if sep else (None, None)
        except Exception:
            basic = (None, None)
    post_id, post_secret = params.get("client_id"), params.get("client_secret")
    if basic is not None and post_secret is not None:
        return "multiple", basic[0] or post_id, None
    if basic is not None:
        return "client_secret_basic", basic[0], basic[1]
    if post_secret is not None:
        return "client_secret_post", post_id, post_secret
    if post_id:
        return "client_id_only", post_id, None
    return None, None, None


def check_client(method: Optional[str], client_id: Optional[str], secret: Optional[str],
                 clients: Dict[str, str]) -> Optional[bool]:
    """True/False whether the presented credentials are a registered pair;
    None when no clients are registered (nothing checked)."""
    if not clients:
        return None
    if method not in ("client_secret_basic", "client_secret_post"):
        return False
    import hmac
    want = clients.get(client_id or "")
    return want is not None and secret is not None and hmac.compare_digest(want, secret)


class _Key:
    """One RSA signing key with a deterministic kid."""

    def __init__(self, path: Optional[str] = None):
        if path and os.path.exists(path):
            with open(path, "rb") as fh:
                self.private = serialization.load_pem_private_key(fh.read(), password=None)
        else:
            self.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.pem = self.private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        if path and not os.path.exists(path):
            with open(path, "wb") as fh:
                fh.write(self.pem)
        self.public = self.private.public_key()
        nums = self.public.public_numbers()
        # Deterministic kid from the public key, so it is stable across restarts.
        self.kid = hashlib.sha256(_b64url_uint(nums.n).encode()).hexdigest()[:16]

    def jwk(self) -> Dict[str, Any]:
        nums = self.public.public_numbers()
        return {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": self.kid,
                "n": _b64url_uint(nums.n), "e": _b64url_uint(nums.e)}


class LocalAS:
    """A real RS256 authorization server with an RFC 8693 token endpoint."""

    def __init__(self, issuer: str = "https://local-as.test", ttl: int = 3600,
                 key_path: Optional[str] = None,
                 providers: Optional[Dict[str, str]] = None,
                 lax_subject_issuer: bool = False,
                 clients: Optional[Dict[str, str]] = None,
                 client_auth: str = "none",
                 act_from_client: bool = False):
        if client_auth not in CLIENT_AUTH_MODES:
            raise ValueError(f"client_auth must be one of {CLIENT_AUTH_MODES}")
        if client_auth != "none" and not clients:
            raise ValueError("client_auth optional/strict needs registered clients")
        if act_from_client and not clients:
            raise ValueError("act_from_client needs registered clients")
        self.clients: Dict[str, str] = dict(clients or {})
        self.client_auth = client_auth
        self.act_from_client = act_from_client
        self.issuer = issuer
        self.ttl = ttl
        self.lax_subject_issuer = lax_subject_issuer
        # Persist keys when a path is given, so restarts keep the same keys
        # (and a gateway's cached JWKS stays valid). Provider keys live next to
        # the AS key as <key_path minus .pem>.<name>.pem.
        self._keys: Dict[str, _Key] = {AS_KEY_NAME: _Key(key_path)}
        self.providers: Dict[str, str] = dict(DEFAULT_PROVIDERS if providers is None else providers)
        for name in self.providers:
            ppath = None
            if key_path:
                base = key_path[:-4] if key_path.endswith(".pem") else key_path
                ppath = f"{base}.{name}.pem"
            self._keys[name] = _Key(ppath)
        self._key = self._keys[AS_KEY_NAME].private
        self._private_pem = self._keys[AS_KEY_NAME].pem
        self._public = self._keys[AS_KEY_NAME].public
        self.kid = self._keys[AS_KEY_NAME].kid
        self.exchanges: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    # -- key material ----------------------------------------------------

    def jwks(self, name: Optional[str] = None) -> Dict[str, Any]:
        """The AS's own JWKS, or (``name``) one provider's."""
        return {"keys": [self._keys[name or AS_KEY_NAME].jwk()]}

    def _issuer_keys(self) -> Dict[str, str]:
        m = {iss: name for name, iss in self.providers.items()}
        m[self.issuer] = AS_KEY_NAME
        return m

    def _key_name_for_issuer(self, issuer: Optional[str]) -> str:
        return self._issuer_keys().get(issuer or self.issuer, AS_KEY_NAME)

    def _sign(self, claims: Dict[str, Any], issuer: Optional[str] = None,
              key_name: Optional[str] = None) -> str:
        now = int(time.time())
        # jti makes every minted token unique, so distinct exchanges produce
        # distinct tokens (lets the probe tell a per-principal exchange from a
        # cache that conflated two callers).
        payload = {"iss": issuer or self.issuer, "iat": now, "exp": now + self.ttl,
                   "jti": uuid.uuid4().hex, **claims}
        key = self._keys[key_name or AS_KEY_NAME]
        return jwt.encode(payload, key.pem, algorithm="RS256", headers={"kid": key.kid})

    def validate(self, token: str, *, audience: Optional[str] = None,
                 verify_issuer: bool = True) -> Dict[str, Any]:
        """Verify a token signed with the AS's OWN key (raises on failure)."""
        options = {"verify_aud": audience is not None, "verify_iss": verify_issuer}
        return jwt.decode(
            token,
            self._public,
            algorithms=["RS256"],
            audience=audience,
            issuer=self.issuer if verify_issuer else None,
            options=options,
        )

    def validate_subject(self, token: str) -> Tuple[Dict[str, Any], str]:
        """Validate a subject token with the key that belongs to its issuer.

        Returns ``(claims, how)``; raises ValueError on an unregistered issuer
        (strict mode) or a signature that does not verify under that key.
        """
        header = jwt.get_unverified_header(token)
        unverified = jwt.decode(token, options={"verify_signature": False})
        iss = unverified.get("iss")
        kid_keys = {k.kid: name for name, k in self._keys.items()}
        name, how = select_subject_key(iss, header.get("kid"), self._issuer_keys(),
                                       kid_keys, lax=self.lax_subject_issuer)
        if name is None:
            raise ValueError(f"invalid_grant: {how}")
        claims = jwt.decode(token, self._keys[name].public, algorithms=["RS256"],
                            options={"verify_aud": False, "require": ["exp", "iss"]})
        return claims, f"{how} (key {name})"

    # -- issuing ---------------------------------------------------------

    def issue_user_token(self, sub: str, *, scope: str = "read:notes",
                         audience: Optional[str] = None,
                         email: Optional[str] = None,
                         issuer: Optional[str] = None,
                         signing_key: Optional[str] = None,
                         act: Optional[str] = None,
                         may_act: Optional[Dict[str, Any]] = None,
                         resource_access: Optional[Dict[str, Any]] = None) -> str:
        """A user's access token — the subject_token a deputy would exchange.

        Carries an ``email`` claim: gateways (e.g. ContextForge) provision the
        external user from it and reject a token without one. ``issuer`` lets a
        caller mint under a specific provider issuer; it is signed with that
        provider's key unless ``signing_key`` names another key (the
        issuer-binding probe signs an UNREGISTERED issuer with a trusted key).
        ``act`` adds an ``act`` claim (a fixture deputy minting its own token).
        """
        claims: Dict[str, Any] = {"sub": sub, "scope": scope,
                                  "aud": audience or self.issuer,
                                  "email": email or f"{sub}@local-as.test"}
        if act:
            claims["act"] = {"sub": act}
        if may_act:
            # RFC 8693 4.4: who may act for this subject (opt-in, test harness).
            claims["may_act"] = dict(may_act)
        if resource_access:
            # Keycloak-style per-client roles claim (opt-in, test harness): lets a
            # gate reproduce a sample policy that checks resource_access[...].roles.
            claims["resource_access"] = dict(resource_access)
        key_name = signing_key or self._key_name_for_issuer(issuer)
        return self._sign(claims, issuer=issuer, key_name=key_name)

    def issue_client_token(self, client_id: str, *, ttl: Optional[int] = None,
                           audience: Optional[str] = None) -> str:
        """A client-credentials token identifying the acting gateway (actor_token).

        ``ttl`` (seconds, may be negative: already expired) and ``audience``
        are for the actor-token checks only; the defaults are unchanged."""
        claims: Dict[str, Any] = {"sub": client_id, "scope": "act"}
        if audience is not None:
            claims["aud"] = audience
        if ttl is None:
            return self._sign(claims)
        now = int(time.time())
        return self._sign({**claims, "iat": now - max(0, -ttl) - 60, "exp": now + ttl})

    def client_credentials(self, params: Dict[str, str]) -> Dict[str, Any]:
        """Issue a client-credentials token (the gateway's actor token in delegation)."""
        client_id = params.get("client_id") or "client"
        token = self.issue_client_token(client_id)
        return {"access_token": token, "token_type": "Bearer", "expires_in": self.ttl,
                "issued_token_type": ACCESS_TOKEN_TYPE}

    def token(self, params: Dict[str, str], authorization: Optional[str] = None) -> Dict[str, Any]:
        """Dispatch the /token endpoint by grant_type. ``authorization`` is the
        request's Authorization header (client_secret_basic)."""
        grant = params.get("grant_type")
        if grant == "client_credentials":
            return self.client_credentials(params)
        return self.token_exchange(params, authorization=authorization)

    def _record(self, rec: Dict[str, Any]) -> None:
        with self._lock:
            rec["seq"] = len(self.exchanges) + 1
            self.exchanges.append(rec)

    def exchange_for(self, issued_fp: Optional[str]) -> Optional[Dict[str, Any]]:
        """The exchange record that issued the token with this fingerprint."""
        with self._lock:
            for r in self.exchanges:
                if issued_fp and r.get("issued_fp") == issued_fp:
                    return dict(r)
        return None

    def token_exchange(self, params: Dict[str, str],
                       authorization: Optional[str] = None) -> Dict[str, Any]:
        """Perform an RFC 8693 token exchange and return the token response dict."""
        if params.get("grant_type") != TOKEN_EXCHANGE_GRANT:
            raise ValueError("unsupported_grant_type")
        subject_token = params.get("subject_token")
        # What the deputy asked for, recorded whatever the outcome. "scope" is
        # None when the parameter was absent (the deputy requested nothing).
        rec: Dict[str, Any] = {
            "time": time.time(),
            "subject_fp": token_fingerprint(subject_token),
            "requested_scope": params.get("scope"),
            "requested_audience": params.get("audience"),
            "actor_present": bool(params.get("actor_token")),
            "actor_fp": token_fingerprint(params.get("actor_token")),
        }
        method, client_id, secret = parse_client_auth(params, authorization)
        valid = check_client(method, client_id, secret, self.clients)
        rec.update(client_auth_method=method, client_id=client_id, client_valid=valid,
                   client_auth_mode=self.client_auth)
        del secret  # never recorded
        try:
            if self.client_auth == "strict" and valid is not True:
                raise ClientAuthError("invalid_client: valid client credentials required")
            if self.client_auth == "optional" and method is not None and valid is not True:
                raise ClientAuthError("invalid_client: client credentials not valid")
            if not subject_token:
                raise ValueError("invalid_request: subject_token required")
            subject, how = self.validate_subject(subject_token)
            rec.update(subject_iss=subject.get("iss"), subject_sub=subject.get("sub"),
                       subject_scope=subject.get("scope"), subject_key=how)

            actor_token = params.get("actor_token")
            act: Optional[Dict[str, Any]] = None
            if actor_token:
                try:
                    actor = self.validate(actor_token)
                except Exception as exc:
                    rec["actor_check"] = f"refused: {type(exc).__name__}"
                    raise ValueError(f"invalid_grant: actor_token {type(exc).__name__}") from exc
                # What this AS checks on an actor token: its own signature, its
                # own issuer, expiry. NOT the audience (recorded per exchange).
                rec.update(actor_check="signature+issuer+expiry (audience not checked)",
                           actor_sub=actor.get("sub"), actor_aud=actor.get("aud"))
                act = {"sub": actor.get("sub")}
                # Preserve any delegation chain the subject already carried.
                if isinstance(subject.get("act"), dict):
                    act["act"] = subject["act"]
                rec["act_source"] = "actor_token"
            elif self.act_from_client and valid is True:
                # The authenticated client (the gateway) is the actor.
                act = {"sub": client_id}
                if isinstance(subject.get("act"), dict):
                    act["act"] = subject["act"]
                rec["act_source"] = "client_auth"
            else:
                rec["act_source"] = None

            audience = params.get("audience") or self.issuer
            # Never grant more than the subject has: requested ∩ subject, or the
            # subject's own scope when nothing was requested.
            scope = cap_scope(params.get("scope"), subject.get("scope", ""))
            if params.get("scope") and not scope:
                raise ValueError("invalid_scope: requested scope not held by the subject")

            claims: Dict[str, Any] = {"sub": subject.get("sub"), "aud": audience, "scope": scope}
            # Carry the end user's ORIGINAL identity through the exchange: the
            # original issuer (the login provider) and email. The upstream grades
            # identity on (orig_iss, subject), so a gateway that conflates two
            # same-named users from different providers is caught — their orig_iss
            # differs even though the subject matches.
            if subject.get("iss") is not None:
                claims["orig_iss"] = subject.get("iss")
            if subject.get("email") is not None:
                claims["email"] = subject.get("email")
            if act is not None:
                claims["act"] = act
            token = self._sign(claims)
        except Exception as exc:
            rec["outcome"] = f"refused: {exc}"
            self._record(rec)
            raise
        rec.update(outcome="granted", issued_fp=token_fingerprint(token),
                   issued_scope=scope, issued_audience=audience)
        self._record(rec)
        return {
            "access_token": token,
            "issued_token_type": ACCESS_TOKEN_TYPE,
            "token_type": "Bearer",
            "expires_in": self.ttl,
            "scope": scope,
        }

    # -- HTTP front ------------------------------------------------------

    def serve(self, host: str = "127.0.0.1", port: int = 0) -> ThreadingHTTPServer:
        as_ = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _json(self, code: int, body: Any):
                data = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                from urllib.parse import urlparse, parse_qs
                parsed = urlparse(self.path)
                path = parsed.path.rstrip("/")
                if path in ("/jwks", "/.well-known/jwks.json"):
                    self._json(200, as_.jwks())
                elif path.startswith("/jwks/"):
                    name = path[len("/jwks/"):]
                    if name in as_._keys:
                        self._json(200, as_.jwks(name))
                    else:
                        self._json(404, {"error": "unknown_key"})
                elif path == "/exchanges":
                    # Fingerprints and scopes only; never a token.
                    with as_._lock:
                        self._json(200, list(as_.exchanges))
                elif path == "/issue":
                    # DEV ONLY: mint a user access token (the subject_token a
                    # caller presents to a gateway). Local test harness use only.
                    q = parse_qs(parsed.query)
                    sub = q.get("sub", ["alice"])[0]
                    aud = q.get("aud", [as_.issuer])[0]
                    scope = q.get("scope", ["read:notes"])[0]
                    iss = q.get("iss", [None])[0]
                    email = q.get("email", [None])[0]
                    key = q.get("key", [None])[0]
                    act = q.get("act", [None])[0]
                    may_act_raw = q.get("may_act", [None])[0]
                    ra_raw = q.get("ra", [None])[0]
                    try:
                        may_act = json.loads(may_act_raw) if may_act_raw else None
                        resource_access = json.loads(ra_raw) if ra_raw else None
                    except ValueError:
                        self._json(400, {"error": "may_act/ra must be JSON"})
                        return
                    if key is not None and key not in as_._keys:
                        self._json(400, {"error": "unknown_key"})
                        return
                    self._json(200, {"access_token": as_.issue_user_token(
                        sub, scope=scope, audience=aud, issuer=iss, email=email,
                        signing_key=key, act=act, may_act=may_act,
                        resource_access=resource_access)})
                elif path == "/issue-client":
                    # DEV ONLY: mint an actor (client) token with a chosen client
                    # id, lifetime (negative = expired) and audience.
                    q = parse_qs(parsed.query)
                    ttl = q.get("ttl", [None])[0]
                    self._json(200, {"access_token": as_.issue_client_token(
                        q.get("client_id", ["client"])[0],
                        ttl=int(ttl) if ttl is not None else None,
                        audience=q.get("aud", [None])[0])})
                elif self.path.rstrip("/") == "/.well-known/openid-configuration":
                    base = f"http://{self.headers.get('Host', host)}"
                    self._json(200, {
                        "issuer": as_.issuer,
                        "token_endpoint": f"{base}/token",
                        "jwks_uri": f"{base}/jwks",
                        "grant_types_supported": [TOKEN_EXCHANGE_GRANT],
                        # test-harness facts the gates record in each run
                        "x_lax_subject_issuer": as_.lax_subject_issuer,
                        "x_client_auth": as_.client_auth,
                        "x_act_from_client": as_.act_from_client,
                        "x_clients": sorted(as_.clients),  # ids only, never secrets
                        "x_providers": as_.providers,
                        "x_scope_cap": "requested ∩ subject; subject's scope if none requested",
                    })
                else:
                    self._json(404, {"error": "not_found"})

            def do_POST(self):
                path = self.path.rstrip("/")
                if path == "/token-fail":
                    # Always fail the exchange — to drive a gateway's
                    # exchange-failure path (e.g. the pre-1.1.1 resource-read
                    # "no Authorization header" behavior).
                    self._json(400, {"error": "invalid_grant",
                                     "error_description": "exchange refused (test)"})
                    return
                if path != "/token":
                    self._json(404, {"error": "not_found"})
                    return
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length).decode()
                params = {k: v[0] for k, v in parse_qs(raw).items()}
                try:
                    self._json(200, as_.token(params, self.headers.get("Authorization")))
                except ClientAuthError as exc:
                    self._json(401, {"error": "invalid_client", "detail": str(exc)})
                except Exception as exc:
                    self._json(400, {"error": "invalid_request", "detail": str(exc)})

        return ThreadingHTTPServer((host, port), Handler)


def _selftest() -> None:
    as_ = LocalAS()
    target = "https://upstream.test/api"
    alice = as_.issue_user_token("alice-uuid", scope="read:notes write:notes")
    actor = as_.issue_client_token("gateway-client")

    # Delegation: actor_token present -> act claim carries the acting client.
    deleg = as_.token_exchange({
        "grant_type": TOKEN_EXCHANGE_GRANT,
        "subject_token": alice, "subject_token_type": JWT_TOKEN_TYPE,
        "actor_token": actor, "actor_token_type": JWT_TOKEN_TYPE,
        "audience": target, "scope": "read:notes",
    })
    d = as_.validate(deleg["access_token"], audience=target)
    assert d["sub"] == "alice-uuid", d
    assert d["act"]["sub"] == "gateway-client", d
    assert d["aud"] == target and d["scope"] == "read:notes", d

    # Impersonation: no actor_token -> no act claim.
    imp = as_.token_exchange({
        "grant_type": TOKEN_EXCHANGE_GRANT,
        "subject_token": alice, "subject_token_type": JWT_TOKEN_TYPE,
        "audience": target, "scope": "read:notes",
    })
    i = as_.validate(imp["access_token"], audience=target)
    assert "act" not in i, i
    assert i["sub"] == "alice-uuid", i

    # JWKS round-trip: validate using only the published public JWKS.
    jwks = as_.jwks()
    key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwks["keys"][0]))
    claims = jwt.decode(deleg["access_token"], key, algorithms=["RS256"],
                        audience=target, issuer=as_.issuer)
    assert claims["act"]["sub"] == "gateway-client"

    # Scope cap: an over-asking request never gets more than the subject has;
    # no request -> the subject's own scope.
    over = as_.token_exchange({"grant_type": TOKEN_EXCHANGE_GRANT, "subject_token": alice,
                               "audience": target, "scope": "read:notes admin"})
    assert over["scope"] == "read:notes", over["scope"]
    none = as_.token_exchange({"grant_type": TOKEN_EXCHANGE_GRANT, "subject_token": alice,
                               "audience": target})
    assert none["scope"] == "read:notes write:notes", none["scope"]
    try:
        as_.token_exchange({"grant_type": TOKEN_EXCHANGE_GRANT, "subject_token": alice,
                            "audience": target, "scope": "admin"})
        raise AssertionError("no-overlap scope request was granted")
    except ValueError as exc:
        assert "invalid_scope" in str(exc)
    rec = as_.exchange_for(token_fingerprint(over["access_token"]))
    assert rec["requested_scope"] == "read:notes admin" and rec["issued_scope"] == "read:notes"
    assert all("token" not in k or k.endswith("_fp") for r in as_.exchanges for k in r)

    # Per-issuer keys: provX's token verifies under provX's key only; an
    # unregistered issuer signed with a trusted key is refused (strict).
    px = as_.issue_user_token("alice", issuer="https://provx.test")
    as_.token_exchange({"grant_type": TOKEN_EXCHANGE_GRANT, "subject_token": px,
                        "audience": target})
    assert as_.jwks("provx")["keys"][0]["kid"] != as_.jwks()["keys"][0]["kid"]
    assert as_.jwks("provx")["keys"][0]["kid"] != as_.jwks("provy")["keys"][0]["kid"]
    forged = as_.issue_user_token("alice", issuer="https://provy.test", signing_key="provx")
    unreg = as_.issue_user_token("alice", issuer="https://unregistered.test", signing_key="provx")
    for bad in (forged, unreg):
        try:
            as_.token_exchange({"grant_type": TOKEN_EXCHANGE_GRANT, "subject_token": bad,
                                "audience": target})
            raise AssertionError("subject token with the wrong issuer key accepted")
        except Exception as exc:
            assert not isinstance(exc, AssertionError), exc
    lax = LocalAS(lax_subject_issuer=True)
    unreg2 = lax.issue_user_token("alice", issuer="https://unregistered.test", signing_key="provx")
    lax.token_exchange({"grant_type": TOKEN_EXCHANGE_GRANT, "subject_token": unreg2,
                        "audience": target})

    print("local_as self-test OK: RS256 + JWKS + RFC 8693 delegation/impersonation"
          " + scope cap + per-issuer keys")


FORBIDDEN_PORTS = {8790, 4444, 4000}


def _serve_main(argv: List[str]) -> None:
    import argparse
    ap = argparse.ArgumentParser(description="serve the local test AS (loopback only)")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--key-path", default=None)
    ap.add_argument("--issuer", default="https://local-as.test")
    ap.add_argument("--lax-subject-issuer", action="store_true")
    ap.add_argument("--client", action="append", default=[], metavar="ID:SECRET",
                    help="register a client for token-exchange client auth (repeatable)")
    ap.add_argument("--client-auth", choices=CLIENT_AUTH_MODES, default="none")
    ap.add_argument("--act-from-client", action="store_true",
                    help="valid client credentials and no actor_token -> act={sub: client_id}")
    a = ap.parse_args(argv)
    if a.port in FORBIDDEN_PORTS:
        raise SystemExit(f"ERROR: refusing reserved port {a.port}")
    clients = {}
    for spec in a.client:
        cid, sep, sec = spec.partition(":")
        if not sep or not cid or not sec:
            raise SystemExit(f"ERROR: --client wants ID:SECRET, got {cid!r}:...")
        clients[cid] = sec
    as_ = LocalAS(issuer=a.issuer, key_path=a.key_path, lax_subject_issuer=a.lax_subject_issuer,
                  clients=clients, client_auth=a.client_auth, act_from_client=a.act_from_client)
    srv = as_.serve(port=a.port)
    print(f"local_as on 127.0.0.1:{a.port} lax_subject_issuer={a.lax_subject_issuer} "
          f"client_auth={a.client_auth} act_from_client={a.act_from_client} "
          f"clients={sorted(clients)}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    import sys as _sys
    if len(_sys.argv) > 1 and _sys.argv[1] == "serve":
        _serve_main(_sys.argv[2:])
    else:
        _selftest()
