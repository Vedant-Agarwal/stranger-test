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

Needs pyjwt[crypto]. Run ``python integration/local_as.py`` for a self-test.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"


def _b64url_uint(n: int) -> str:
    import base64

    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


class LocalAS:
    """A real RS256 authorization server with an RFC 8693 token endpoint."""

    def __init__(self, issuer: str = "https://local-as.test", ttl: int = 3600,
                 key_path: Optional[str] = None):
        self.issuer = issuer
        self.ttl = ttl
        # Persist the key when a path is given, so restarts keep the same key
        # (and a gateway's cached JWKS stays valid).
        import os
        if key_path and os.path.exists(key_path):
            with open(key_path, "rb") as fh:
                self._key = serialization.load_pem_private_key(fh.read(), password=None)
        else:
            self._key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self._private_pem = self._key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        if key_path and not os.path.exists(key_path):
            with open(key_path, "wb") as fh:
                fh.write(self._private_pem)
        self._public = self._key.public_key()
        # Deterministic kid from the public key, so it is stable across restarts.
        nums = self._public.public_numbers()
        self.kid = hashlib.sha256(_b64url_uint(nums.n).encode()).hexdigest()[:16]

    # -- key material ----------------------------------------------------

    def jwks(self) -> Dict[str, Any]:
        nums = self._public.public_numbers()
        return {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "kid": self.kid,
                    "n": _b64url_uint(nums.n),
                    "e": _b64url_uint(nums.e),
                }
            ]
        }

    def _sign(self, claims: Dict[str, Any], issuer: Optional[str] = None) -> str:
        now = int(time.time())
        # jti makes every minted token unique, so distinct exchanges produce
        # distinct tokens (lets the probe tell a per-principal exchange from a
        # cache that conflated two callers).
        payload = {"iss": issuer or self.issuer, "iat": now, "exp": now + self.ttl,
                   "jti": uuid.uuid4().hex, **claims}
        return jwt.encode(payload, self._private_pem, algorithm="RS256",
                          headers={"kid": self.kid})

    def validate(self, token: str, *, audience: Optional[str] = None,
                 verify_issuer: bool = True) -> Dict[str, Any]:
        """Verify a token this AS signed and return its claims (raises on failure).

        ``verify_issuer=False`` accepts any issuer we signed (used for exchange
        subject tokens, which may carry a provider issuer like provX/provY)."""
        options = {"verify_aud": audience is not None, "verify_iss": verify_issuer}
        return jwt.decode(
            token,
            self._public,
            algorithms=["RS256"],
            audience=audience,
            issuer=self.issuer if verify_issuer else None,
            options=options,
        )

    # -- issuing ---------------------------------------------------------

    def issue_user_token(self, sub: str, *, scope: str = "read:notes",
                         audience: Optional[str] = None,
                         email: Optional[str] = None,
                         issuer: Optional[str] = None) -> str:
        """A user's access token — the subject_token a deputy would exchange.

        Carries an ``email`` claim: gateways (e.g. ContextForge) provision the
        external user from it and reject a token without one. ``issuer`` lets a
        caller mint under a specific provider issuer (for the two-issuer test).
        """
        claims: Dict[str, Any] = {"sub": sub, "scope": scope,
                                  "aud": audience or self.issuer,
                                  "email": email or f"{sub}@local-as.test"}
        return self._sign(claims, issuer=issuer)

    def issue_client_token(self, client_id: str) -> str:
        """A client-credentials token identifying the acting gateway (actor_token)."""
        return self._sign({"sub": client_id, "scope": "act"})

    def client_credentials(self, params: Dict[str, str]) -> Dict[str, Any]:
        """Issue a client-credentials token (the gateway's actor token in delegation)."""
        client_id = params.get("client_id") or "client"
        token = self.issue_client_token(client_id)
        return {"access_token": token, "token_type": "Bearer", "expires_in": self.ttl,
                "issued_token_type": ACCESS_TOKEN_TYPE}

    def token(self, params: Dict[str, str]) -> Dict[str, Any]:
        """Dispatch the /token endpoint by grant_type."""
        grant = params.get("grant_type")
        if grant == "client_credentials":
            return self.client_credentials(params)
        return self.token_exchange(params)

    def token_exchange(self, params: Dict[str, str]) -> Dict[str, Any]:
        """Perform an RFC 8693 token exchange and return the token response dict."""
        if params.get("grant_type") != TOKEN_EXCHANGE_GRANT:
            raise ValueError("unsupported_grant_type")
        subject_token = params.get("subject_token")
        if not subject_token:
            raise ValueError("invalid_request: subject_token required")
        subject = self.validate(subject_token, verify_issuer=False)

        actor_token = params.get("actor_token")
        act: Optional[Dict[str, Any]] = None
        if actor_token:
            actor = self.validate(actor_token)
            act = {"sub": actor.get("sub")}
            # Preserve any delegation chain the subject already carried.
            if isinstance(subject.get("act"), dict):
                act["act"] = subject["act"]

        audience = params.get("audience") or self.issuer
        # Narrow the scope to what was requested, defaulting to the subject's.
        scope = params.get("scope") or subject.get("scope", "")

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

            def _json(self, code: int, body: Dict[str, Any]):
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
                elif path == "/issue":
                    # DEV ONLY: mint a user access token (the subject_token a
                    # caller presents to a gateway). Local test harness use only.
                    q = parse_qs(parsed.query)
                    sub = q.get("sub", ["alice"])[0]
                    aud = q.get("aud", [as_.issuer])[0]
                    scope = q.get("scope", ["read:notes"])[0]
                    iss = q.get("iss", [None])[0]
                    email = q.get("email", [None])[0]
                    self._json(200, {"access_token": as_.issue_user_token(
                        sub, scope=scope, audience=aud, issuer=iss, email=email)})
                elif self.path.rstrip("/") == "/.well-known/openid-configuration":
                    base = f"http://{self.headers.get('Host', host)}"
                    self._json(200, {
                        "issuer": as_.issuer,
                        "token_endpoint": f"{base}/token",
                        "jwks_uri": f"{base}/jwks",
                        "grant_types_supported": [TOKEN_EXCHANGE_GRANT],
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
                    self._json(200, as_.token(params))
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

    print("local_as self-test OK: RS256 + JWKS + RFC 8693 delegation/impersonation")


if __name__ == "__main__":
    _selftest()
