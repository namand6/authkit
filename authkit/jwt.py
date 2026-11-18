"""JSON Web Tokens (HS256) from scratch, with the checks libraries get wrong when misconfigured.

- The algorithm is fixed by the server, never taken from the token: `alg: none` and algorithm
  confusion attacks fail.
- Keys have ids (`kid`), so keys rotate without logging everyone out: sign with the newest,
  verify with any key still in the keyring.
- `exp`, `nbf`, `iat`, `iss` and `aud` are all checked, with a small clock-skew leeway.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time


class TokenError(Exception):
    pass


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    if not isinstance(s, str) or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in s):
        raise TokenError("malformed token")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _json(obj) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()


class Keyring:
    def __init__(self, keys: dict[str, bytes], current: str):
        if current not in keys:
            raise ValueError("current key id must be in keys")
        if any(len(k) < 32 for k in keys.values()):
            raise ValueError("HS256 keys must be at least 32 bytes")
        self.keys, self.current = dict(keys), current


def encode(claims: dict, ring: Keyring) -> str:
    header = {"alg": "HS256", "typ": "JWT", "kid": ring.current}
    signing_input = f"{b64url(_json(header))}.{b64url(_json(claims))}"
    sig = hmac.new(ring.keys[ring.current], signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{b64url(sig)}"


def decode(token: str, ring: Keyring, issuer: str, audience: str, leeway: int = 30, now: float | None = None) -> dict:
    parts = token.split(".") if isinstance(token, str) else []
    if len(parts) != 3:
        raise TokenError("malformed token")
    try:
        header = json.loads(b64url_decode(parts[0]))
        claims = json.loads(b64url_decode(parts[1]))
    except (ValueError, UnicodeDecodeError) as e:
        raise TokenError("malformed token") from e
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise TokenError("malformed token")
    if header.get("alg") != "HS256":                       # never trust the token's choice of algorithm
        raise TokenError("unsupported algorithm")
    key = ring.keys.get(header.get("kid"))
    if key is None:
        raise TokenError("unknown key")
    want = hmac.new(key, f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(want, b64url_decode(parts[2])):
        raise TokenError("bad signature")
    now = time.time() if now is None else now
    for claim in ("exp", "iat"):
        if not isinstance(claims.get(claim), (int, float)):
            raise TokenError(f"missing {claim}")
    if now > claims["exp"] + leeway:
        raise TokenError("token expired")
    if "nbf" in claims and now + leeway < claims["nbf"]:
        raise TokenError("token not yet valid")
    if claims["iat"] > now + leeway:
        raise TokenError("issued in the future")
    if claims.get("iss") != issuer:
        raise TokenError("wrong issuer")
    aud = claims.get("aud")
    if audience not in (aud if isinstance(aud, list) else [aud]):
        raise TokenError("wrong audience")
    return claims
