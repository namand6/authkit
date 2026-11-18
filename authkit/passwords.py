"""Password hashing with scrypt (memory-hard, in the standard library) and a sane policy."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

# Cost parameters. Stored in each hash, so they can be raised later without breaking old hashes.
N, R, P, DKLEN = 2 ** 14, 8, 1, 32

COMMON = {"password", "password1", "password123", "123456789012", "qwertyuiop12", "iloveyou1234", "letmein12345",
          "welcome12345", "adminadmin12", "passwordpassword"}


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def hash_password(password: str, n: int = N, r: int = R, p: int = P) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, dklen=DKLEN, maxmem=64 * 1024 * 1024)
    return f"scrypt${n}${r}${p}${_b64(salt)}${_b64(dk)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt, dk = stored.split("$")
        if algo != "scrypt":
            return False
        want = base64.b64decode(dk)
        got = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p),
                             dklen=len(want), maxmem=64 * 1024 * 1024)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(got, want)   # constant time


def needs_rehash(stored: str) -> bool:
    try:
        _, n, r, p, *_ = stored.split("$")
        return (int(n), int(r), int(p)) != (N, R, P)
    except ValueError:
        return True


# A real hash of a random password, verified against when the email doesn't exist, so a login for an
# unknown account takes as long as one for a real account (no user enumeration by timing).
DUMMY_HASH = hash_password(secrets.token_urlsafe(16))


def policy_problems(password: str, email: str = "") -> list[str]:
    out = []
    if len(password) < 12:
        out.append("use at least 12 characters")
    if len(password) > 256:
        out.append("use at most 256 characters")
    if password.lower() in COMMON:
        out.append("that password is too common")
    local = email.split("@")[0].lower()
    if local and len(local) >= 4 and local in password.lower():
        out.append("don't include your email name in the password")
    return out
