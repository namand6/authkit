"""Accounts, sessions and OAuth 2.0 (authorization code + PKCE), on SQLite.

Sessions = short-lived JWT access token (15 min) + opaque refresh token (14 days):
- Refresh tokens are random, stored only as SHA-256 hashes, and single-use. Each refresh returns a
  new one in the same "family". Presenting an already-used token means it was stolen (or replayed),
  so the whole family is revoked and both the thief and the victim must log in again.
- "Log out everywhere" bumps the user's token version; access tokens carry the version they were
  minted with and are rejected after the bump, without a token blacklist.
- Failed logins lock the account with backoff (5 fails → 1 min, doubling up to 1 hour).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import sqlite3
import threading
import time
from urllib.parse import urlencode

from . import jwt, passwords, rbac

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, pw TEXT NOT NULL,
  roles TEXT NOT NULL DEFAULT '["viewer"]', failed INTEGER NOT NULL DEFAULT 0, locked_until REAL NOT NULL DEFAULT 0,
  token_version INTEGER NOT NULL DEFAULT 0, created REAL NOT NULL);
CREATE TABLE IF NOT EXISTS refresh (hash TEXT PRIMARY KEY, family TEXT NOT NULL, user_id INTEGER NOT NULL,
  client_id TEXT, expires REAL NOT NULL, used INTEGER NOT NULL DEFAULT 0, revoked INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS clients (id TEXT PRIMARY KEY, name TEXT, redirect_uris TEXT NOT NULL, scopes TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS codes (hash TEXT PRIMARY KEY, client_id TEXT, user_id INTEGER, redirect_uri TEXT,
  challenge TEXT, scope TEXT, expires REAL, used INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS audit (at REAL, user_id INTEGER, event TEXT);
"""

ACCESS_TTL, REFRESH_TTL, CODE_TTL = 15 * 60, 14 * 86400, 60
MAX_FAILS, BASE_LOCK, MAX_LOCK = 5, 60, 3600


class AuthError(Exception):
    def __init__(self, message: str, status: int = 401):
        super().__init__(message)
        self.status = status


def _h(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class Auth:
    def __init__(self, db_path: str, ring: jwt.Keyring, issuer: str = "authkit", audience: str = "api", clock=time.time):
        self.db_path = db_path
        self._local = threading.local()          # one connection per thread; SQLite handles the locking
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(SCHEMA)
        self.ring, self.issuer, self.audience, self.clock = ring, issuer, audience, clock

    @property
    def db(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.db_path, isolation_level=None, timeout=10)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA busy_timeout=10000")
            self._local.conn = conn
        return conn

    def _audit(self, user_id, event):
        self.db.execute("INSERT INTO audit VALUES (?,?,?)", (self.clock(), user_id, event))

    # ---------- accounts
    def signup(self, email: str, password: str, roles: list[str] | None = None) -> int:
        email = email.strip().lower()
        if "@" not in email or len(email) > 254:
            raise AuthError("invalid email", 400)
        problems = passwords.policy_problems(password, email)
        if problems:
            raise AuthError("; ".join(problems), 400)
        roles = roles or ["viewer"]
        if any(r not in rbac.ROLES for r in roles):
            raise AuthError("unknown role", 400)
        try:
            cur = self.db.execute("INSERT INTO users (email, pw, roles, created) VALUES (?,?,?,?)",
                                  (email, passwords.hash_password(password), json.dumps(roles), self.clock()))
        except sqlite3.IntegrityError:
            raise AuthError("could not create account", 400) from None   # same message: no enumeration
        self._audit(cur.lastrowid, "signup")
        return cur.lastrowid

    def login(self, email: str, password: str, client_id: str | None = None) -> dict:
        email = email.strip().lower()
        row = self.db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        now = self.clock()
        if row is None:
            passwords.verify_password(password, passwords.DUMMY_HASH)   # equal work for unknown emails
            raise AuthError("wrong email or password")
        if row["locked_until"] > now:
            raise AuthError(f"too many attempts; try again in {int(row['locked_until'] - now) + 1}s", 429)
        if not passwords.verify_password(password, row["pw"]):
            fails = row["failed"] + 1
            locked = now + min(MAX_LOCK, BASE_LOCK * 2 ** (fails - MAX_FAILS)) if fails >= MAX_FAILS else 0
            self.db.execute("UPDATE users SET failed=?, locked_until=? WHERE id=?", (fails, locked, row["id"]))
            self._audit(row["id"], "login_failed")
            raise AuthError("wrong email or password")
        updates = {"failed": 0, "locked_until": 0}
        if passwords.needs_rehash(row["pw"]):
            updates["pw"] = passwords.hash_password(password)
        self.db.execute(f"UPDATE users SET {', '.join(k + '=?' for k in updates)} WHERE id=?", (*updates.values(), row["id"]))
        self._audit(row["id"], "login")
        return self._issue(row, family=secrets.token_hex(16), client_id=client_id)

    def _issue(self, row, family: str, client_id: str | None = None, scope: str = "") -> dict:
        now = int(self.clock())
        claims = {"sub": str(row["id"]), "iss": self.issuer, "aud": self.audience, "iat": now, "exp": now + ACCESS_TTL,
                  "ver": row["token_version"], "roles": json.loads(row["roles"]), "jti": secrets.token_hex(8)}
        if client_id:
            claims["cid"], claims["scope"] = client_id, scope
        refresh = secrets.token_urlsafe(32)
        self.db.execute("INSERT INTO refresh (hash, family, user_id, client_id, expires) VALUES (?,?,?,?,?)",
                        (_h(refresh), family, row["id"], client_id, now + REFRESH_TTL))
        return {"access_token": jwt.encode(claims, self.ring), "token_type": "Bearer", "expires_in": ACCESS_TTL,
                "refresh_token": refresh}

    def refresh(self, token: str) -> dict:
        rt = self.db.execute("SELECT * FROM refresh WHERE hash=?", (_h(token),)).fetchone()
        if rt is None or rt["revoked"] or rt["expires"] < self.clock():
            raise AuthError("invalid refresh token")
        # Atomic claim in the database (not a process lock), so it holds across many app servers:
        # exactly one request can flip used 0 -> 1; everyone else is a replay.
        claimed = self.db.execute("UPDATE refresh SET used=1 WHERE hash=? AND used=0 AND revoked=0", (rt["hash"],)).rowcount
        if not claimed:
            self.db.execute("UPDATE refresh SET revoked=1 WHERE family=?", (rt["family"],))
            self._audit(rt["user_id"], "refresh_reuse_detected")
            raise AuthError("refresh token reuse detected; all sessions in this family were revoked")
        row = self.db.execute("SELECT * FROM users WHERE id=?", (rt["user_id"],)).fetchone()
        return self._issue(row, rt["family"], rt["client_id"])

    def logout(self, token: str) -> None:
        rt = self.db.execute("SELECT family FROM refresh WHERE hash=?", (_h(token),)).fetchone()
        if rt:
            self.db.execute("UPDATE refresh SET revoked=1 WHERE family=?", (rt["family"],))

    def logout_everywhere(self, user_id: int) -> None:
        self.db.execute("UPDATE users SET token_version = token_version + 1 WHERE id=?", (user_id,))
        self.db.execute("UPDATE refresh SET revoked=1 WHERE user_id=?", (user_id,))
        self._audit(user_id, "logout_everywhere")

    def verify(self, access_token: str, perm: str | None = None) -> dict:
        try:
            claims = jwt.decode(access_token, self.ring, self.issuer, self.audience, now=self.clock())
        except jwt.TokenError as e:
            raise AuthError(str(e)) from None
        row = self.db.execute("SELECT token_version, roles FROM users WHERE id=?", (int(claims["sub"]),)).fetchone()
        if row is None or row["token_version"] != claims.get("ver"):
            raise AuthError("session was revoked")
        if perm and not rbac.can(json.loads(row["roles"]), perm):   # current roles, not the token's stale copy
            raise AuthError("forbidden", 403)
        return claims

    def set_roles(self, user_id: int, roles: list[str]) -> None:
        if any(r not in rbac.ROLES for r in roles):
            raise AuthError("unknown role", 400)
        self.db.execute("UPDATE users SET roles=? WHERE id=?", (json.dumps(roles), user_id))

    # ---------- OAuth 2.0 authorization server (code flow + PKCE S256)
    def register_client(self, client_id: str, name: str, redirect_uris: list[str], scopes: list[str]) -> None:
        self.db.execute("INSERT OR REPLACE INTO clients VALUES (?,?,?,?)",
                        (client_id, name, json.dumps(redirect_uris), json.dumps(scopes)))

    def authorize(self, user_id: int, client_id: str, redirect_uri: str, code_challenge: str,
                  method: str = "S256", scope: str = "", state: str = "") -> str:
        """The user is logged in and approved the client; returns the redirect URL carrying the code."""
        c = self.db.execute("SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
        if c is None:
            raise AuthError("unknown client", 400)
        if redirect_uri not in json.loads(c["redirect_uris"]):     # exact match; never redirect elsewhere
            raise AuthError("redirect_uri not registered", 400)
        if method != "S256" or not (43 <= len(code_challenge) <= 128):
            raise AuthError("PKCE with S256 is required", 400)
        allowed = set(json.loads(c["scopes"]))
        requested = set(scope.split()) if scope else set()
        if not requested <= allowed:
            raise AuthError("scope not allowed", 400)
        code = secrets.token_urlsafe(32)
        self.db.execute("INSERT INTO codes VALUES (?,?,?,?,?,?,?,0)", (_h(code), client_id, user_id, redirect_uri,
                        code_challenge, " ".join(sorted(requested)), self.clock() + CODE_TTL))
        q = {"code": code, **({"state": state} if state else {})}
        return f"{redirect_uri}{'&' if '?' in redirect_uri else '?'}{urlencode(q)}"

    def exchange_code(self, code: str, client_id: str, redirect_uri: str, code_verifier: str) -> dict:
        row = self.db.execute("SELECT * FROM codes WHERE hash=?", (_h(code),)).fetchone()
        if row is None or row["expires"] < self.clock():
            raise AuthError("invalid_grant", 400)
        if not self.db.execute("UPDATE codes SET used=1 WHERE hash=? AND used=0", (row["hash"],)).rowcount:
            # a replayed code: revoke anything it already produced
            self.db.execute("UPDATE refresh SET revoked=1 WHERE user_id=? AND client_id=?", (row["user_id"], client_id))
            raise AuthError("invalid_grant", 400)
        if row["client_id"] != client_id or row["redirect_uri"] != redirect_uri:
            raise AuthError("invalid_grant", 400)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).rstrip(b"=").decode()
        if not hmac.compare_digest(challenge, row["challenge"]):
            raise AuthError("invalid_grant", 400)
        user = self.db.execute("SELECT * FROM users WHERE id=?", (row["user_id"],)).fetchone()
        return self._issue(user, secrets.token_hex(16), client_id, row["scope"])


def pkce_pair() -> tuple[str, str]:
    """(verifier, S256 challenge), as a client would make them."""
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge
