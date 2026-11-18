"""A small JSON API over the auth service (stdlib only), to show it end to end.

  POST /signup {email, password}            POST /login {email, password}
  POST /refresh {refresh_token}             POST /logout {refresh_token}
  POST /logout-all            (Bearer)      GET  /me                 (Bearer, profile:read)
  GET  /admin/users           (Bearer, users:read)
  GET  /oauth/authorize?client_id&redirect_uri&code_challenge&code_challenge_method=S256&scope&state  (Bearer)
  POST /oauth/token {grant_type: authorization_code|refresh_token, ...}
"""

from __future__ import annotations

import json
import os
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import jwt
from .service import Auth, AuthError


def make_handler(auth: Auth):
    class H(BaseHTTPRequestHandler):
        server_version = "authkit"

        def log_message(self, *a):
            pass

        def _send(self, code: int, obj=None, headers: dict | None = None):
            body = json.dumps(obj if obj is not None else {}).encode()
            self.send_response(code)
            for k, v in {"Content-Type": "application/json", "Cache-Control": "no-store", **(headers or {})}.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _body(self) -> dict:
            raw = self.rfile.read(min(int(self.headers.get("Content-Length") or 0), 16384))
            if self.headers.get("Content-Type", "").startswith("application/x-www-form-urlencoded"):
                return {k: v[0] for k, v in parse_qs(raw.decode()).items()}
            return json.loads(raw or b"{}")

        def _bearer(self, perm: str | None = None) -> dict:
            h = self.headers.get("Authorization", "")
            if not h.startswith("Bearer "):
                raise AuthError("missing bearer token")
            return auth.verify(h[7:], perm)

        def _run(self, fn):
            try:
                fn()
            except AuthError as e:
                hdr = {"WWW-Authenticate": 'Bearer error="invalid_token"'} if e.status == 401 else None
                self._send(e.status, {"error": str(e)}, hdr)
            except (ValueError, KeyError, TypeError):
                self._send(400, {"error": "bad request"})

        def do_GET(self):
            url = urlparse(self.path)

            def go():
                if url.path == "/me":
                    c = self._bearer("profile:read")
                    row = auth.db.execute("SELECT id, email, roles FROM users WHERE id=?", (int(c["sub"]),)).fetchone()
                    return self._send(200, {"id": row["id"], "email": row["email"], "roles": json.loads(row["roles"])})
                if url.path == "/admin/users":
                    self._bearer("users:read")
                    rows = auth.db.execute("SELECT id, email, roles FROM users ORDER BY id").fetchall()
                    return self._send(200, [{"id": r["id"], "email": r["email"], "roles": json.loads(r["roles"])} for r in rows])
                if url.path == "/oauth/authorize":
                    c = self._bearer()
                    q = {k: v[0] for k, v in parse_qs(url.query).items()}
                    loc = auth.authorize(int(c["sub"]), q["client_id"], q["redirect_uri"], q["code_challenge"],
                                         q.get("code_challenge_method", ""), q.get("scope", ""), q.get("state", ""))
                    return self._send(302, {}, {"Location": loc})
                self._send(404, {"error": "not found"})
            self._run(go)

        def do_POST(self):
            path = urlparse(self.path).path

            def go():
                b = self._body()
                if path == "/signup":
                    return self._send(201, {"id": auth.signup(b["email"], b["password"])})
                if path == "/login":
                    return self._send(200, auth.login(b["email"], b["password"]))
                if path == "/refresh":
                    return self._send(200, auth.refresh(b["refresh_token"]))
                if path == "/logout":
                    auth.logout(b["refresh_token"])
                    return self._send(204)
                if path == "/logout-all":
                    auth.logout_everywhere(int(self._bearer()["sub"]))
                    return self._send(204)
                if path == "/oauth/token":
                    if b.get("grant_type") == "authorization_code":
                        return self._send(200, auth.exchange_code(b["code"], b["client_id"], b["redirect_uri"], b["code_verifier"]))
                    if b.get("grant_type") == "refresh_token":
                        return self._send(200, auth.refresh(b["refresh_token"]))
                    return self._send(400, {"error": "unsupported_grant_type"})
                self._send(404, {"error": "not found"})
            self._run(go)
    return H


def main(port: int = 8797, db: str = "authkit.db"):
    secret = os.environ.get("AUTHKIT_SECRET", "").encode() or secrets.token_bytes(32)
    auth = Auth(db, jwt.Keyring({"k1": secret}, "k1"))
    print(f"authkit on http://127.0.0.1:{port}", flush=True)
    ThreadingHTTPServer(("127.0.0.1", port), make_handler(auth)).serve_forever()


if __name__ == "__main__":
    main()
