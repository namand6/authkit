# authkit

Authentication and authorization from scratch, standard library only: password hashing, JWTs,
refresh-token rotation with theft detection, role-based access control, and an OAuth 2.0
authorization server (authorization code + PKCE). The test suite is written as a list of attacks.

## What it defends against

| Attack | Defense | Test |
|---|---|---|
| Cracking a leaked password database | scrypt (memory-hard), per-user salt, cost stored per hash, rehash on login when cost rises | `test_password_*`, `test_needs_rehash*` |
| `alg: none` / algorithm confusion | server fixes HS256; the token's `alg` is never trusted | `test_jwt_rejects_alg_none_and_alg_swap` |
| Forged or edited tokens | HMAC-SHA256 with constant-time compare | `test_jwt_rejects_tampering_and_wrong_key` |
| Old, early, foreign tokens | `exp`, `nbf`, `iat`, `iss`, `aud` all enforced with small leeway | `test_jwt_claims_checked` |
| Key compromise | key ids (`kid`): rotate the signing key without logging everyone out, then retire the old one | `test_jwt_key_rotation` |
| Stolen refresh token | single-use rotation; replaying a used token revokes the whole session family | `test_refresh_rotation_and_reuse_detection` |
| Race between two refreshes | the "used" flag flips in one atomic SQL update, so it holds across app servers | `test_concurrent_refresh_only_one_wins` |
| Account enumeration | same error for unknown email and wrong password, and equal hashing work for both | `test_unknown_email_and_wrong_password_look_the_same` |
| Password guessing | lockout with exponential backoff (5 fails → 1 min, doubling to 1 h) | `test_lockout_with_backoff` |
| Lost device | "log out everywhere" bumps a token version, killing access tokens immediately, no blacklist | `test_logout_and_logout_everywhere` |
| Stale privileges | permissions checked against current roles, not the token's copy | `test_role_change_applies_immediately` |
| OAuth code interception | PKCE S256 required; codes are single-use, 60 s, bound to client and exact redirect URI | `test_oauth_*` |
| OAuth code replay | replaying a code revokes the tokens it already produced | `test_oauth_code_single_use_and_replay_revokes` |
| Open redirect | redirect URIs must exactly match a registered one | `test_oauth_rejects_bad_requests` |

## Design

- **Access token:** HS256 JWT, 15 minutes, carries `sub`, `roles`, `ver` (token version), `jti`.
- **Refresh token:** 32 random bytes, stored only as a SHA-256 hash, 14 days, one family per login.
- **RBAC:** roles map to permissions with inheritance (`admin ⊇ editor ⊇ viewer`); code checks
  permissions (`users:read`), never role names.
- **Storage:** SQLite with WAL and one connection per thread.

## Run it

```bash
python3.12 -m venv .venv && .venv/bin/pip install pytest
.venv/bin/python -m pytest -q                       # 28 tests
AUTHKIT_SECRET=$(openssl rand -hex 32) .venv/bin/python -m authkit.server   # http://127.0.0.1:8797
curl -s localhost:8797/signup -d '{"email":"a@b.co","password":"correct horse battery"}'
curl -s localhost:8797/login  -d '{"email":"a@b.co","password":"correct horse battery"}'
```

Production notes: put it behind TLS, keep the signing key in a secrets manager, send the refresh token
as an `HttpOnly; Secure; SameSite=Strict` cookie for browser clients, and add per-IP rate limiting on
`/login` (see the companion `ratelimit` project).
