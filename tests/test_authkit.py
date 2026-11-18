import json
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import parse_qs, urlencode, urlparse

import pytest

from authkit import jwt, passwords, rbac
from authkit.service import ACCESS_TTL, Auth, AuthError, pkce_pair

KEY = b"k" * 32
PW = "correct horse battery staple"


class Clock:
    def __init__(self):
        self.t = 1_800_000_000.0

    def __call__(self):
        return self.t


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def auth(tmp_path, clock):
    a = Auth(str(tmp_path / "a.db"), jwt.Keyring({"k1": KEY}, "k1"), clock=clock)
    a.signup("ana@example.com", PW)
    a.signup("root@example.com", PW, ["admin"])
    return a


# ---------- passwords
def test_password_hash_roundtrip_and_salt():
    h1, h2 = passwords.hash_password("x" * 12), passwords.hash_password("x" * 12)
    assert h1 != h2 and passwords.verify_password("x" * 12, h1) and not passwords.verify_password("y" * 12, h1)
    assert not passwords.verify_password("x", "garbage") and not passwords.verify_password("x", "md5$1$2$3$4$5")


def test_needs_rehash_when_cost_changes():
    assert passwords.needs_rehash(passwords.hash_password("p" * 12, n=2 ** 12))
    assert not passwords.needs_rehash(passwords.hash_password("p" * 12))


def test_policy():
    assert passwords.policy_problems("short") == ["use at least 12 characters"]
    assert passwords.policy_problems("passwordpassword") == ["that password is too common"]
    assert passwords.policy_problems("ana.smith-rocks-2026", "ana.smith@x.com") == ["don't include your email name in the password"]


# ---------- JWT attacks
def ring():
    return jwt.Keyring({"k1": KEY}, "k1")


def claims(**kw):
    now = int(time.time())
    return {"sub": "1", "iss": "authkit", "aud": "api", "iat": now, "exp": now + 60, **kw}


def test_jwt_roundtrip():
    assert jwt.decode(jwt.encode(claims(), ring()), ring(), "authkit", "api")["sub"] == "1"


def test_jwt_rejects_alg_none_and_alg_swap():
    t = jwt.encode(claims(), ring())
    h, p, _ = t.split(".")
    none_header = jwt.b64url(json.dumps({"alg": "none", "typ": "JWT", "kid": "k1"}).encode())
    with pytest.raises(jwt.TokenError, match="unsupported algorithm"):
        jwt.decode(f"{none_header}.{p}.", ring(), "authkit", "api")
    rs = jwt.b64url(json.dumps({"alg": "RS256", "kid": "k1"}).encode())
    with pytest.raises(jwt.TokenError, match="unsupported algorithm"):
        jwt.decode(f"{rs}.{p}.{t.split('.')[2]}", ring(), "authkit", "api")


def test_jwt_rejects_tampering_and_wrong_key():
    t = jwt.encode(claims(), ring())
    h, p, s = t.split(".")
    evil = jwt.b64url(json.dumps(claims(sub="2")).encode())
    with pytest.raises(jwt.TokenError, match="bad signature"):
        jwt.decode(f"{h}.{evil}.{s}", ring(), "authkit", "api")
    other = jwt.Keyring({"k1": b"z" * 32}, "k1")
    with pytest.raises(jwt.TokenError, match="bad signature"):
        jwt.decode(t, other, "authkit", "api")


@pytest.mark.parametrize("kw,err", [({"exp": 1}, "expired"), ({"iss": "evil"}, "issuer"), ({"aud": "other"}, "audience"),
                                    ({"nbf": int(time.time()) + 999}, "not yet"), ({"iat": int(time.time()) + 999}, "future")])
def test_jwt_claims_checked(kw, err):
    with pytest.raises(jwt.TokenError, match=err):
        jwt.decode(jwt.encode(claims(**kw), ring()), ring(), "authkit", "api")


def test_jwt_key_rotation():
    old = jwt.encode(claims(), jwt.Keyring({"k1": KEY}, "k1"))
    rotated = jwt.Keyring({"k1": KEY, "k2": b"n" * 32}, "k2")
    assert jwt.decode(old, rotated, "authkit", "api")                      # old tokens still verify
    assert json.loads(jwt.b64url_decode(jwt.encode(claims(), rotated).split(".")[0]))["kid"] == "k2"
    with pytest.raises(jwt.TokenError, match="unknown key"):
        jwt.decode(old, jwt.Keyring({"k2": b"n" * 32}, "k2"), "authkit", "api")   # k1 retired
    with pytest.raises(ValueError):
        jwt.Keyring({"k": b"short"}, "k")


def test_jwt_malformed():
    for bad in ("", "a.b", "a.b.c.d", "!!.@@.##", None):
        with pytest.raises(jwt.TokenError):
            jwt.decode(bad, ring(), "authkit", "api")


# ---------- RBAC
def test_rbac_inheritance():
    assert rbac.can(["admin"], "docs:read") and rbac.can(["editor"], "docs:write")
    assert not rbac.can(["viewer"], "docs:write") and not rbac.can(["nope"], "docs:read")


# ---------- sessions
def test_signup_rules(auth):
    with pytest.raises(AuthError, match="12 characters"):
        auth.signup("b@example.com", "short")
    with pytest.raises(AuthError, match="could not create"):
        auth.signup("ANA@example.com", PW)        # duplicate, case-insensitive, vague message


def test_login_and_verify(auth):
    t = auth.login("ana@example.com", PW)
    c = auth.verify(t["access_token"], "profile:read")
    assert c["roles"] == ["viewer"] and c["exp"] - c["iat"] == ACCESS_TTL
    with pytest.raises(AuthError) as e:
        auth.verify(t["access_token"], "users:read")
    assert e.value.status == 403


def test_unknown_email_and_wrong_password_look_the_same(auth):
    msgs = []
    for email in ("ana@example.com", "ghost@example.com"):
        with pytest.raises(AuthError) as e:
            auth.login(email, "wrong password!!")
        msgs.append(str(e.value))
    assert msgs[0] == msgs[1]


def test_lockout_with_backoff(auth, clock):
    for _ in range(5):
        with pytest.raises(AuthError):
            auth.login("ana@example.com", "wrong password!!")
    with pytest.raises(AuthError) as e:
        auth.login("ana@example.com", PW)            # even the right password is refused while locked
    assert e.value.status == 429
    clock.t += 61
    assert auth.login("ana@example.com", PW)["access_token"]


def test_access_token_expires(auth, clock):
    t = auth.login("ana@example.com", PW)
    clock.t += ACCESS_TTL + 31
    with pytest.raises(AuthError, match="expired"):
        auth.verify(t["access_token"])


def test_refresh_rotation_and_reuse_detection(auth):
    t1 = auth.login("ana@example.com", PW)
    t2 = auth.refresh(t1["refresh_token"])
    assert t2["refresh_token"] != t1["refresh_token"]
    with pytest.raises(AuthError, match="reuse detected"):
        auth.refresh(t1["refresh_token"])            # attacker replays the stolen old token
    with pytest.raises(AuthError):
        auth.refresh(t2["refresh_token"])            # ...so the legit newer token is dead too


def test_concurrent_refresh_only_one_wins(auth):
    rt = auth.login("ana@example.com", PW)["refresh_token"]
    results = []

    def go():
        try:
            auth.refresh(rt); results.append("ok")
        except AuthError:
            results.append("no")
    ts = [threading.Thread(target=go) for _ in range(8)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert len(results) == 8 and results.count("ok") == 1


def test_logout_and_logout_everywhere(auth):
    a = auth.login("ana@example.com", PW)
    b = auth.login("ana@example.com", PW)
    auth.logout(a["refresh_token"])
    with pytest.raises(AuthError):
        auth.refresh(a["refresh_token"])
    assert auth.refresh(b["refresh_token"])          # other device unaffected
    auth.logout_everywhere(int(auth.verify(b["access_token"])["sub"]))
    with pytest.raises(AuthError, match="revoked"):
        auth.verify(b["access_token"])               # access token dies immediately, no blacklist


def test_role_change_applies_immediately(auth):
    t = auth.login("ana@example.com", PW)
    uid = int(auth.verify(t["access_token"])["sub"])
    auth.set_roles(uid, ["admin"])
    assert auth.verify(t["access_token"], "users:read")
    auth.set_roles(uid, ["viewer"])
    with pytest.raises(AuthError):
        auth.verify(t["access_token"], "users:read")


# ---------- OAuth + PKCE
@pytest.fixture
def oauth(auth):
    auth.register_client("notes-app", "Notes", ["https://notes.example/cb"], ["profile", "docs"])
    uid = int(auth.verify(auth.login("ana@example.com", PW)["access_token"])["sub"])
    return auth, uid


def code_from(url):
    return parse_qs(urlparse(url).query)["code"][0]


def test_oauth_code_flow(oauth):
    auth, uid = oauth
    verifier, challenge = pkce_pair()
    url = auth.authorize(uid, "notes-app", "https://notes.example/cb", challenge, scope="profile", state="xyz")
    assert parse_qs(urlparse(url).query)["state"] == ["xyz"]
    tok = auth.exchange_code(code_from(url), "notes-app", "https://notes.example/cb", verifier)
    c = auth.verify(tok["access_token"])
    assert c["cid"] == "notes-app" and c["scope"] == "profile"


def test_oauth_rejects_bad_requests(oauth):
    auth, uid = oauth
    verifier, challenge = pkce_pair()
    with pytest.raises(AuthError, match="redirect_uri"):
        auth.authorize(uid, "notes-app", "https://evil.example/cb", challenge)
    with pytest.raises(AuthError, match="PKCE"):
        auth.authorize(uid, "notes-app", "https://notes.example/cb", challenge, method="plain")
    with pytest.raises(AuthError, match="scope"):
        auth.authorize(uid, "notes-app", "https://notes.example/cb", challenge, scope="admin")
    url = auth.authorize(uid, "notes-app", "https://notes.example/cb", challenge)
    with pytest.raises(AuthError):
        auth.exchange_code(code_from(url), "notes-app", "https://notes.example/cb", "wrong-verifier" * 4)


def test_oauth_code_single_use_and_replay_revokes(oauth):
    auth, uid = oauth
    verifier, challenge = pkce_pair()
    code = code_from(auth.authorize(uid, "notes-app", "https://notes.example/cb", challenge))
    tok = auth.exchange_code(code, "notes-app", "https://notes.example/cb", verifier)
    with pytest.raises(AuthError):
        auth.exchange_code(code, "notes-app", "https://notes.example/cb", verifier)
    with pytest.raises(AuthError):
        auth.refresh(tok["refresh_token"])           # tokens from the replayed code were revoked


def test_oauth_code_expires(oauth, clock):
    auth, uid = oauth
    verifier, challenge = pkce_pair()
    code = code_from(auth.authorize(uid, "notes-app", "https://notes.example/cb", challenge))
    clock.t += 61
    with pytest.raises(AuthError):
        auth.exchange_code(code, "notes-app", "https://notes.example/cb", verifier)


# ---------- HTTP API end to end
def test_http_api(tmp_path):
    from http.server import ThreadingHTTPServer
    from authkit.server import make_handler
    a = Auth(str(tmp_path / "h.db"), jwt.Keyring({"k1": KEY}, "k1"))
    srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(a))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"

    def req(method, path, body=None, token=None):
        r = urllib.request.Request(base + path, data=json.dumps(body).encode() if body is not None else None, method=method,
                                   headers={"Content-Type": "application/json", **({"Authorization": f"Bearer {token}"} if token else {})})
        try:
            with urllib.request.urlopen(r) as resp:
                return resp.status, json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")
    try:
        assert req("POST", "/signup", {"email": "z@example.com", "password": PW})[0] == 201
        s, t = req("POST", "/login", {"email": "z@example.com", "password": PW})
        assert s == 200
        assert req("GET", "/me", token=t["access_token"])[1]["email"] == "z@example.com"
        assert req("GET", "/admin/users", token=t["access_token"])[0] == 403
        assert req("GET", "/me")[0] == 401
        s, t2 = req("POST", "/refresh", {"refresh_token": t["refresh_token"]})
        assert s == 200 and req("POST", "/refresh", {"refresh_token": t["refresh_token"]})[0] == 401
    finally:
        srv.shutdown()
