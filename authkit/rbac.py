"""Roles → permissions, with inheritance. Checks are on permissions, never on role names, so adding
a role never means hunting for `if role == "admin"` across the codebase."""

from __future__ import annotations

ROLES: dict[str, dict] = {
    "viewer": {"inherits": [], "perms": {"profile:read", "docs:read"}},
    "editor": {"inherits": ["viewer"], "perms": {"docs:write"}},
    "admin": {"inherits": ["editor"], "perms": {"users:read", "users:manage", "docs:delete"}},
}


def permissions(roles: list[str], table: dict = ROLES) -> set[str]:
    out, seen, stack = set(), set(), list(roles)
    while stack:
        r = stack.pop()
        if r in seen or r not in table:
            continue
        seen.add(r)
        out |= table[r]["perms"]
        stack += table[r]["inherits"]
    return out


def can(roles: list[str], perm: str) -> bool:
    return perm in permissions(roles)
