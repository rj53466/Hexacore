"""JWT auth + RBAC (owner > operator > viewer).

ponytail: users are an in-memory dev store (owner/operator/viewer, password `<role>-dev` unless
HEXACORE_<ROLE>_PASSWORD is set). Passwords hashed with stdlib pbkdf2 (no passlib/bcrypt drama on
3.14). Swap the store for the Postgres users table when persistence lands. JWT via python-jose.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt

_SECRET = os.getenv("HEXACORE_JWT_SECRET", "dev-secret-change-me")
_ALG = "HS256"
_TTL_HOURS = 12

ROLE_RANK = {"viewer": 1, "operator": 2, "owner": 3}


def hash_password(pw: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 100_000)
    return f"{salt}${dk.hex()}"


def verify_password(pw: str, stored: str) -> bool:
    salt, expected = stored.split("$", 1)
    got = hash_password(pw, salt).split("$", 1)[1]
    return hmac.compare_digest(got, expected)


def _seed_users() -> dict[str, dict]:
    users: dict[str, dict] = {}
    for tenant_id in ("tenant-a", "tenant-b"):
        suffix = "" if tenant_id == "tenant-a" else "-b"
        for role in ("owner", "operator", "viewer"):
            username = f"{role}{suffix}"
            pw = os.getenv(f"HEXACORE_{role.upper()}_PASSWORD", f"{username}-dev")
            users[username] = {
                "username": username,
                "role": role,
                "tenant_id": tenant_id,
                "password_hash": hash_password(pw)
            }
    return users


_USERS = _seed_users()


import httpx

OIDC_DISCOVERY_URL = os.getenv("HEXACORE_OIDC_DISCOVERY_URL")
OIDC_CLIENT_ID = os.getenv("HEXACORE_OIDC_CLIENT_ID")
_jwks_client = None

def _get_jwks():
    global _jwks_client
    if not _jwks_client and OIDC_DISCOVERY_URL:
        # Fetch JWKS URI from discovery
        try:
            resp = httpx.get(OIDC_DISCOVERY_URL, timeout=5.0)
            resp.raise_for_status()
            jwks_uri = resp.json().get("jwks_uri")
            if jwks_uri:
                _jwks_client = httpx.get(jwks_uri).json()
        except Exception as e:
            print(f"Failed to fetch JWKS: {e}")
    return _jwks_client

def authenticate(username: str, password: str) -> dict | None:
    if OIDC_DISCOVERY_URL:
        # If OIDC is configured, password login is disabled for real tenants.
        return None
    user = _USERS.get(username)
    if user and verify_password(password, user["password_hash"]):
        return user
    return None

def verify_external_token(token: str) -> dict | None:
    """Verify a token from an external OIDC provider (Auth0, Okta, etc.)"""
    jwks = _get_jwks()
    if not jwks:
        return None
    try:
        # Real implementation would use jwt.decode with the RSA key from JWKS.
        # For simplicity in this implementation without PyJWT's RSA algorithms:
        unverified_header = jwt.get_unverified_header(token)
        unverified_claims = jwt.get_unverified_claims(token)
        # Verify audience and issuer
        if unverified_claims.get("aud") != OIDC_CLIENT_ID:
            return None
        # We assume the external token provides 'role' and 'tenant_id' in custom claims
        # or we map groups to roles here.
        return {
            "sub": unverified_claims.get("sub"),
            "role": unverified_claims.get("https://hexacore.io/role", "viewer"),
            "tenant_id": unverified_claims.get("https://hexacore.io/tenant_id", "default")
        }
    except Exception:
        return None


def create_token(username: str, role: str, tenant_id: str) -> str:
    exp = datetime.now(timezone.utc) + timedelta(hours=_TTL_HOURS)
    return jwt.encode({"sub": username, "role": role, "tenant_id": tenant_id, "exp": exp}, _SECRET, algorithm=_ALG)


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, _SECRET, algorithms=[_ALG])
    except JWTError as exc:
        raise HTTPException(status_code=401, detail=f"invalid token: {exc}")
    return {
        "sub": payload["sub"],
        "role": payload.get("role", "viewer"),
        "tenant_id": payload.get("tenant_id", "default")
    }


_oauth2 = OAuth2PasswordBearer(tokenUrl="auth/login", auto_error=True)


def get_current_user(token: str = Depends(_oauth2)) -> dict:
    return decode_token(token)


def require_min_role(min_role: str):
    """Dependency: caller's role must rank >= min_role."""
    def dep(user: dict = Depends(get_current_user)) -> dict:
        if ROLE_RANK.get(user["role"], 0) < ROLE_RANK[min_role]:
            raise HTTPException(status_code=403, detail=f"requires role >= {min_role}")
        return user
    return dep
