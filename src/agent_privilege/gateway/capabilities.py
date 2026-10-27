"""Signed task-capability grants (HMAC-SHA256). Key lives only in the gateway process.

A grant is bound to principal (agent_id), tenant, accounts, destinations, tools, a per-call
amount limit, expiry and delegation depth. Verification here is the *enforcement point's*
job (signature, expiry, binding, revocation); the policy then checks the claims against the
requested action.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any

from .canonicalize import canonical_json, sha256_hex


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def sign_grant(key: bytes, claims: dict[str, Any]) -> str:
    body = canonical_json(claims).encode()
    mac = hmac.new(key, body, hashlib.sha256).digest()
    return f"{_b64(body)}.{_b64(mac)}"


def grant_hash(token: str) -> str:
    return sha256_hex(token)


def verify_grant(key: bytes, token: str | None, *, principal: str, tenant: str, now_ms: int,
                 revoked: set[str]) -> dict[str, Any]:
    """Return {'present','valid','reason','claims'}. Never raises."""
    if not token:
        return {"present": False, "valid": False, "reason": "no_grant", "claims": None}
    try:
        b, m = token.split(".")
        body, mac = _unb64(b), _unb64(m)
        good = hmac.new(key, body, hashlib.sha256).digest()
        if not hmac.compare_digest(good, mac):
            return {"present": True, "valid": False, "reason": "bad_signature", "claims": None}
        claims = json.loads(body)
    except Exception:
        return {"present": True, "valid": False, "reason": "malformed_grant", "claims": None}
    reason = None
    if claims.get("principal") != principal:
        reason = "principal_mismatch"
    elif claims.get("tenant") != tenant:
        reason = "tenant_mismatch"
    elif int(claims.get("exp_ms", 0)) < now_ms:
        reason = "grant_expired"
    elif claims.get("grant_id") in revoked:
        reason = "grant_revoked"
    return {"present": True, "valid": reason is None, "reason": reason or "ok", "claims": claims}
