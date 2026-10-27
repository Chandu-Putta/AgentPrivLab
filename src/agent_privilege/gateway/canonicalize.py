"""Stable canonical serialization and request hashing.

Canonical form: UTF-8 JSON, sorted keys, no whitespace, NFC-normalised strings,
Decimal/amount values rendered as normalised strings. Floats are rejected for
money fields to avoid representation ambiguity.
"""
from __future__ import annotations

import hashlib
import json
import unicodedata
from decimal import Decimal
from typing import Any


def _norm(v: Any) -> Any:
    if isinstance(v, str):
        return unicodedata.normalize("NFC", v)
    if isinstance(v, Decimal):
        return format(v.normalize(), "f")
    if isinstance(v, bool) or v is None or isinstance(v, int):
        return v
    if isinstance(v, float):
        raise TypeError("floats are not permitted in canonical requests; use Decimal or str")
    if isinstance(v, dict):
        return {_norm(str(k)): _norm(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_norm(x) for x in v]
    raise TypeError(f"unsupported type in canonical form: {type(v).__name__}")


def canonical_json(obj: Any) -> str:
    return json.dumps(_norm(obj), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def request_hash(tool: str, params: dict[str, Any], tenant: str, principal: str) -> str:
    """Hash binding the exact action: tool, parameters, tenant and principal."""
    return sha256_hex(
        canonical_json({"tool": tool, "params": params, "tenant": tenant, "principal": principal})
    )
