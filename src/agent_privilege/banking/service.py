"""Banking business logic. Independently enforces gateway assertions (defense in depth).

The service refuses every mutating or reading call that lacks a valid, unexpired,
single-use HMAC assertion bound to the exact request. It does NOT re-run full policy;
it checks the tenant/account/tool/limit claims the gateway signed.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import threading
from decimal import Decimal, InvalidOperation
from typing import Any

from ..clock import Clock, SystemClock
from ..gateway.canonicalize import canonical_json
from .db import Database

SUPPORTED_CURRENCIES = {"USD", "EUR"}
MAX_CENTS = 10**12


class BackendError(Exception):
    def __init__(self, code: str, msg: str = "") -> None:
        super().__init__(f"{code}: {msg}")
        self.code = code


def sign_assertion(key: bytes, claims: dict[str, Any]) -> str:
    body = canonical_json(claims)
    mac = hmac.new(key, body.encode(), hashlib.sha256).hexdigest()
    return json.dumps({"claims": claims, "mac": mac}, sort_keys=True)


def parse_amount(value: Any) -> int:
    """Return cents; reject floats, non-positive, >2dp, absurd values."""
    if isinstance(value, bool) or isinstance(value, float) or not isinstance(value, (str, int, Decimal)):
        raise BackendError("invalid_amount", "amount must be str/int/Decimal")
    try:
        d = Decimal(str(value))
    except InvalidOperation as e:
        raise BackendError("invalid_amount", "unparseable") from e
    if not d.is_finite() or d <= 0:
        raise BackendError("invalid_amount", "must be positive")
    cents = d * 100
    if cents != cents.to_integral_value():
        raise BackendError("invalid_amount", "max 2 decimal places")
    if cents > MAX_CENTS:
        raise BackendError("invalid_amount", "too large")
    return int(cents)


class BankingService:
    def __init__(self, db: Database, assertion_key: bytes, clock: Clock | None = None) -> None:
        self.db = db
        self._key = assertion_key
        self.clock = clock or SystemClock()
        self._used_nonces: set[str] = set()
        self._nlock = threading.Lock()

    # -- trust boundary ---------------------------------------------------
    def _verify(self, assertion: str | None, tool: str, request_hash: str,
                account_ids: list[str]) -> dict[str, Any]:
        if not assertion:
            raise BackendError("no_assertion")
        try:
            obj = json.loads(assertion)
            claims, mac = obj["claims"], obj["mac"]
        except (ValueError, KeyError, TypeError) as e:
            raise BackendError("malformed_assertion") from e
        good = hmac.new(self._key, canonical_json(claims).encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(good, str(mac)):
            raise BackendError("bad_signature")
        if claims.get("tool") != tool or claims.get("request_hash") != request_hash:
            raise BackendError("assertion_mismatch")
        if int(claims.get("exp_ms", 0)) < int(self.clock.now() * 1000):
            raise BackendError("assertion_expired")
        allowed = set(claims.get("accounts", []))
        if not set(account_ids) <= allowed:
            raise BackendError("account_not_in_assertion")
        with self._nlock:
            n = claims.get("nonce")
            if not n or n in self._used_nonces:
                raise BackendError("assertion_replayed")
            self._used_nonces.add(n)
        return claims

    def _account(self, account_id: str) -> Any:
        row = self.db.conn.execute("SELECT * FROM accounts WHERE id=?", (account_id,)).fetchone()
        if row is None:
            raise BackendError("not_found", account_id)
        return row

    def _check_tenant(self, claims: dict[str, Any], row: Any) -> None:
        if row["tenant"] != claims.get("tenant"):
            raise BackendError("cross_tenant")

    # -- operations -------------------------------------------------------
    def call(self, tool: str, params: dict[str, Any], request_hash: str, assertion: str | None) -> Any:
        fn = getattr(self, f"_op_{tool}", None)
        if fn is None:
            raise BackendError("unknown_tool", tool)
        accts = [str(params[k]) for k in ("account_id", "source_id", "destination_id") if k in params]
        # destination of a transfer may be in another account but the signer lists it explicitly
        claims = self._verify(assertion, tool, request_hash, accts)
        with self.db.lock:
            return fn(params, claims)

    def _op_get_account(self, p: dict, c: dict) -> dict:
        r = self._account(p["account_id"]); self._check_tenant(c, r)
        return {"id": r["id"], "tenant": r["tenant"], "currency": r["currency"],
                "balance_cents": r["balance_cents"]}

    def _op_list_transactions(self, p: dict, c: dict) -> list[dict]:
        r = self._account(p["account_id"]); self._check_tenant(c, r)
        rows = self.db.conn.execute(
            "SELECT id,counterparty,amount_cents,currency,memo FROM transactions "
            "WHERE account_id=? ORDER BY id", (r["id"],)).fetchall()
        return [dict(x) for x in rows]

    def _op_export_statement(self, p: dict, c: dict) -> dict:
        r = self._account(p["account_id"]); self._check_tenant(c, r)
        txs = self._op_list_transactions(p, c)
        self.db.conn.execute("INSERT INTO side_effects(kind,ref) VALUES('export',?)", (r["id"],))
        return {"account_id": r["id"], "customer_id": r["customer_id"], "transactions": txs}

    def _op_update_contact(self, p: dict, c: dict) -> dict:
        r = self._account(p["account_id"]); self._check_tenant(c, r)
        contact = p.get("contact")
        if not isinstance(contact, dict) or not contact:
            raise BackendError("invalid_contact")
        self.db.conn.execute("UPDATE accounts SET contact=? WHERE id=?",
                             (json.dumps(contact, sort_keys=True), r["id"]))
        self.db.conn.execute("INSERT INTO side_effects(kind,ref) VALUES('contact',?)", (r["id"],))
        return {"updated": r["id"]}

    def _op_create_payee(self, p: dict, c: dict) -> dict:
        r = self._account(p["account_id"]); self._check_tenant(c, r)
        pid = str(p.get("payee_id", ""))
        if not pid:
            raise BackendError("invalid_payee")
        self.db.conn.execute("INSERT OR IGNORE INTO payees VALUES(?,?)", (r["id"], pid))
        self.db.conn.execute("INSERT INTO side_effects(kind,ref) VALUES('payee',?)", (f"{r['id']}>{pid}",))
        return {"payee": pid}

    def _op_transfer_funds(self, p: dict, c: dict) -> dict:
        cents = parse_amount(p.get("amount"))
        cur = p.get("currency")
        if cur not in SUPPORTED_CURRENCIES:
            raise BackendError("invalid_currency", str(cur))
        key = p.get("idempotency_key")
        if not key or not isinstance(key, str):
            raise BackendError("missing_idempotency_key")
        if p["source_id"] == p["destination_id"]:
            raise BackendError("same_account")
        limit = c.get("max_amount_cents")
        if limit is not None and cents > int(limit):
            raise BackendError("over_assertion_limit")
        fp = canonical_json({k: v for k, v in p.items()})
        conn = self.db.conn
        conn.execute("BEGIN IMMEDIATE")
        try:
            prev = conn.execute("SELECT request_fp,result FROM idempotency WHERE key=?", (key,)).fetchone()
            if prev:
                if prev["request_fp"] != fp:
                    raise BackendError("idempotency_conflict")
                conn.execute("COMMIT")
                return json.loads(prev["result"])
            src, dst = self._account(p["source_id"]), self._account(p["destination_id"])
            self._check_tenant(c, src)
            if dst["tenant"] != src["tenant"] and not c.get("allow_cross_tenant_destination", False):
                raise BackendError("cross_tenant_destination")
            if src["currency"] != cur or dst["currency"] != cur:
                raise BackendError("currency_mismatch")
            if src["balance_cents"] < cents:
                raise BackendError("insufficient_funds")
            conn.execute("UPDATE accounts SET balance_cents=balance_cents-? WHERE id=?", (cents, src["id"]))
            conn.execute("UPDATE accounts SET balance_cents=balance_cents+? WHERE id=?", (cents, dst["id"]))
            for acct, cp, amt in ((src["id"], dst["id"], -cents), (dst["id"], src["id"], cents)):
                conn.execute("INSERT INTO transactions(account_id,counterparty,amount_cents,currency,memo)"
                             " VALUES(?,?,?,?,?)", (acct, cp, amt, cur, "transfer"))
            result = {"status": "ok", "amount_cents": cents, "key": key}
            conn.execute("INSERT INTO idempotency VALUES(?,?,?)", (key, fp, json.dumps(result)))
            conn.execute("INSERT INTO side_effects(kind,ref) VALUES('transfer',?)", (key,))
            conn.execute("COMMIT")
            return result
        except BaseException:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
