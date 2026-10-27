"""SQLite-backed synthetic banking store. Single shared connection guarded by a lock;
transfers run inside BEGIN IMMEDIATE so they are atomic and serialised."""
from __future__ import annotations

import sqlite3
import threading

SCHEMA = """
CREATE TABLE accounts(id TEXT PRIMARY KEY, tenant TEXT NOT NULL, customer_id TEXT NOT NULL,
  currency TEXT NOT NULL, balance_cents INTEGER NOT NULL CHECK(balance_cents >= 0),
  contact TEXT NOT NULL);
CREATE TABLE transactions(id INTEGER PRIMARY KEY AUTOINCREMENT, account_id TEXT NOT NULL,
  counterparty TEXT, amount_cents INTEGER NOT NULL, currency TEXT NOT NULL, memo TEXT NOT NULL);
CREATE TABLE payees(account_id TEXT NOT NULL, payee_id TEXT NOT NULL, PRIMARY KEY(account_id,payee_id));
CREATE TABLE idempotency(key TEXT PRIMARY KEY, request_fp TEXT NOT NULL, result TEXT NOT NULL);
CREATE TABLE side_effects(id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, ref TEXT NOT NULL);
"""


class Database:
    def __init__(self, path: str = ":memory:") -> None:
        self.conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        self.conn.executescript(SCHEMA)

    def reset(self) -> None:
        with self.lock:
            for t in ("accounts", "transactions", "payees", "idempotency", "side_effects"):
                self.conn.execute(f"DELETE FROM {t}")
            self.conn.execute("DELETE FROM sqlite_sequence")

    def side_effect_count(self) -> int:
        with self.lock:
            return self.conn.execute("SELECT COUNT(*) FROM side_effects").fetchone()[0]

    def snapshot(self) -> dict:
        """Deterministic full-state snapshot used to prove denied calls changed nothing."""
        with self.lock:
            out = {}
            for t, order in (("accounts", "id"), ("transactions", "id"),
                             ("payees", "account_id,payee_id"), ("side_effects", "id")):
                out[t] = [tuple(r) for r in self.conn.execute(f"SELECT * FROM {t} ORDER BY {order}")]
            return out
