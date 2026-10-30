import os
import sqlite3
import time
from typing import Any, Dict, List, Optional, Tuple

from backend.database.base import DatabaseAdapter


def _sqlite_read_only_authorizer(
    action: int,
    arg1: Optional[str],
    arg2: Optional[str],
    db_name: Optional[str],
    trigger_name: Optional[str],
) -> int:
    """SQLite native authorizer callback that strictly permits only read operations."""
    allowed_actions = {
        sqlite3.SQLITE_SELECT,
        sqlite3.SQLITE_READ,
        sqlite3.SQLITE_FUNCTION,
    }
    return sqlite3.SQLITE_OK if action in allowed_actions else sqlite3.SQLITE_DENY


class SQLiteAdapter(DatabaseAdapter):
    """
    SQLite adapter for PII Shield.
    Enforces native read-only authorizer callbacks and safe cursor pagination.
    """

    def __init__(self, db_path: str):
        self.db_path = db_path

    def _get_connection(self) -> sqlite3.Connection:
        if not os.path.exists(self.db_path):
            from backend.db import init_db
            init_db(self.db_path)
        conn = sqlite3.connect(self.db_path, timeout=5.0)
        conn.set_authorizer(_sqlite_read_only_authorizer)
        return conn

    def test_connection(self) -> Dict[str, Any]:
        start = time.perf_counter()
        try:
            conn = self._get_connection()
            cur = conn.cursor()
            cur.execute("SELECT 1")
            cur.fetchone()
            conn.close()
            latency_ms = round((time.perf_counter() - start) * 1000, 2)
            return {
                "status": "connected",
                "engine": "sqlite",
                "database": os.path.basename(self.db_path),
                "latency_ms": latency_ms,
                "read_only_guard": "sqlite_authorizer_active",
            }
        except Exception as exc:
            return {
                "status": "error",
                "engine": "sqlite",
                "error": str(exc),
            }

    def execute_read_query(
        self, sql: str, max_rows: int = 1000, timeout_seconds: int = 10
    ) -> Tuple[List[str], List[List[Any]], Dict[str, Any]]:
        start = time.perf_counter()
        conn = self._get_connection()
        try:
            cur = conn.cursor()
            cur.execute(sql)
            description = cur.description
            if not description:
                return [], [], {"rows_fetched": 0, "execution_ms": 0.0, "truncated": False}

            columns = [col[0] for col in description]
            # Fetch at most max_rows + 1 to detect if truncation occurred
            raw_rows = cur.fetchmany(max_rows + 1)
            truncated = len(raw_rows) > max_rows
            if truncated:
                raw_rows = raw_rows[:max_rows]

            rows = [list(r) for r in raw_rows]
            execution_ms = round((time.perf_counter() - start) * 1000, 2)
            metadata = {
                "rows_fetched": len(rows),
                "execution_ms": execution_ms,
                "truncated": truncated,
                "max_rows": max_rows,
            }
            return columns, rows, metadata
        finally:
            conn.close()

    def get_tables(self) -> List[str]:
        conn = self._get_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
            return [row[0] for row in cur.fetchall()]
        finally:
            conn.close()

    def get_table_columns(self, table: str) -> List[str]:
        conn = self._get_connection()
        try:
            cur = conn.cursor()
            cur.execute(f"PRAGMA table_info('{table}')")
            # PRAGMA returns (cid, name, type, notnull, dflt_value, pk)
            return [row[1] for row in cur.fetchall()]
        except Exception:
            # Fallback using empty SELECT
            cur = conn.cursor()
            cur.execute(f"SELECT * FROM {table} LIMIT 0")
            return [col[0] for col in cur.description] if cur.description else []
        finally:
            conn.close()

    def get_sample_rows(self, table: str, limit: int = 5) -> List[List[Any]]:
        conn = self._get_connection()
        try:
            cur = conn.cursor()
            cur.execute(f"SELECT * FROM {table} LIMIT {int(limit)}")
            return [list(r) for r in cur.fetchall()]
        finally:
            conn.close()

    def close(self) -> None:
        pass

