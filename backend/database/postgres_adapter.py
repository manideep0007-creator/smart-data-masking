import os
import time
from typing import Any, Dict, List, Optional, Tuple

from backend.database.base import DatabaseAdapter

try:
    import psycopg
    from psycopg import sql as pg_sql
    PSYCOPG_AVAILABLE = True
except ImportError:
    psycopg = None
    pg_sql = None
    PSYCOPG_AVAILABLE = False


class PostgreSQLAdapter(DatabaseAdapter):
    """
    PostgreSQL adapter for PII Shield.
    Enforces driver/session-level read-only transactions, statement timeouts,
    safe Identifier quoting (psycopg.sql.Identifier), and safe cursor pagination.
    """

    def __init__(
        self,
        connection_url: Optional[str] = None,
        host: Optional[str] = None,
        port: int = 5432,
        dbname: Optional[str] = None,
        user: Optional[str] = None,
        password: Optional[str] = None,
    ):
        self.connection_url = connection_url or os.getenv("DATABASE_URL")
        self.host = host or os.getenv("POSTGRES_HOST", "localhost")
        self.port = int(port or os.getenv("POSTGRES_PORT", 5432))
        self.dbname = dbname or os.getenv("POSTGRES_DB", "postgres")
        self.user = user or os.getenv("POSTGRES_USER", "postgres")
        self.password = password or os.getenv("POSTGRES_PASSWORD", "")

    def _get_connection_kwargs(self) -> Dict[str, Any]:
        if self.connection_url:
            return {"conninfo": self.connection_url, "connect_timeout": 2}
        return {
            "host": self.host,
            "port": self.port,
            "dbname": self.dbname,
            "user": self.user,
            "password": self.password,
            "connect_timeout": 2,
        }

    def _get_connection(self, timeout_seconds: int = 5):
        if not PSYCOPG_AVAILABLE:
            raise RuntimeError(
                "psycopg driver is not installed. Please install psycopg[binary] to enable PostgreSQL support."
            )
        kwargs = self._get_connection_kwargs()
        conn = psycopg.connect(**kwargs)
        # Enforce read-only session & query timeout at the PostgreSQL engine level
        with conn.cursor() as cur:
            cur.execute("SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY;")
            cur.execute(f"SET statement_timeout = '{int(timeout_seconds * 1000)}ms';")
        conn.commit()
        return conn

    def test_connection(self) -> Dict[str, Any]:
        if not PSYCOPG_AVAILABLE:
            return {
                "status": "error",
                "engine": "postgresql",
                "error": "psycopg driver is not installed",
            }
        start = time.perf_counter()
        try:
            conn = self._get_connection(timeout_seconds=3)
            with conn.cursor() as cur:
                cur.execute("SELECT version();")
                version = cur.fetchone()[0]
            conn.close()
            latency_ms = round((time.perf_counter() - start) * 1000, 2)
            return {
                "status": "connected",
                "engine": "postgresql",
                "database": self.dbname,
                "version": version,
                "latency_ms": latency_ms,
                "read_only_guard": "session_transaction_read_only_active",
            }
        except Exception as exc:
            return {
                "status": "error",
                "engine": "postgresql",
                "database": self.dbname,
                "error": str(exc),
            }

    def execute_read_query(
        self, sql: str, max_rows: int = 1000, timeout_seconds: int = 10
    ) -> Tuple[List[str], List[List[Any]], Dict[str, Any]]:
        start = time.perf_counter()
        conn = self._get_connection(timeout_seconds=timeout_seconds)
        try:
            with conn.cursor() as cur:
                cur.execute(sql)
                if not cur.description:
                    return [], [], {"rows_fetched": 0, "execution_ms": 0.0, "truncated": False}

                columns = [col.name for col in cur.description]
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
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT table_name
                    FROM information_schema.tables
                    WHERE table_schema = 'public'
                    ORDER BY table_name;
                    """
                )
                return [row[0] for row in cur.fetchall()]
        finally:
            conn.close()

    def _validate_table_identifier(self, table: str) -> str:
        """Validate table name against PostgreSQL public schema tables."""
        known_tables = self.get_tables()
        for t in known_tables:
            if t.lower() == table.lower():
                return t
        raise ValueError(f"Invalid table identifier '{table}'. Table does not exist in database.")

    def get_table_columns(self, table: str) -> List[str]:
        validated_table = self._validate_table_identifier(table)
        conn = self._get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT column_name
                    FROM information_schema.columns
                    WHERE table_schema = 'public' AND table_name = %s
                    ORDER BY ordinal_position;
                    """,
                    (validated_table,),
                )
                return [row[0] for row in cur.fetchall()]
        finally:
            conn.close()

    def get_sample_rows(self, table: str, limit: int = 5) -> List[List[Any]]:
        validated_table = self._validate_table_identifier(table)
        safe_limit = max(1, min(int(limit), 100))
        conn = self._get_connection()
        try:
            with conn.cursor() as cur:
                # Use psycopg.sql.Identifier to safely quote table identifier
                query = pg_sql.SQL("SELECT * FROM {} LIMIT %s").format(
                    pg_sql.Identifier(validated_table)
                )
                cur.execute(query, (safe_limit,))
                return [list(r) for r in cur.fetchall()]
        finally:
            conn.close()

    def close(self) -> None:
        pass
