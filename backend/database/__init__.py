import os
from typing import Optional

from dotenv import load_dotenv

from backend.database.base import DatabaseAdapter
from backend.database.sqlite_adapter import SQLiteAdapter
from backend.database.postgres_adapter import PostgreSQLAdapter

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_ENV_PATH = os.path.join(_PROJECT_ROOT, ".env")
if os.path.exists(_ENV_PATH):
    load_dotenv(_ENV_PATH)

_CURRENT_ADAPTER: Optional[DatabaseAdapter] = None


def get_database_adapter(engine: Optional[str] = None, db_path: Optional[str] = None) -> DatabaseAdapter:
    """
    Factory function to retrieve or instantiate the configured DatabaseAdapter.
    Defaults to SQLite with saffron_bank.db or customers.db, or PostgreSQL when DB_ENGINE=postgres.
    """
    configured_engine = (engine or os.getenv("DB_ENGINE", "sqlite")).lower().strip()

    if configured_engine in ("postgres", "postgresql", "pg"):
        return PostgreSQLAdapter()
    else:
        from backend.db import DEFAULT_DB_PATH
        raw_path = db_path or os.getenv("DB_PATH", DEFAULT_DB_PATH)
        if raw_path and not os.path.isabs(raw_path):
            resolved_path = os.path.normpath(os.path.join(_PROJECT_ROOT, raw_path))
        else:
            resolved_path = raw_path
        return SQLiteAdapter(resolved_path)


__all__ = ["DatabaseAdapter", "SQLiteAdapter", "PostgreSQLAdapter", "get_database_adapter"]

