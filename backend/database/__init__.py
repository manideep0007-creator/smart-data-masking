import os
from typing import Optional

from backend.database.base import DatabaseAdapter
from backend.database.sqlite_adapter import SQLiteAdapter
from backend.database.postgres_adapter import PostgreSQLAdapter

_CURRENT_ADAPTER: Optional[DatabaseAdapter] = None


def get_database_adapter(engine: Optional[str] = None, db_path: Optional[str] = None) -> DatabaseAdapter:
    """
    Factory function to retrieve or instantiate the configured DatabaseAdapter.
    Defaults to SQLite with customers.db, or PostgreSQL when DB_ENGINE=postgres.
    """
    configured_engine = (engine or os.getenv("DB_ENGINE", "sqlite")).lower().strip()

    if configured_engine in ("postgres", "postgresql", "pg"):
        return PostgreSQLAdapter()
    else:
        from backend.db import DEFAULT_DB_PATH
        resolved_path = db_path or os.getenv("DB_PATH", DEFAULT_DB_PATH)
        return SQLiteAdapter(resolved_path)


__all__ = ["DatabaseAdapter", "SQLiteAdapter", "PostgreSQLAdapter", "get_database_adapter"]

