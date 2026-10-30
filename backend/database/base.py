from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple


class DatabaseAdapter(ABC):
    """
    Common database interface for the PII Shield query gateway.
    Abstracts query execution, metadata discovery, and read-only enforcement
    across different database engines (SQLite, PostgreSQL).
    """

    @abstractmethod
    def test_connection(self) -> Dict[str, Any]:
        """Verify database connectivity and return status information."""
        pass

    @abstractmethod
    def execute_read_query(
        self, sql: str, max_rows: int = 1000, timeout_seconds: int = 10
    ) -> Tuple[List[str], List[List[Any]], Dict[str, Any]]:
        """
        Safely execute a read-only query with row-limit and timeout safeguards.
        Returns:
            columns: List of column header names
            rows: List of fetched rows
            metadata: Dict with execution statistics (rows_fetched, execution_ms, truncated)
        """
        pass

    @abstractmethod
    def get_tables(self) -> List[str]:
        """Return the list of user tables in the database."""
        pass

    @abstractmethod
    def get_table_columns(self, table: str) -> List[str]:
        """Return list of column names for a given table."""
        pass

    @abstractmethod
    def get_sample_rows(self, table: str, limit: int = 5) -> List[List[Any]]:
        """Return sample rows for heuristic analysis."""
        pass

    @abstractmethod
    def close(self) -> None:
        """Close any open connections and release resources."""
        pass

