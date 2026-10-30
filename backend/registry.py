import datetime
from typing import Any, Dict, List, Optional


class MetadataRegistry:
    """
    Centralized in-memory registry of discovered schema metadata and PII classifications.
    Provides fast lookup for query masking and tracks schema scan history.
    """

    def __init__(self):
        # Maps table_name -> Dict of metadata (scanned_at, total_columns, columns: {col_name -> col_meta})
        self._tables: Dict[str, Dict[str, Any]] = {}
        self._last_scan_timestamp: Optional[str] = None

    def register_table_scan(
        self, table_name: str, column_classifications: List[Dict[str, Any]]
    ) -> None:
        """Register or update classifications for a table."""
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self._last_scan_timestamp = now_iso

        columns_dict: Dict[str, Dict[str, Any]] = {}
        for col in column_classifications:
            columns_dict[col["name"].lower()] = col

        self._tables[table_name.lower()] = {
            "table_name": table_name,
            "scanned_at": now_iso,
            "total_columns": len(column_classifications),
            "columns": columns_dict,
            "column_list": column_classifications,
        }

    def get_table_metadata(self, table_name: str) -> Optional[Dict[str, Any]]:
        """Retrieve full scanned metadata for a table."""
        return self._tables.get(table_name.lower())

    def get_column_classification(
        self, table_name: str, column_name: str
    ) -> Optional[Dict[str, Any]]:
        """Lookup classification for a specific column in a table."""
        table_meta = self._tables.get(table_name.lower())
        if not table_meta:
            return None
        return table_meta["columns"].get(column_name.lower())

    def find_column_classification(self, column_name: str) -> Optional[Dict[str, Any]]:
        """Find classification across any registered table by column name."""
        col_key = column_name.lower()
        for table_meta in self._tables.values():
            if col_key in table_meta["columns"]:
                return table_meta["columns"][col_key]
        return None

    def get_all_tables_metadata(self) -> Dict[str, Any]:
        """Return snapshot of all registered tables."""
        return {
            "tables": {k: v["column_list"] for k, v in self._tables.items()},
            "table_count": len(self._tables),
            "last_scan_timestamp": self._last_scan_timestamp,
        }

    def clear(self) -> None:
        """Clear registry for testing or full schema reset."""
        self._tables.clear()
        self._last_scan_timestamp = None


# Global registry singleton
registry = MetadataRegistry()

