import datetime
import threading
import time
from typing import Any, Dict, List, Optional
import logging

from backend.database import get_database_adapter
from backend.detector import classify_column
from backend.registry import registry

logger = logging.getLogger("pii_shield_scanner")


class BackgroundScanner:
    """
    Lightweight background scanner that asynchronously traverses database tables,
    samples data, evaluates heuristic classification rules, and populates the metadata registry
    without blocking incoming user queries.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._current_task: Optional[Dict[str, Any]] = None
        self._history: List[Dict[str, Any]] = []

    def get_status(self) -> Dict[str, Any]:
        """Get the current or most recent scan task status."""
        with self._lock:
            if not self._current_task:
                return {
                    "status": "idle",
                    "progress_pct": 100,
                    "tables_total": 0,
                    "tables_scanned": 0,
                    "columns_classified": 0,
                    "message": "No scan currently running. Ready to scan.",
                }
            return dict(self._current_task)

    def get_history(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent scan history log."""
        with self._lock:
            return list(reversed(self._history[-limit:]))

    def start_scan(
        self, table_name: Optional[str] = None, sample_limit: int = 10
    ) -> Dict[str, Any]:
        """
        Trigger an asynchronous background scan.
        Validates target table against database before spawning thread.
        Thread lock prevents race conditions or state corruption.
        """
        adapter = get_database_adapter()
        available_tables = adapter.get_tables()

        if table_name:
            # Validate table existence
            matched = [t for t in available_tables if t.lower() == table_name.lower()]
            if not matched:
                raise ValueError(
                    f"Table '{table_name}' does not exist in database. Available: {', '.join(available_tables)}"
                )
            target_table = matched[0]
        else:
            target_table = None

        safe_sample_limit = max(1, min(int(sample_limit), 100))

        with self._lock:
            if self._current_task and self._current_task.get("status") == "scanning":
                return {
                    "task_id": self._current_task["task_id"],
                    "status": "scanning",
                    "message": "A scan is already in progress.",
                    "progress_pct": self._current_task.get("progress_pct", 0),
                }

            task_id = f"scan_{int(time.time())}"
            task_info = {
                "task_id": task_id,
                "status": "scanning",
                "target_table": target_table or "all",
                "sample_limit": safe_sample_limit,
                "progress_pct": 0,
                "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "completed_at": None,
                "tables_total": 1 if target_table else len(available_tables),
                "tables_scanned": 0,
                "columns_classified": 0,
                "findings": [],
                "error": None,
            }
            self._current_task = task_info

        # Launch background worker thread
        thread = threading.Thread(
            target=self._run_scan_worker,
            args=(task_id, target_table, safe_sample_limit),
            daemon=True,
        )
        thread.start()

        return {
            "task_id": task_id,
            "status": "scanning",
            "message": f"Background scan initiated for '{target_table or 'all tables'}'.",
        }

    def _run_scan_worker(
        self, task_id: str, target_table: Optional[str] = None, sample_limit: int = 10
    ) -> None:
        """Worker executing schema discovery and classification."""
        logger.info(f"Background scanner starting task {task_id}")
        adapter = get_database_adapter()

        try:
            if target_table:
                tables = [target_table]
            else:
                tables = adapter.get_tables()

            total_tables = len(tables)
            with self._lock:
                if self._current_task and self._current_task["task_id"] == task_id:
                    self._current_task["tables_total"] = total_tables

            total_columns = 0
            all_findings = []

            for idx, table in enumerate(tables):
                # Fetch columns and bounded sample rows (avoid loading large tables into memory)
                columns = adapter.get_table_columns(table)
                sample_rows = adapter.get_sample_rows(table, limit=sample_limit)

                table_classifications = []
                for col_idx, col_name in enumerate(columns):
                    sample_values = [
                        row[col_idx] for row in sample_rows if col_idx < len(row)
                    ]
                    classification = classify_column(col_name, sample_values)
                    table_classifications.append(classification)
                    total_columns += 1

                # Update metadata registry
                registry.register_table_scan(table, table_classifications)
                all_findings.append({
                    "table": table,
                    "columns_count": len(table_classifications),
                    "sensitive_count": sum(1 for c in table_classifications if c["tag"] != "PUBLIC"),
                })

                # Update progress
                progress = int(((idx + 1) / max(1, total_tables)) * 100)
                with self._lock:
                    if self._current_task and self._current_task["task_id"] == task_id:
                        self._current_task["tables_scanned"] = idx + 1
                        self._current_task["progress_pct"] = progress
                        self._current_task["columns_classified"] = total_columns

                time.sleep(0.01)

            # Mark completed
            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            with self._lock:
                if self._current_task and self._current_task["task_id"] == task_id:
                    self._current_task["status"] = "completed"
                    self._current_task["progress_pct"] = 100
                    self._current_task["completed_at"] = now_iso
                    self._current_task["findings"] = all_findings
                    self._history.append(dict(self._current_task))

            logger.info(f"Background scan {task_id} completed successfully.")

        except Exception as exc:
            logger.error(f"Background scanner failed for task {task_id}: {exc}")
            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            with self._lock:
                if self._current_task and self._current_task["task_id"] == task_id:
                    self._current_task["status"] = "failed"
                    self._current_task["completed_at"] = now_iso
                    self._current_task["error"] = "Scanner internal error encountered."
                    self._history.append(dict(self._current_task))


# Global scanner instance
background_scanner = BackgroundScanner()
