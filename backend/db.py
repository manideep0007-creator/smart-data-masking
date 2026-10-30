import os
import sqlite3
from typing import Optional

DEFAULT_DB_PATH = os.path.join(os.path.dirname(__file__), "customers.db")

SAMPLE_CUSTOMERS = [
    (1, "Asha", "asha@example.com", "555-019-2834", "123-45-6789", "4111-2222-3333-1111", 85000, "742 Evergreen Ter, Springfield"),
    (2, "John Doe", "john.doe@techcorp.org", "555-832-1102", "987-65-4321", "4242-4242-4242-4242", 120000, "10 Downing St, London"),
    (3, "Carlos Mendez", "carlos.m@example.net", "555-472-8819", "345-67-8901", "5500-0000-0000-9999", 92000, "456 Oak Avenue, Metropolis"),
    (4, "Priya Patel", "priya.patel@acme.io", "555-901-3344", "567-89-0123", "4000-1234-5678-9010", 105000, "123 Maple Blvd, Gotham"),
]


def init_db(db_path: Optional[str] = None) -> str:
    """Initialize the SQLite database and seed sample records if not already populated."""
    path = db_path or DEFAULT_DB_PATH
    conn = sqlite3.connect(path)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            phone TEXT NOT NULL,
            ssn TEXT NOT NULL,
            card_number TEXT NOT NULL,
            salary REAL NOT NULL,
            address TEXT NOT NULL
        )
    """)
    cursor.execute("SELECT COUNT(*) FROM customers")
    count = cursor.fetchone()[0]
    if count == 0:
        cursor.executemany("""
            INSERT INTO customers (id, name, email, phone, ssn, card_number, salary, address)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, SAMPLE_CUSTOMERS)
        conn.commit()
    conn.close()
    return path


def _read_only_authorizer(action: int, arg1: Optional[str], arg2: Optional[str], db_name: Optional[str], trigger_name: Optional[str]) -> int:
    """SQLite authorizer callback that permits only read operations."""
    allowed_actions = {
        sqlite3.SQLITE_SELECT,
        sqlite3.SQLITE_READ,
        sqlite3.SQLITE_FUNCTION,
    }
    return sqlite3.SQLITE_OK if action in allowed_actions else sqlite3.SQLITE_DENY


def get_read_only_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """Return a connection configured to strictly deny write actions."""
    path = db_path or DEFAULT_DB_PATH
    if not os.path.exists(path):
        init_db(path)
    conn = sqlite3.connect(path)
    conn.set_authorizer(_read_only_authorizer)
    return conn

