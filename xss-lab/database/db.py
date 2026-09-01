"""
Thin SQLite helper. All queries here use parameterized statements (?) —
this lab teaches XSS, not SQL injection, so the DB layer itself is not
intentionally vulnerable.
"""

import os
import sqlite3
from pathlib import Path

DB_PATH = os.environ.get("XSS_LAB_DB", str(Path(__file__).parent / "lab.db"))
SCHEMA_PATH = Path(__file__).parent / "schema.sql"


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(reset: bool = False) -> None:
    """Create (or recreate, if reset=True) the database from schema.sql."""
    if reset and os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    first_time = not os.path.exists(DB_PATH)
    conn = get_connection()
    try:
        if reset or first_time:
            with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
                conn.executescript(f.read())
            conn.commit()
    finally:
        conn.close()


def query(sql: str, params: tuple = ()):
    conn = get_connection()
    try:
        cur = conn.execute(sql, params)
        rows = cur.fetchall()
        return rows
    finally:
        conn.close()


def execute(sql: str, params: tuple = ()) -> int:
    conn = get_connection()
    try:
        cur = conn.execute(sql, params)
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()
