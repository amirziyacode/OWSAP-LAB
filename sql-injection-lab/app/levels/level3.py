"""
Level 3 - Database Enumeration via UNION-based SQL Injection

VULNERABILITY:
Same style as level 2, but the flag is not stored in the queried table.
The player must enumerate schema (sqlite_master) and pivot to another table.
Selected columns: name, category (2 columns).
"""

from database import get_db


def search_products(q: str):
    conn = get_db()
    cur = conn.cursor()

    # --- INTENTIONALLY VULNERABLE ---
    query = (
        "SELECT name, category FROM level3_products "
        "WHERE category = '" + q + "'"
    )
    # ---------------------------------

    error = None
    rows = []
    try:
        cur.execute(query)
        rows = cur.fetchall()
    except Exception as e:
        error = str(e)
    conn.close()
    return rows, query, error
