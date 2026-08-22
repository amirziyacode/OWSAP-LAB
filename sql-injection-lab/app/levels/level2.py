"""
Level 2 - UNION-based SQL Injection

VULNERABILITY:
A search parameter is concatenated directly into a LIKE clause.
The products table has exactly 3 selected columns: name, description, price.
"""

from database import get_db


def search_products(q: str):
    conn = get_db()
    cur = conn.cursor()

    # --- INTENTIONALLY VULNERABLE ---
    query = (
        "SELECT name, description, price FROM level2_products "
        "WHERE name LIKE '%" + q + "%'"
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
