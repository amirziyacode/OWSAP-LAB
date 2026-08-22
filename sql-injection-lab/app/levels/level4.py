"""
Level 4 - Hidden Output SQL Injection

VULNERABILITY:
The application filters results with "AND visible = 1" appended
server-side. The id parameter is concatenated directly, so the
appended clause can be neutralized (e.g. via a comment or an
always-true OR condition combined with UNION).
"""

from database import get_db


def get_item(item_id: str):
    conn = get_db()
    cur = conn.cursor()

    # --- INTENTIONALLY VULNERABLE ---
    query = (
        "SELECT title, note FROM level4_items WHERE id = "
        + item_id
        + " AND visible = 1"
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
