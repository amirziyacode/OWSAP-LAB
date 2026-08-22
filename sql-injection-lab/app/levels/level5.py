"""
Level 5 - Boolean-based Blind SQL Injection

VULNERABILITY:
The username parameter is concatenated directly into a WHERE clause.
No row data or SQL errors are ever returned to the client - only a
generic "User found" / "User not found" message depending on whether
the query returned any rows. This is enough to leak data one bit at
a time via conditional (TRUE/FALSE) payloads.
"""

from database import get_db


def check_user(username: str):
    conn = get_db()
    cur = conn.cursor()

    # --- INTENTIONALLY VULNERABLE ---
    query = "SELECT id FROM level5_users WHERE username = '" + username + "'"
    # ---------------------------------

    found = False
    try:
        cur.execute(query)
        rows = cur.fetchall()
        found = len(rows) > 0
    except Exception:
        # Errors are swallowed on purpose - this level is blind,
        # not error-based.
        found = False
    conn.close()
    return found, query
