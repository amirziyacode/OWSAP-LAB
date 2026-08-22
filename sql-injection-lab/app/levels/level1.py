"""
Level 1 - Basic Authentication SQL Injection

VULNERABILITY:
User-supplied username/password are concatenated directly into a SQL
string with no parameterization and no escaping.
"""

from database import get_db


def attempt_login(username: str, password: str):
    conn = get_db()
    cur = conn.cursor()

    # --- INTENTIONALLY VULNERABLE ---
    query = (
        "SELECT * FROM level1_users WHERE username = '"
        + username
        + "' AND password = '"
        + password
        + "'"
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
