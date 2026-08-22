"""
Level 10 - Advanced Combined Challenge

Combines:
  1. Authentication-bypass SQL injection to reach a logged-in state.
  2. A filtered (weak blacklist) search endpoint vulnerable to
     UNION-based injection.
  3. Schema enumeration (sqlite_master) to find the vault table.
  4. Pulling the final flag out of an unrelated table via UNION.

Errors are intentionally shown on this level (like level 3) so the
player can use them for enumeration - this is the most "advanced" and
forgiving level in terms of feedback, but requires chaining several
steps together.
"""

from database import get_db

BLACKLIST = ["drop ", "insert ", "update ", "delete ", "--;"]


def is_blocked(raw_input: str) -> bool:
    lowered = raw_input.lower()
    return any(bad in lowered for bad in BLACKLIST)


def login(username: str, password: str):
    conn = get_db()
    cur = conn.cursor()

    # --- INTENTIONALLY VULNERABLE ---
    query = (
        "SELECT * FROM level10_users WHERE username = '"
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


def search_products(code: str):
    conn = get_db()
    cur = conn.cursor()

    if is_blocked(code):
        conn.close()
        return None, None, "Blocked by filter: forbidden keyword detected."

    # --- INTENTIONALLY VULNERABLE ---
    query = "SELECT name, code FROM level10_products WHERE code = '" + code + "'"
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
