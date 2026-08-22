"""
Level 7 - Filtered SQL Injection (weak blacklist)

VULNERABILITY:
A naive, CASE-SENSITIVE blacklist rejects a handful of obvious
lowercase SQL keywords/sequences. It does nothing to stop the same
keywords in a different case, alternative whitespace, or equivalent
SQL syntax.
"""

from database import get_db

# Deliberately weak: case-sensitive, exact-substring blacklist.
BLACKLIST = ["union", "select", "--", "or ", " or", "sleep"]


def is_blocked(raw_input: str) -> bool:
    return any(bad in raw_input for bad in BLACKLIST)


def login(username: str, password: str):
    conn = get_db()
    cur = conn.cursor()

    blocked = is_blocked(username) or is_blocked(password)
    if blocked:
        conn.close()
        return None, None, "Blocked by filter: forbidden keyword detected."

    # --- INTENTIONALLY VULNERABLE ---
    query = (
        "SELECT * FROM level7_users WHERE username = '"
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
