"""
Level 6 - Time-based Blind SQL Injection

VULNERABILITY:
Same concatenation flaw as level 5, but this time the response text
is IDENTICAL regardless of whether the condition is true or false -
there is no visible difference at all. The only observable signal is
response time, which the player can influence with an expensive
conditional SQLite expression (SQLite has no SLEEP(); a heavy
self-join / cartesian product is the classic equivalent).
"""

import time

from database import get_db


def check_user_timing(username: str):
    conn = get_db()
    cur = conn.cursor()

    # --- INTENTIONALLY VULNERABLE ---
    query = "SELECT id FROM level6_users WHERE username = '" + username + "'"
    # ---------------------------------

    start = time.time()
    try:
        cur.execute(query)
        cur.fetchall()
    except Exception:
        pass
    elapsed = time.time() - start
    conn.close()
    # The response message never reveals TRUE/FALSE - only elapsed time differs.
    return elapsed, query
