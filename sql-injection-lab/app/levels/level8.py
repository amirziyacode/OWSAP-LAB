"""
Level 8 - WAF Bypass

VULNERABILITY:
A more "realistic" filtering layer performs a single, non-recursive,
case-insensitive substring removal of a few dangerous keywords before
the value is used in the query. Because the removal happens only ONCE
and does not re-scan the resulting string, an attacker can craft input
where deleting the keyword produces a *new* occurrence of the keyword
(e.g. "UNIunionON" -> removing "union" once leaves "UNION").

This mirrors a very common real-world WAF/filter implementation bug.
"""

import re

from database import get_db

DANGEROUS_KEYWORDS = ["union", "select"]


def naive_filter(value: str) -> str:
    """Removes each dangerous keyword ONCE (non-recursively), case-insensitively."""
    cleaned = value
    for kw in DANGEROUS_KEYWORDS:
        cleaned = re.sub(kw, "", cleaned, count=1, flags=re.IGNORECASE)
    return cleaned


def login(username: str, password: str):
    conn = get_db()
    cur = conn.cursor()

    safe_username = naive_filter(username)
    safe_password = naive_filter(password)

    # --- INTENTIONALLY VULNERABLE ---
    query = (
        "SELECT * FROM level8_users WHERE username = '"
        + safe_username
        + "' AND password = '"
        + safe_password
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
