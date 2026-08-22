"""
Level 9 - Second-order SQL Injection

VULNERABILITY:
Registration (register_username) is completely safe - it uses a
parameterized query, so nothing malicious happens at input time.
The stored value is only used unsafely LATER, in a separate
"process pending signups" operation, which builds a query by string
concatenation using the value that was read back out of the database.
"""

from database import get_db


def register_username(username: str):
    """Step 1: safely store the raw username (parameterized - not vulnerable here)."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO level9_pending_signups (username) VALUES (?)", (username,)
    )
    conn.commit()
    conn.close()


def process_pending_signups():
    """
    Step 2: process every pending signup. This simulates a background job
    (e.g. a batch script) that later reads the stored value back out of
    the database and unsafely concatenates it into a new query.
    """
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, username FROM level9_pending_signups")
    pending = cur.fetchall()

    results = []
    for row in pending:
        stored_username = row["username"]

        # --- INTENTIONALLY VULNERABLE (second-order) ---
        query = (
            "SELECT username, bio FROM level9_profiles WHERE username = '"
            + stored_username
            + "'"
        )
        # -------------------------------------------------
        error = None
        rows = []
        try:
            cur.execute(query)
            rows = cur.fetchall()
        except Exception as e:
            error = str(e)
        results.append(
            {
                "stored_username": stored_username,
                "query": query,
                "rows": rows,
                "error": error,
            }
        )

    # Clear the queue after processing, like a real batch job would.
    cur.execute("DELETE FROM level9_pending_signups")
    conn.commit()
    conn.close()
    return results
