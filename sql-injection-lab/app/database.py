"""
database.py
Handles SQLite database initialization and reset for the SQL Injection CTF Lab.

IMPORTANT: This file deliberately seeds a fully vulnerable database.
Do not reuse any of this code, schema, or query style in a real application.
"""

import os
import sqlite3

DB_PATH = os.path.join(os.path.dirname(__file__), "lab.db")

FLAGS = {
    1: "FLAG{auth_bypass_1s_ju5t_th3_b3g1nn1ng}",
    2: "FLAG{uni0n_s3l3ct_l1ke_a_pr0}",
    3: "FLAG{enum3r4t10n_unlocks_s3cr3ts}",
    4: "FLAG{r34d_th3_qu3ry_n0t_th3_scr33n}",
    5: "FLAG{bl1nd_but_n0t_d3af_b00l34n}",
    6: "FLAG{t1m3_1s_4ls0_4_ch4nn3l}",
    7: "FLAG{f1lt3rs_4r3_n0t_p4rs3rs}",
    8: "FLAG{w4f_n0rm4l1z4t10n_f41ls}",
    9: "FLAG{st0r3d_t0d4y_3x3cut3d_l4t3r}",
    10: "FLAG{ch41n3d_st3ps_t0_full_c0mpr0m1s3}",
}


def get_db():
    """Return a new sqlite3 connection with row access by column name."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(reset=False):
    """Create (or reset) the full lab schema and seed data."""
    if reset and os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    first_time = not os.path.exists(DB_PATH)
    conn = get_db()
    cur = conn.cursor()

    # ---------- Level 1: Basic auth bypass ----------
    cur.executescript(
        """
        DROP TABLE IF EXISTS level1_users;
        CREATE TABLE level1_users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0
        );
        """
    )
    cur.executemany(
        "INSERT INTO level1_users (username, password, is_admin) VALUES (?, ?, ?)",
        [
            ("guest", "guestpass", 0),
            ("alice", "alicepw123", 0),
            ("admin", "S3cur3AdminPW!", 1),
        ],
    )

    # ---------- Level 2: UNION-based on a product search ----------
    cur.executescript(
        """
        DROP TABLE IF EXISTS level2_products;
        CREATE TABLE level2_products (
            id INTEGER PRIMARY KEY,
            name TEXT,
            description TEXT,
            price REAL
        );
        """
    )
    cur.executemany(
        "INSERT INTO level2_products (name, description, price) VALUES (?, ?, ?)",
        [
            ("Widget", "A basic widget", 9.99),
            ("Gadget", "A useful gadget", 19.99),
            ("Gizmo", "A fancy gizmo", 29.99),
        ],
    )
    # The flag lives in a separate, named table. The player already knows
    # its name/column from the level description - level 2 only tests the
    # UNION mechanics (column count + injection point), not enumeration.
    cur.executescript(
        """
        DROP TABLE IF EXISTS level2_secret_flags;
        CREATE TABLE level2_secret_flags (
            id INTEGER PRIMARY KEY,
            flag_value TEXT
        );
        """
    )
    cur.execute(
        "INSERT INTO level2_secret_flags (flag_value) VALUES (?)", (FLAGS[2],)
    )

    # ---------- Level 3: Enumeration across tables ----------
    cur.executescript(
        """
        DROP TABLE IF EXISTS level3_products;
        DROP TABLE IF EXISTS level3_secret_vault;
        CREATE TABLE level3_products (
            id INTEGER PRIMARY KEY,
            name TEXT,
            category TEXT
        );
        CREATE TABLE level3_secret_vault (
            id INTEGER PRIMARY KEY,
            secret_name TEXT,
            secret_value TEXT
        );
        """
    )
    cur.executemany(
        "INSERT INTO level3_products (name, category) VALUES (?, ?)",
        [("Notebook", "office"), ("Pen", "office"), ("Backpack", "travel")],
    )
    cur.execute(
        "INSERT INTO level3_secret_vault (secret_name, secret_value) VALUES (?, ?)",
        ("ctf_flag", FLAGS[3]),
    )

    # ---------- Level 4: Hidden output, must reason about the query ----------
    cur.executescript(
        """
        DROP TABLE IF EXISTS level4_items;
        CREATE TABLE level4_items (
            id INTEGER PRIMARY KEY,
            title TEXT,
            visible INTEGER DEFAULT 1,
            note TEXT
        );
        """
    )
    cur.executemany(
        "INSERT INTO level4_items (title, visible, note) VALUES (?, ?, ?)",
        [
            ("Public Item A", 1, "nothing special"),
            ("Public Item B", 1, "nothing special"),
            ("Hidden Flag Item", 0, FLAGS[4]),
        ],
    )

    # ---------- Level 5: Boolean-based blind ----------
    cur.executescript(
        """
        DROP TABLE IF EXISTS level5_users;
        CREATE TABLE level5_users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            secret_flag TEXT
        );
        """
    )
    cur.execute(
        "INSERT INTO level5_users (username, secret_flag) VALUES (?, ?)",
        ("targetuser", FLAGS[5]),
    )

    # ---------- Level 6: Time-based blind ----------
    cur.executescript(
        """
        DROP TABLE IF EXISTS level6_users;
        CREATE TABLE level6_users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            secret_flag TEXT
        );
        """
    )
    cur.execute(
        "INSERT INTO level6_users (username, secret_flag) VALUES (?, ?)",
        ("targetuser", FLAGS[6]),
    )

    # ---------- Level 7: Filtered (weak blacklist) ----------
    cur.executescript(
        """
        DROP TABLE IF EXISTS level7_users;
        CREATE TABLE level7_users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            secret_flag TEXT
        );
        """
    )
    cur.execute(
        "INSERT INTO level7_users (username, password, secret_flag) VALUES (?, ?, ?)",
        ("admin", "N0tG3ssable!", FLAGS[7]),
    )

    # ---------- Level 8: WAF bypass (input normalization layer) ----------
    cur.executescript(
        """
        DROP TABLE IF EXISTS level8_users;
        CREATE TABLE level8_users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            secret_flag TEXT
        );
        """
    )
    cur.execute(
        "INSERT INTO level8_users (username, password, secret_flag) VALUES (?, ?, ?)",
        ("admin", "An0th3rP4ssw0rd!", FLAGS[8]),
    )

    # ---------- Level 9: Second-order injection ----------
    cur.executescript(
        """
        DROP TABLE IF EXISTS level9_pending_signups;
        DROP TABLE IF EXISTS level9_profiles;
        CREATE TABLE level9_pending_signups (
            id INTEGER PRIMARY KEY,
            username TEXT
        );
        CREATE TABLE level9_profiles (
            id INTEGER PRIMARY KEY,
            username TEXT,
            bio TEXT
        );
        """
    )
    cur.execute(
        "INSERT INTO level9_profiles (username, bio) VALUES (?, ?)",
        ("system", f"internal note: {FLAGS[9]}"),
    )

    # ---------- Level 10: Combined challenge ----------
    cur.executescript(
        """
        DROP TABLE IF EXISTS level10_users;
        DROP TABLE IF EXISTS level10_products;
        DROP TABLE IF EXISTS level10_vault;
        CREATE TABLE level10_users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            role TEXT
        );
        CREATE TABLE level10_products (
            id INTEGER PRIMARY KEY,
            name TEXT,
            code TEXT
        );
        CREATE TABLE level10_vault (
            id INTEGER PRIMARY KEY,
            label TEXT,
            value TEXT
        );
        """
    )
    cur.executemany(
        "INSERT INTO level10_users (username, password, role) VALUES (?, ?, ?)",
        [
            ("player", "playerpass", "user"),
            ("boss", "Fin4lB0ssPW!", "admin"),
        ],
    )
    cur.executemany(
        "INSERT INTO level10_products (name, code) VALUES (?, ?)",
        [("Alpha", "A-100"), ("Beta", "B-200")],
    )
    cur.execute(
        "INSERT INTO level10_vault (label, value) VALUES (?, ?)",
        ("final_flag", FLAGS[10]),
    )

    # ---------- Progress tracking ----------
    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS progress (
            level INTEGER PRIMARY KEY,
            completed INTEGER DEFAULT 0,
            completed_at TEXT
        );
        """
    )
    for lvl in range(1, 11):
        cur.execute(
            "INSERT OR IGNORE INTO progress (level, completed) VALUES (?, 0)",
            (lvl,),
        )
    if reset:
        cur.execute("UPDATE progress SET completed = 0, completed_at = NULL")

    conn.commit()
    conn.close()
    return first_time
