"""
app.py - SQL Injection CTF Lab

Entry point for the Flask application. Wires together routing, session
handling, progress tracking, request logging, and lab reset.

FOR LOCAL / EDUCATIONAL / AUTHORIZED-TESTING USE ONLY.
Every level in this application is intentionally vulnerable to SQL
injection. Do not deploy this application on a public network.
"""

import logging
import os
import time
from datetime import datetime, timezone

from flask import Flask, g, jsonify, redirect, render_template, request, session, url_for

from database import FLAGS, get_db, init_db
from levels import (
    level1,
    level10,
    level2,
    level3,
    level4,
    level5,
    level6,
    level7,
    level8,
    level9,
)

app = Flask(__name__)
app.secret_key = os.environ.get("LAB_SECRET_KEY", "dev-only-not-for-production")

LOG_PATH = os.path.join(os.path.dirname(__file__), "requests.log")
logger = logging.getLogger("lab")
logger.setLevel(logging.INFO)
if not logger.handlers:
    file_handler = logging.FileHandler(LOG_PATH)
    file_handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
    logger.addHandler(file_handler)

RECENT_REQUESTS = []  # in-memory ring buffer for the /logs debug page
MAX_RECENT = 200

LEVEL_META = {
    1: {"title": "Basic Authentication SQL Injection", "difficulty": "Easy"},
    2: {"title": "UNION-based SQL Injection", "difficulty": "Easy"},
    3: {"title": "Database Enumeration", "difficulty": "Medium"},
    4: {"title": "Hidden Output", "difficulty": "Medium"},
    5: {"title": "Boolean-based Blind SQL Injection", "difficulty": "Medium"},
    6: {"title": "Time-based Blind SQL Injection", "difficulty": "Hard"},
    7: {"title": "Filtered SQL Injection", "difficulty": "Hard"},
    8: {"title": "WAF Bypass", "difficulty": "Hard"},
    9: {"title": "Second-order SQL Injection", "difficulty": "Very Hard"},
    10: {"title": "Advanced Combined Challenge", "difficulty": "Very Hard"},
}


# ---------------------------------------------------------------------------
# Request logging
# ---------------------------------------------------------------------------
@app.before_request
def start_timer():
    g.start_time = time.time()


@app.after_request
def log_request(response):
    try:
        elapsed_ms = round((time.time() - g.start_time) * 1000, 2)
        entry = {
            "time": datetime.now(timezone.utc).isoformat(),
            "method": request.method,
            "path": request.path,
            "args": request.args.to_dict(),
            "status": response.status_code,
            "elapsed_ms": elapsed_ms,
        }
        logger.info(entry)
        RECENT_REQUESTS.append(entry)
        if len(RECENT_REQUESTS) > MAX_RECENT:
            RECENT_REQUESTS.pop(0)
    except Exception:
        pass
    return response


# ---------------------------------------------------------------------------
# Progress helpers
# ---------------------------------------------------------------------------
def get_progress():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT level, completed FROM progress ORDER BY level")
    rows = {r["level"]: bool(r["completed"]) for r in cur.fetchall()}
    conn.close()
    return rows


def mark_complete(level: int):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "UPDATE progress SET completed = 1, completed_at = ? WHERE level = ?",
        (datetime.now(timezone.utc).isoformat(), level),
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Core pages
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    progress = get_progress()
    return render_template("index.html", levels=LEVEL_META, progress=progress)


@app.route("/progress")
def progress_page():
    progress = get_progress()
    return render_template("progress.html", levels=LEVEL_META, progress=progress)


@app.route("/logs")
def logs_page():
    return render_template("logs.html", entries=list(reversed(RECENT_REQUESTS)))


@app.route("/reset", methods=["POST"])
def reset_lab():
    init_db(reset=True)
    session.clear()
    RECENT_REQUESTS.clear()
    return redirect(url_for("index"))


@app.route("/submit-flag/<int:level>", methods=["POST"])
def submit_flag(level):
    submitted = request.form.get("flag", "").strip()
    correct = FLAGS.get(level)
    result = "wrong"
    if correct and submitted == correct:
        mark_complete(level)
        result = "correct"
    return redirect(url_for(f"level{level}_page", result=result))


# ---------------------------------------------------------------------------
# Level 1 - Basic Authentication SQL Injection
# ---------------------------------------------------------------------------
@app.route("/level1", methods=["GET", "POST"], endpoint="level1_page")
def level1_page():
    rows, query, error, message, flag = [], None, None, None, None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        rows, query, error = level1.attempt_login(username, password)
        message = "Login successful!" if rows else "Invalid credentials."
        if rows and rows[0]["is_admin"]:
            flag = FLAGS[1]
    return render_template(
        "level1.html", rows=rows, query=query, error=error, message=message, flag=flag
    )


# ---------------------------------------------------------------------------
# Level 2 - UNION-based SQL Injection
# ---------------------------------------------------------------------------
@app.route("/level2", methods=["GET"], endpoint="level2_page")
def level2_page():
    q = request.args.get("q", "")
    rows, query, error = ([], None, None) if q == "" else level2.search_products(q)
    return render_template("level2.html", rows=rows, query=query, error=error, q=q)


# ---------------------------------------------------------------------------
# Level 3 - Database Enumeration
# ---------------------------------------------------------------------------
@app.route("/level3", methods=["GET"], endpoint="level3_page")
def level3_page():
    q = request.args.get("q", "")
    rows, query, error = ([], None, None) if q == "" else level3.search_products(q)
    return render_template("level3.html", rows=rows, query=query, error=error, q=q)


# ---------------------------------------------------------------------------
# Level 4 - Hidden Output
# ---------------------------------------------------------------------------
@app.route("/level4", methods=["GET"], endpoint="level4_page")
def level4_page():
    item_id = request.args.get("id", "")
    rows, query, error = ([], None, None) if item_id == "" else level4.get_item(item_id)
    return render_template(
        "level4.html", rows=rows, query=query, error=error, item_id=item_id
    )


# ---------------------------------------------------------------------------
# Level 5 - Boolean-based Blind SQL Injection
# ---------------------------------------------------------------------------
@app.route("/level5", methods=["GET"], endpoint="level5_page")
def level5_page():
    username = request.args.get("username", "")
    found, query = (False, None) if username == "" else level5.check_user(username)
    return render_template(
        "level5.html", found=found, query=query, username=username
    )


# ---------------------------------------------------------------------------
# Level 6 - Time-based Blind SQL Injection
# ---------------------------------------------------------------------------
@app.route("/level6", methods=["GET"], endpoint="level6_page")
def level6_page():
    username = request.args.get("username", "")
    elapsed, query = (
        (None, None) if username == "" else level6.check_user_timing(username)
    )
    return render_template(
        "level6.html", elapsed=elapsed, query=query, username=username
    )


# ---------------------------------------------------------------------------
# Level 7 - Filtered SQL Injection
# ---------------------------------------------------------------------------
@app.route("/level7", methods=["GET", "POST"], endpoint="level7_page")
def level7_page():
    rows, query, error, message = [], None, None, None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        rows, query, error = level7.login(username, password)
        if error:
            message = error
        else:
            message = "Login successful!" if rows else "Invalid credentials."
    return render_template(
        "level7.html", rows=rows, query=query, error=error, message=message
    )


# ---------------------------------------------------------------------------
# Level 8 - WAF Bypass
# ---------------------------------------------------------------------------
@app.route("/level8", methods=["GET", "POST"], endpoint="level8_page")
def level8_page():
    rows, query, error, message = [], None, None, None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        rows, query, error = level8.login(username, password)
        message = "Login successful!" if rows else "Invalid credentials."
    return render_template(
        "level8.html", rows=rows, query=query, error=error, message=message
    )


# ---------------------------------------------------------------------------
# Level 9 - Second-order SQL Injection
# ---------------------------------------------------------------------------
@app.route("/level9", methods=["GET", "POST"], endpoint="level9_page")
def level9_page():
    message = None
    if request.method == "POST":
        action = request.form.get("action")
        if action == "register":
            username = request.form.get("username", "")
            level9.register_username(username)
            message = "Registered. Your signup is now pending processing."
    return render_template("level9.html", message=message)


@app.route("/level9/process", methods=["POST"])
def level9_process():
    results = level9.process_pending_signups()
    return render_template("level9_results.html", results=results)


# ---------------------------------------------------------------------------
# Level 10 - Advanced Combined Challenge
# ---------------------------------------------------------------------------
@app.route("/level10", methods=["GET", "POST"], endpoint="level10_page")
def level10_page():
    message = None
    if request.method == "POST" and request.form.get("action") == "login":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        rows, query, error = level10.login(username, password)
        if rows:
            session["level10_logged_in"] = True
            session["level10_username"] = rows[0]["username"]
            message = f"Logged in as {rows[0]['username']}"
        else:
            message = error or "Invalid credentials."
    logged_in = session.get("level10_logged_in", False)
    return render_template(
        "level10.html", message=message, logged_in=logged_in, results=None
    )


@app.route("/level10/search", methods=["GET"])
def level10_search():
    if not session.get("level10_logged_in"):
        return redirect(url_for("level10_page"))
    code = request.args.get("code", "")
    rows, query, error = ([], None, None) if code == "" else level10.search_products(code)
    return render_template(
        "level10.html",
        message=None,
        logged_in=True,
        results={"rows": rows, "query": query, "error": error, "code": code},
    )


@app.route("/level10/logout", methods=["POST"])
def level10_logout():
    session.pop("level10_logged_in", None)
    session.pop("level10_username", None)
    return redirect(url_for("level10_page"))


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------
init_db(reset=False)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
