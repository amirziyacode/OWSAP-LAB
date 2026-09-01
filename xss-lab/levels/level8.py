"""
Level 8 — Realistic multi-step XSS attack chain.

Mimics a small forum:
  * Login (alice / lab-password-1, or register your own throwaway account)
  * Profile bio
  * Comments on an "Announcements" post
  * A simulated admin who periodically reviews new comments there
  * Notifications

INTENTIONAL VULNERABILITY:
Each comment shows a small "preview card" with the author's bio, rendered
with |safe (unescaped). A learner needs to chain two steps: (1) stash a
payload in their own profile bio, (2) post a comment on the Announcements
post so the admin's periodic review renders that bio preview inside the
admin's own session. That gives the payload admin-context execution,
which it uses to call a privileged, session-authenticated API endpoint
(/level8/api/promote) that only an admin session is supposed to be able to
call meaningfully -- demonstrating real-world impact beyond a plain alert().
"""

from functools import wraps
from flask import Blueprint, render_template, request, redirect, url_for, session, flash, jsonify

from database.db import query, execute
from levels.config import get_level
from levels.progress import get_flag_if_completed, mark_complete
from levels.xss_detect import looks_executable

bp = Blueprint("level8", __name__, url_prefix="/level8")

ANNOUNCEMENTS_TITLE = "Community Announcements"


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("level8_user_id"):
            flash("Please log in first.")
            return redirect(url_for("level8.login"))
        return view(*args, **kwargs)
    return wrapped


def get_announcements_post():
    rows = query("SELECT * FROM posts WHERE level = 'level8' LIMIT 1")
    return rows[0] if rows else None


def get_user_by_username(username):
    rows = query("SELECT * FROM users WHERE username = ?", (username,))
    return rows[0] if rows else None


def get_profile(user_id):
    rows = query("SELECT * FROM profiles WHERE user_id = ?", (user_id,))
    return rows[0] if rows else None


@bp.route("/login", methods=["GET", "POST"])
def login():
    level = get_level("level8")
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        user = get_user_by_username(username)
        # Parameterized lookup + plain equality check -- this lab is about
        # XSS, not auth bypass, so login itself is intentionally simple.
        if user and user["password"] == password:
            session["level8_user_id"] = user["id"]
            session["level8_username"] = user["username"]
            session["level8_role"] = user["role"]
            return redirect(url_for("level8.index"))
        flash("Invalid credentials.")
    return render_template("level8_login.html", level=level)


@bp.route("/logout")
def logout():
    for k in ("level8_user_id", "level8_username", "level8_role"):
        session.pop(k, None)
    return redirect(url_for("level8.index"))


@bp.route("/")
def index():
    level = get_level("level8")
    post = get_announcements_post()
    comments = []
    if post:
        raw_comments = query(
            "SELECT c.*, p.bio as author_bio FROM comments c "
            "LEFT JOIN users u ON u.username = c.author "
            "LEFT JOIN profiles p ON p.user_id = u.id "
            "WHERE c.level = 'level8' AND c.post_id = ? ORDER BY c.id",
            (post["id"],),
        )
        comments = raw_comments

    return render_template(
        "level8.html",
        level=level,
        flag=get_flag_if_completed("level8"),
        post=post,
        comments=comments,
        current_user=session.get("level8_username"),
        role=session.get("level8_role"),
    )


@bp.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    level = get_level("level8")
    user_id = session["level8_user_id"]

    if request.method == "POST":
        bio = request.form.get("bio", "")
        existing = get_profile(user_id)
        if existing:
            execute("UPDATE profiles SET bio = ? WHERE user_id = ?", (bio, user_id))
        else:
            execute(
                "INSERT INTO profiles (user_id, display_name, bio) VALUES (?, ?, ?)",
                (user_id, session["level8_username"], bio),
            )
        flash("Bio updated.")
        return redirect(url_for("level8.profile"))

    prof = get_profile(user_id)
    return render_template("level8_profile.html", level=level, profile=prof)


@bp.route("/comment", methods=["POST"])
@login_required
def add_comment():
    post = get_announcements_post()
    body = request.form.get("body", "")
    if not body.strip():
        flash("Comment cannot be empty.")
        return redirect(url_for("level8.index"))

    execute(
        "INSERT INTO comments (level, post_id, author, body) VALUES (?, ?, ?, ?)",
        ("level8", post["id"], session["level8_username"], body),
    )

    simulate_admin_review(post["id"])
    return redirect(url_for("level8.index"))


@bp.route("/api/promote", methods=["POST"])
def api_promote():
    """
    A privileged, session-authenticated action. In this lab it simply
    records a notification and (if called from within a simulated admin
    context) marks the level complete -- standing in for a real
    high-impact admin action a genuine attack chain might trigger, such as
    creating a new admin account or exfiltrating data.
    """
    if session.get("level8_role") != "admin":
        return jsonify({"error": "forbidden"}), 403

    execute(
        "INSERT INTO notifications (recipient, body) VALUES (?, ?)",
        ("admin", "Privileged action triggered via /level8/api/promote"),
    )
    mark_complete("level8")
    return jsonify({"status": "ok"})


def simulate_admin_review(post_id: int):
    """
    Stand-in for: the admin periodically loads the Announcements page in
    their own authenticated browser session. If any comment's author bio
    preview would execute script, we simulate that script running inside
    an admin session (i.e. we simulate it calling the privileged endpoint).
    """
    comments = query(
        "SELECT c.*, p.bio as author_bio FROM comments c "
        "LEFT JOIN users u ON u.username = c.author "
        "LEFT JOIN profiles p ON p.user_id = u.id "
        "WHERE c.level = 'level8' AND c.post_id = ? ORDER BY c.id",
        (post_id,),
    )
    for c in comments:
        bio = c["author_bio"] or ""
        if looks_executable(bio):
            # The bio preview would have executed in the admin's browser.
            execute(
                "INSERT INTO notifications (recipient, body) VALUES (?, ?)",
                ("admin", f"Reviewed comment from {c['author']}"),
            )
            mark_complete("level8")
            return
