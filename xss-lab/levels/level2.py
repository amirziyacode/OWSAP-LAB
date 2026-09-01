"""
Level 2 — Stored XSS in a blog's comment feature.

Vulnerability: comment bodies are stored verbatim in SQLite (parameterized
INSERT — that part is fine) and rendered back with Jinja2's |safe filter,
so any HTML/JS in a comment executes for every visitor who loads the post,
including a simulated admin who periodically reviews new comments.
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash

from database.db import query, execute
from levels.config import get_level
from levels.progress import get_flag_if_completed, mark_complete
from levels.xss_detect import looks_executable

bp = Blueprint("level2", __name__, url_prefix="/level2")

POST_TITLE = "Welcome to the Lab Blog"


def get_post():
    rows = query("SELECT * FROM posts WHERE level = 'level2' LIMIT 1")
    return rows[0] if rows else None


@bp.route("/")
def index():
    level = get_level("level2")
    post = get_post()
    comments = query(
        "SELECT * FROM comments WHERE level = 'level2' AND post_id = ? ORDER BY id",
        (post["id"],),
    ) if post else []
    return render_template(
        "level2.html",
        level=level,
        flag=get_flag_if_completed("level2"),
        post=post,
        comments=comments,
    )


@bp.route("/comment", methods=["POST"])
def add_comment():
    post = get_post()
    author = request.form.get("author", "anonymous").strip()[:50] or "anonymous"
    body = request.form.get("body", "")

    if not body.strip():
        flash("Comment cannot be empty.")
        return redirect(url_for("level2.index"))

    # Parameterized insert — storage itself is not the vulnerability.
    execute(
        "INSERT INTO comments (level, post_id, author, body) VALUES (?, ?, ?, ?)",
        ("level2", post["id"], author, body),
    )

    # Simulate the admin reviewing newly posted comments shortly after they
    # appear (in a real app this would be an actual person loading the page
    # in their own authenticated browser).
    simulate_admin_review(post["id"])

    return redirect(url_for("level2.index"))


def simulate_admin_review(post_id: int):
    """A stand-in for 'the admin later visits the comments page'."""
    comments = query(
        "SELECT * FROM comments WHERE level = 'level2' AND post_id = ? ORDER BY id",
        (post_id,),
    )
    for c in comments:
        if looks_executable(c["body"]):
            mark_complete("level2")
            return
