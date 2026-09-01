"""
Level 6 — Filter / blacklist bypass.

Vulnerability: comments are checked against a small, case-insensitive
substring blacklist before being stored, but the stored value is still
rendered completely unescaped (same |safe rendering bug as Level 2). The
blacklist only knows about a handful of well-known bad patterns, which is
exactly why blacklists are a weak defense — there are many equivalent ways
to achieve script execution that a short list of strings can't anticipate.
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash

from database.db import query, execute
from levels.config import get_level
from levels.progress import get_flag_if_completed, mark_complete
from levels.xss_detect import looks_executable

bp = Blueprint("level6", __name__, url_prefix="/level6")

# INTENTIONAL VULNERABILITY:
# This is a classic weak blacklist: a short, incomplete list of substrings.
# It blocks the most obvious payload patterns but has no understanding of
# HTML/JS parsing, so it can't anticipate every tag/attribute combination
# that executes script.
BLACKLIST = ["<script", "onerror", "onload", "javascript:"]


def is_blocked(body: str) -> bool:
    lowered = body.lower()
    return any(bad in lowered for bad in BLACKLIST)


@bp.route("/")
def index():
    level = get_level("level6")
    comments = query(
        "SELECT * FROM comments WHERE level = 'level6' ORDER BY id"
    )
    return render_template(
        "level6.html",
        level=level,
        flag=get_flag_if_completed("level6"),
        comments=comments,
    )


@bp.route("/comment", methods=["POST"])
def add_comment():
    author = request.form.get("author", "anonymous").strip()[:50] or "anonymous"
    body = request.form.get("body", "")

    if not body.strip():
        flash("Comment cannot be empty.")
        return redirect(url_for("level6.index"))

    if is_blocked(body):
        flash("Your comment was blocked: it matched a disallowed pattern.")
        return redirect(url_for("level6.index"))

    execute(
        "INSERT INTO comments (level, post_id, author, body) VALUES (?, NULL, ?, ?)",
        ("level6", author, body),
    )

    simulate_admin_review()
    return redirect(url_for("level6.index"))


def simulate_admin_review():
    comments = query("SELECT * FROM comments WHERE level = 'level6' ORDER BY id")
    for c in comments:
        if looks_executable(c["body"]):
            mark_complete("level6")
            return
