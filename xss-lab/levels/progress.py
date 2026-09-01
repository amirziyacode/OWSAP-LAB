"""
Tracks which levels a given lab session has completed.

Completion is recorded server-side (SQLite), keyed by a random per-browser
session id (a Flask session cookie value, not a security-sensitive secret —
this is a single-player local trainer). Flags are only released through
get_flag_if_completed().
"""

import uuid
from flask import session

from database.db import query, execute
from levels.config import get_level


def get_session_id() -> str:
    if "lab_session_id" not in session:
        session["lab_session_id"] = uuid.uuid4().hex
    return session["lab_session_id"]


def mark_complete(level_id: str) -> bool:
    """Record completion. Returns True if this call newly completed the level."""
    sid = get_session_id()
    already = query(
        "SELECT 1 FROM progress WHERE session_id = ? AND level = ?", (sid, level_id)
    )
    if already:
        return False
    execute(
        "INSERT INTO progress (session_id, level) VALUES (?, ?)", (sid, level_id)
    )
    return True


def is_complete(level_id: str) -> bool:
    sid = get_session_id()
    rows = query(
        "SELECT 1 FROM progress WHERE session_id = ? AND level = ?", (sid, level_id)
    )
    return bool(rows)


def completed_levels() -> set:
    sid = get_session_id()
    rows = query("SELECT level FROM progress WHERE session_id = ?", (sid,))
    return {r["level"] for r in rows}


def get_flag_if_completed(level_id: str):
    """Only returns the real flag string once the level is actually marked complete."""
    if is_complete(level_id):
        return get_level(level_id).flag
    return None


def reset_progress() -> None:
    sid = get_session_id()
    execute("DELETE FROM progress WHERE session_id = ?", (sid,))
