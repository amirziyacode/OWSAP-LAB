"""
Shared helpers for the Command Injection Lab.

IMPORTANT: This module intentionally contains helpers that make it easy to
write vulnerable code in each level. That is the point of the lab. None of
this should ever be copied into a real application.
"""
import hmac
import os
import uuid

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FLAGS_DIR = os.path.join(BASE_DIR, "flags")
LEVEL7_WORKDIR = os.path.join(BASE_DIR, "data", "level7_workdir")
VALID_LEVELS = tuple(f"level{i}" for i in range(1, 9))


def read_flag(level_name: str) -> str:
    path = os.path.join(FLAGS_DIR, f"{level_name}.txt")
    with open(path, "r") as f:
        return f.read().strip()


def check_flag(level_name: str, submitted: str) -> bool:
    if level_name not in VALID_LEVELS:
        return False
    expected = read_flag(level_name)
    candidate = (submitted or "").strip()
    if len(candidate) != len(expected):
        return False
    return hmac.compare_digest(candidate, expected)


def new_job_id() -> str:
    """Unpredictable job id (level 8)."""
    return uuid.uuid4().hex


def safe_join_workdir(filename: str) -> str | None:
    """
    Resolve `filename` against LEVEL7_WORKDIR and refuse to return a path
    that escapes it (basic path-traversal guard). Returns None if the
    resolved path is outside the working directory.

    NOTE: this only guards the *filename* parameter. Level 7's vulnerability
    lives in the *operation* parameter, which this function does not touch.
    """
    candidate = os.path.normpath(os.path.join(LEVEL7_WORKDIR, filename))
    workdir_real = os.path.realpath(LEVEL7_WORKDIR)
    candidate_real = os.path.realpath(candidate)
    if os.path.commonpath([workdir_real, candidate_real]) != workdir_real:
        return None
    return candidate


def contains_any(value: str, needles) -> bool:
    return any(n in value for n in needles)
