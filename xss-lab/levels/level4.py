"""
Level 4 — DOM-based XSS.

Vulnerability lives entirely in static/js/level4.js: the page reads
window.location.hash (a #name=... fragment that never reaches the server)
and writes it into the DOM via innerHTML instead of textContent. The Flask
route below just serves the static page and current flag status; the
server never sees the payload at all, which is the point of this level.
"""

from flask import Blueprint, render_template

from levels.config import get_level
from levels.progress import get_flag_if_completed

bp = Blueprint("level4", __name__, url_prefix="/level4")


@bp.route("/")
def index():
    level = get_level("level4")
    return render_template(
        "level4.html",
        level=level,
        flag=get_flag_if_completed("level4"),
    )
