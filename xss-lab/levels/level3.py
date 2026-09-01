"""
Level 3 — Attribute-context XSS in a profile settings page.

Vulnerability: the display name is placed inside value="..." on an <input>
by string-formatting it directly into the HTML, only escaping enough to
avoid breaking normal usage (nothing at all, in fact) rather than properly
HTML-attribute-encoding it. A learner who only escapes for HTML *text*
content (encoding < and >) will find that's insufficient here — the real
issue is the unescaped double quote.
"""

from flask import Blueprint, render_template, request, session
from markupsafe import Markup

from levels.config import get_level
from levels.progress import get_flag_if_completed

bp = Blueprint("level3", __name__, url_prefix="/level3")

DEFAULT_NAME = "Alice"

INPUT_FRAGMENT = '<input type="text" name="display_name" value="{name}">'


@bp.route("/", methods=["GET", "POST"])
def index():
    level = get_level("level3")

    if request.method == "POST":
        session["level3_name"] = request.form.get("display_name", DEFAULT_NAME)

    name = session.get("level3_name", DEFAULT_NAME)

    # INTENTIONAL VULNERABILITY:
    # `name` is spliced directly into an HTML attribute with no attribute
    # encoding at all. Encoding < and > (as many naive fixes do) would NOT
    # be sufficient here even if applied — a literal double-quote is enough
    # to close the attribute and start a new one (e.g. autofocus onfocus=...).
    # NOTE: plain str.format() is used (not Markup.format()) because
    # Markup.format() auto-escapes interpolated values, which would
    # accidentally "fix" this intentionally vulnerable level.
    raw_html = INPUT_FRAGMENT.format(name=name)
    input_html = Markup(raw_html)

    return render_template(
        "level3.html",
        level=level,
        flag=get_flag_if_completed("level3"),
        input_html=input_html,
        name=name,
    )
