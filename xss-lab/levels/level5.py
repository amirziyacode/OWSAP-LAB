"""
Level 5 — XSS inside a JavaScript string literal.

Vulnerability: the username is interpolated directly into an inline
<script> block as a JS string, with HTML-encoding applied (which is the
wrong defense for this context) instead of JavaScript-string escaping.
Encoding < and > does nothing to stop a double-quote from terminating the
string literal.
"""

from flask import Blueprint, render_template, request, session
from markupsafe import Markup

from levels.config import get_level
from levels.progress import get_flag_if_completed

bp = Blueprint("level5", __name__, url_prefix="/level5")

DEFAULT_USERNAME = "guest"

SCRIPT_FRAGMENT = """
<script>
    // Server-rendered greeting logic
    const username = "{username}";
    document.getElementById("greeting").textContent = "Welcome back, " + username + "!";
</script>
"""


@bp.route("/", methods=["GET", "POST"])
def index():
    level = get_level("level5")

    if request.method == "POST":
        session["level5_username"] = request.form.get("username", DEFAULT_USERNAME)

    username = session.get("level5_username", DEFAULT_USERNAME)

    # INTENTIONAL VULNERABILITY:
    # `escape()` HTML-encodes the value (turns " into &#34; only in some
    # escaping schemes -- MarkupSafe's escape() *does* encode quotes for
    # HTML-attribute safety, but here the value is being placed inside a
    # <script> block, a completely different context with different escaping
    # rules). Because the surrounding template renders this fragment via
    # Markup() (bypassing Jinja2 autoescaping) and the developer only ever
    # thought about the HTML-text case, no JavaScript-string escaping
    # (backslash-escaping quotes, backslashes, newlines, </script>, etc.)
    # is ever applied. If MarkupSafe's HTML attribute escaping happens to
    # neutralize a given payload it is incidental, not a real fix -- see
    # solutions/level5.md for payloads that still work.
    username_for_js = str(username).replace("<", "").replace(">", "")
    script_html = Markup(SCRIPT_FRAGMENT.format(username=username_for_js))

    return render_template(
        "level5.html",
        level=level,
        flag=get_flag_if_completed("level5"),
        script_html=script_html,
        username=username,
    )
