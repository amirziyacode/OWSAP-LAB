"""
Level 1 — Reflected XSS in a product search feature.

Vulnerability: the ?q= search term is reflected into the results heading
using Markup()/render_template_string with the raw value spliced directly
into the HTML string, instead of being auto-escaped by Jinja2.
"""

from flask import Blueprint, render_template, request, render_template_string
from markupsafe import Markup

from levels.config import get_level
from levels.progress import get_flag_if_completed

bp = Blueprint("level1", __name__, url_prefix="/level1")

PRODUCTS = [
    "Mechanical Keyboard",
    "USB-C Hub",
    "27in Monitor",
    "Wireless Mouse",
    "Noise Cancelling Headphones",
]

# This fragment is rendered with the query already interpolated into the
# HTML string below, then marked Markup() so Jinja2 will NOT re-escape it.
RESULTS_FRAGMENT = """
<div class="panel">
  <h3>Search results for: {query}</h3>
  <ul>
  {items}
  </ul>
</div>
"""


@bp.route("/")
def index():
    level = get_level("level1")
    return render_template(
        "level1.html",
        level=level,
        flag=get_flag_if_completed("level1"),
        results_html=None,
        q="",
    )


@bp.route("/search")
def search():
    level = get_level("level1")
    q = request.args.get("q", "")

    matches = [p for p in PRODUCTS if q.lower() in p.lower()] if q else PRODUCTS
    items_html = "".join(f"<li>{escape_product(p)}</li>" for p in matches)

    # INTENTIONAL VULNERABILITY:
    # `q` is spliced directly into the HTML fragment and the whole fragment
    # is wrapped in Markup(), which tells Jinja2 "this is already safe HTML,
    # do not escape it." A real implementation must not do this with
    # user-controlled input — it should let Jinja2's autoescaping handle `q`
    # (i.e. use {{ q }} in the template) or explicitly HTML-encode it.
    results_html = Markup(RESULTS_FRAGMENT.format(query=q, items=items_html))

    return render_template(
        "level1.html",
        level=level,
        flag=get_flag_if_completed("level1"),
        results_html=results_html,
        q=q,
    )


def escape_product(name: str) -> str:
    # Static product names are safe, but we still escape defensively.
    return (
        name.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
