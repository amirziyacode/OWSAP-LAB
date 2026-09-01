"""
Level 7 — CSP-protected page that still has a DOM XSS.

The page ships a real, restrictive Content-Security-Policy with a
per-request nonce:

    script-src 'self' 'nonce-<random>' 'unsafe-eval'; object-src 'none'; base-uri 'self';

This blocks the simplest attack (injecting your own <script>alert(1)</script>
or an onerror= handler) because attacker-supplied markup has no valid nonce
and CSP refuses to run it.

INTENTIONAL VULNERABILITY:
The page also ships its own first-party inline script that legitimately
carries the nonce (so CSP allows it to run). That trusted script reads a
`?theme=` query parameter and unsafely passes it to eval() to "apply" a
theme. Because 'unsafe-eval' is present in the policy (a realistic but
risky CSP misconfiguration some legacy apps carry), an attacker who
controls the *data* fed into that already-trusted script can still achieve
script execution without ever needing to inject a new <script> tag of
their own -- they just need to break out of the string being eval()'d.
"""

import os
from flask import Blueprint, render_template, request, make_response

from levels.config import get_level
from levels.progress import get_flag_if_completed

bp = Blueprint("level7", __name__, url_prefix="/level7")


@bp.route("/")
def index():
    level = get_level("level7")
    nonce = os.urandom(16).hex()
    theme = request.args.get("theme", "dark")

    resp = make_response(
        render_template(
            "level7.html",
            level=level,
            flag=get_flag_if_completed("level7"),
            nonce=nonce,
            theme=theme,
        )
    )

    # Real, restrictive CSP -- this is what makes Level 7 harder than the
    # earlier reflected/DOM levels. 'unsafe-eval' is included because the
    # (badly written) first-party script below relies on eval(); this
    # mirrors real apps that carry 'unsafe-eval' for legacy reasons and
    # thereby weaken an otherwise strong CSP.
    resp.headers["Content-Security-Policy"] = (
        f"default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}' 'unsafe-eval'; "
        f"object-src 'none'; base-uri 'self'; "
        f"style-src 'self' 'unsafe-inline'"
    )
    return resp
