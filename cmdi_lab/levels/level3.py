"""
Level 3 - Hidden Parameter

Vulnerability
-------------
The form has two fields, `filename` and `format`. `filename` looks like the
dangerous one (it names a file!) but it is validated against a strict
allowlist regex and is never even passed to the shell - it only appears in
the human-readable label. `format` looks cosmetic (just an output
extension) but it is the value actually concatenated into the shell
command that "converts" the report.

Intended solution
------------------
Ignore `filename` and attack `format` instead, e.g.:

    format = txt; cat flags/level3.txt
"""
import re
import subprocess

from flask import Blueprint, render_template, request

bp = Blueprint("level3", __name__)

FILENAME_RE = re.compile(r"^[A-Za-z0-9_\-]{1,40}$")


@bp.route("/level3", methods=["GET", "POST"])
def view():
    output = None
    error = None
    filename = ""
    fmt = ""

    if request.method == "POST":
        filename = request.form.get("filename", "")
        fmt = request.form.get("format", "")

        if not FILENAME_RE.match(filename):
            error = "Invalid filename: only letters, numbers, - and _ are allowed."
        else:
            # `filename` is safely validated above and is not used in the
            # shell command at all - it's purely cosmetic here.
            #
            # VULNERABLE: `format` is never validated and is concatenated
            # directly (unquoted) into a shell command that "prepares" the
            # report. `filename` is single-quoted and therefore inert.
            command = f"echo 'preparing report for {filename}' as format: {fmt}"
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
            output = (result.stdout or "") + (result.stderr or "")

    return render_template(
        "level3.html", output=output, error=error, filename=filename, fmt=fmt
    )
