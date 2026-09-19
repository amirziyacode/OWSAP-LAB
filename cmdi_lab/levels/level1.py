"""
Level 1 - Basic Command Injection

Vulnerability
-------------
The `host` field is dropped straight into a shell string and executed with
`shell=True`. There is no validation and no quoting at all, so any shell
metacharacter (`;`, `|`, `&&`, backticks, `$()`, ...) lets the player run
arbitrary commands.

Intended solution
------------------
Submit something like:
    127.0.0.1; cat flags/level1.txt
or
    127.0.0.1 && cat flags/level1.txt
"""
import subprocess

from flask import Blueprint, render_template, request

bp = Blueprint("level1", __name__)


@bp.route("/level1", methods=["GET", "POST"])
def view():
    output = None
    error = None
    host = ""

    if request.method == "POST":
        host = request.form.get("host", "")

        # VULNERABLE: user input concatenated directly into a shell command.
        command = f"ping -c 1 -W 1 {host}"
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
            output = (result.stdout or "") + (result.stderr or "")
        except subprocess.TimeoutExpired:
            error = "Command timed out."

    return render_template("level1.html", output=output, error=error, host=host)
