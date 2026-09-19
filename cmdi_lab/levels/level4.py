r"""
Level 4 - Blacklist Bypass

Vulnerability
-------------
Before building the shell command, the host value is checked against a
blacklist of "dangerous" characters: `; & | ` $ ( ) < >`. That blocks the
obvious payloads from level 1. But the blacklist forgets that a newline
character (`\n`) also separates commands in a shell script, so a payload
containing a raw newline sails right through the filter untouched.

Intended solution
------------------
Send a host value containing an actual newline byte (not the two
characters `\` and `n`) followed by a command, e.g. via curl:

    curl --data-urlencode 'host=127.0.0.1
cat flags/level4.txt' http://127.0.0.1:5000/level4

This demonstrates why naive blacklists rarely enumerate every way a shell
can be told "the current command is over, start a new one".
"""
import subprocess

from flask import Blueprint, render_template, request

bp = Blueprint("level4", __name__)

# Looks thorough, but incomplete: no '\n', no '\r', nothing about $IFS,
# nothing about wildcard/glob expansion.
BLACKLIST = [";", "&", "|", "`", "$", "(", ")", "<", ">"]


def is_blacklisted(value: str) -> bool:
    return any(bad in value for bad in BLACKLIST)


@bp.route("/level4", methods=["GET", "POST"])
def view():
    output = None
    error = None
    host = ""

    if request.method == "POST":
        host = request.form.get("host", "")

        if is_blacklisted(host):
            error = "Rejected: input contains a disallowed character."
        else:
            # VULNERABLE: the blacklist above is incomplete (no newline
            # handling), so a newline-separated second command still runs.
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

    return render_template("level4.html", output=output, error=error, host=host)
