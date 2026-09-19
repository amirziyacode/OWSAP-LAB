r"""
Level 6 - Shell Parsing / Expansion

Vulnerability
-------------
Two layers of defense sit in front of the shell call:

  1. A regex allowlist that only permits letters, digits, `. - / $ { } ( )`.
  2. A blacklist that explicitly rejects `; & | \` <space> <newline> <CR>`.

Both layers were written with "command separators" in mind (`;`, `&&`,
`|`, newline) and both happen to still allow `$`, `(`, `)`, `{`, `}` and
`/` through - the author assumed those were harmless punctuation for
hostnames. They are not: together they are exactly what's needed for
POSIX command substitution, and `${IFS}` (the shell's internal field
separator variable) expands to whitespace, which sidesteps the fact that
literal spaces are blocked.

Intended solution
------------------
Because *no command separator is needed at all* here, a basic `; ls`
style payload will always be rejected. The working payload instead relies
on command substitution combined with the `${IFS}` trick to avoid the
space character entirely:

    $(cat${IFS}flags/level6.txt)

The shell expands `${IFS}` to a space before running `cat flags/level6.txt`
inside the substitution, then splices the flag's contents into the ping
command as the "hostname" - which shows up in the ping error output.
"""
import re
import subprocess

from flask import Blueprint, render_template, request

bp = Blueprint("level6", __name__)

# Layer 1: allowlist regex. Looks strict, but still permits $ ( ) { } /
# which is all that's needed for command substitution + ${IFS}.
ALLOWED_RE = re.compile(r"^[A-Za-z0-9./\-${}()]+$")

# Layer 2: blacklist of "classic" separators. Redundant with the regex for
# most cases, but conceptually distinct - and still misses the expansion
# trick above entirely.
BLACKLIST = [";", "&", "|", "`", "\n", "\r", " "]


def is_valid_host(value: str) -> bool:
    if not value:
        return False
    if not ALLOWED_RE.match(value):
        return False
    if any(bad in value for bad in BLACKLIST):
        return False
    return True


@bp.route("/level6", methods=["GET", "POST"])
def view():
    output = None
    error = None
    host = ""

    if request.method == "POST":
        host = request.form.get("host", "")

        if not is_valid_host(host):
            error = "Rejected: input failed validation."
        else:
            # VULNERABLE: passes validation above but the shell still
            # performs command substitution and ${IFS} expansion on it.
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

    return render_template("level6.html", output=output, error=error, host=host)
