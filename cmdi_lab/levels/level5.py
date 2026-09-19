"""
Level 5 - Argument Injection

Vulnerability
-------------
This level never touches a shell (`shell=False` throughout), so classic
metacharacters like `;` or `|` do nothing here - `subprocess` passes them
to the target program as literal, inert bytes.

The bug is different: the "search pattern" field is tokenized with
`shlex.split()` and the resulting tokens are appended directly onto the
argv list that gets handed to the `find` utility:

    args = ["find", SEARCH_DIR, "-type", "f", "-name"] + shlex.split(pattern)
    subprocess.run(args, shell=False)

Because the user fully controls those extra argv tokens, they can inject
*new flags* that `find` itself understands - most notably `-exec`, which
tells `find` to run an arbitrary program for each match.

Intended solution
------------------
Submit a pattern such as:

    * -exec cat /app/flags/level5.txt ;

which expands the argv list to:

    find <SEARCH_DIR> -type f -name * -exec cat /app/flags/level5.txt ;

`find` happily runs the injected `-exec` clause - no shell metacharacters
were ever needed.
"""
import os
import shlex
import subprocess

from flask import Blueprint, render_template, request

from .utils import BASE_DIR

bp = Blueprint("level5", __name__)

SEARCH_DIR = os.path.join(BASE_DIR, "data", "level7_workdir")


@bp.route("/level5", methods=["GET", "POST"])
def view():
    output = None
    error = None
    pattern = ""

    if request.method == "POST":
        pattern = request.form.get("pattern", "")

        try:
            extra_args = shlex.split(pattern) if pattern else ["*"]
        except ValueError as exc:
            extra_args = None
            error = f"Could not parse pattern: {exc}"

        if extra_args is not None:
            # VULNERABLE: user-controlled tokens are appended straight onto
            # the argv list, letting the player inject new `find` flags
            # (e.g. -exec) rather than just a filename pattern.
            args = ["find", SEARCH_DIR, "-type", "f", "-name"] + extra_args
            try:
                result = subprocess.run(
                    args,
                    shell=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                output = (result.stdout or "") + (result.stderr or "")
            except subprocess.TimeoutExpired:
                error = "Command timed out."
            except FileNotFoundError:
                error = "Search utility not found."

    return render_template("level5.html", output=output, error=error, pattern=pattern)
