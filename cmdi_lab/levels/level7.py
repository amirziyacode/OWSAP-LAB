"""
Level 7 - File Processing Service

Vulnerability
-------------
Two form fields: `filename` and `operation`.

`filename` is properly defended: it's resolved against a fixed working
directory with `safe_join_workdir()`, which rejects any path that would
escape that directory (path traversal via `../`, absolute paths, etc.).

`operation` is meant to select one of a small set of `file(1)` flags
("info", "mime", "encoding") but instead of mapping it through a fixed
dictionary, the developer formatted it straight into the shell command,
assuming users would only ever send one of the three expected values.
That assumption is the bug - `operation` is the truly unsafe field, even
though `filename` is the one that "looks" file-system-dangerous.

Intended solution
------------------
Send a legitimate filename (e.g. `notes.txt`) together with an `operation`
value that breaks out of the intended flag position. The shell command
runs with its cwd set to the working directory, so the flag is reached
with a relative path two levels up:

    operation = brief; cat ../../flags/level7.txt #
"""
import subprocess

from flask import Blueprint, render_template, request

from .utils import LEVEL7_WORKDIR, safe_join_workdir

bp = Blueprint("level7", __name__)

KNOWN_OPERATIONS = {"info", "mime", "encoding"}


@bp.route("/level7", methods=["GET", "POST"])
def view():
    output = None
    error = None
    filename = ""
    operation = ""

    if request.method == "POST":
        filename = request.form.get("filename", "")
        operation = request.form.get("operation", "")

        # SAFE: filename is confined to the working directory.
        filepath = safe_join_workdir(filename)
        if filepath is None:
            error = "Rejected: filename must refer to a file inside the working directory."
        else:
            # VULNERABLE: `operation` is expected to be one of
            # KNOWN_OPERATIONS but is never actually checked against that
            # set before being formatted into the shell command below.
            flag = {
                "info": "brief",
                "mime": "mime-type",
                "encoding": "mime-encoding",
            }.get(operation, operation)  # falls through to raw user input

            command = f"file --{flag} '{filepath}'"
            try:
                result = subprocess.run(
                    command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    cwd=LEVEL7_WORKDIR,
                )
                output = (result.stdout or "") + (result.stderr or "")
            except subprocess.TimeoutExpired:
                error = "Command timed out."

    return render_template(
        "level7.html", output=output, error=error, filename=filename, operation=operation
    )
