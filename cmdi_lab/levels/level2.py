"""
Level 2 - Blind Command Injection

Vulnerability
-------------
`POST /level2` kicks off a background diagnostic (a shell ping) built the
same unsafe way as level 1, but the raw output is never returned to the
client - only a job id. The player has to prove code execution blindly.

Intended solution
------------------
Classic time-based blind injection: inject a sleep alongside the ping, e.g.

    127.0.0.1; sleep 6

then poll `/level2/status?job_id=...`. A normal ping finishes in well under
a second; if the job takes noticeably longer than the configured threshold,
that proves the injected command actually ran on the server, and the status
endpoint reveals the flag as the "proof of execution" reward.
"""
import subprocess
import threading
import time

from flask import Blueprint, jsonify, render_template, request

from .utils import new_job_id, read_flag

bp = Blueprint("level2", __name__)

SLOW_THRESHOLD_SECONDS = 4.0

_jobs = {}
_lock = threading.Lock()


def _run_job(job_id: str, host: str):
    start = time.monotonic()
    with _lock:
        _jobs[job_id]["status"] = "running"

    # VULNERABLE: same unsanitized shell concatenation as level 1, but the
    # output is discarded - only timing/side effects are observable.
    command = f"ping -c 1 -W 1 {host}"
    try:
        subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except subprocess.TimeoutExpired:
        pass

    duration = time.monotonic() - start
    with _lock:
        _jobs[job_id]["status"] = "done"
        _jobs[job_id]["duration"] = round(duration, 2)


@bp.route("/level2", methods=["GET", "POST"])
def view():
    job_id = None
    if request.method == "POST":
        host = request.form.get("host", "")
        job_id = new_job_id()
        with _lock:
            _jobs[job_id] = {"status": "queued", "duration": None}
        thread = threading.Thread(target=_run_job, args=(job_id, host), daemon=True)
        thread.start()

    return render_template("level2.html", job_id=job_id)


@bp.route("/level2/status", methods=["GET"])
def status():
    job_id = request.args.get("job_id", "")
    with _lock:
        job = _jobs.get(job_id)

    if job is None:
        return jsonify({"error": "unknown job_id"}), 404

    response = {"status": job["status"], "duration": job["duration"]}

    if job["status"] == "done" and job["duration"] is not None:
        if job["duration"] >= SLOW_THRESHOLD_SECONDS:
            response["flag"] = read_flag("level2")

    return jsonify(response)
