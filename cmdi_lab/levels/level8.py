"""
Level 8 - Asynchronous Diagnostic Job System

Vulnerability
-------------
`POST /level8` accepts a small JSON-like config (just a `host` field for
this lab), stores it under an unpredictable job id, and returns
immediately - the request never touches the shell directly. A background
worker thread (no Celery/Redis, just `threading`) picks the job up,
builds a shell command from the stored `host` value exactly like level 1,
and writes whatever the command produces to a local per-job log file.

The player has to:
  1. discover that `host` is the vulnerable field,
  2. submit a job with an injected payload,
  3. poll `/level8/job/<job_id>` until the worker reports `done`,
  4. fetch `/level8/log/<job_id>` to read the captured output.

Intended solution
------------------
POST host = `127.0.0.1; cat flags/level8.txt`, then poll the job and read
its log once finished. The flag shows up in the log because the injected
command's stdout is captured right alongside the ping output.
"""
import subprocess
import threading
import time

from flask import Blueprint, abort, jsonify, render_template, request

from .utils import new_job_id

bp = Blueprint("level8", __name__)

_jobs = {}
_lock = threading.Lock()


def _run_job(job_id: str, host: str):
    with _lock:
        _jobs[job_id]["status"] = "running"

    # Simulate a bit of queueing/processing latency, like a real worker.
    time.sleep(1.5)

    # VULNERABLE: the stored, user-controlled `host` value is concatenated
    # directly into a shell command with no sanitization, run entirely out
    # of band from the original HTTP request.
    command = f"ping -c 1 -W 1 {host}"
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=15,
        )
        log_output = (result.stdout or "") + (result.stderr or "")
    except subprocess.TimeoutExpired:
        log_output = "[worker] command timed out\n"

    with _lock:
        _jobs[job_id]["status"] = "done"
        _jobs[job_id]["log"] = log_output


@bp.route("/level8", methods=["GET", "POST"])
def view():
    job_id = None
    if request.method == "POST":
        host = request.form.get("host", "")
        job_id = new_job_id()
        with _lock:
            _jobs[job_id] = {"status": "queued", "log": ""}
        thread = threading.Thread(target=_run_job, args=(job_id, host), daemon=True)
        thread.start()

    return render_template("level8.html", job_id=job_id)


@bp.route("/level8/job/<job_id>", methods=["GET"])
def job_status(job_id):
    with _lock:
        job = _jobs.get(job_id)
    if job is None:
        abort(404)
    return jsonify({"job_id": job_id, "status": job["status"]})


@bp.route("/level8/log/<job_id>", methods=["GET"])
def job_log(job_id):
    with _lock:
        job = _jobs.get(job_id)
    if job is None:
        abort(404)
    if job["status"] != "done":
        return jsonify({"job_id": job_id, "status": job["status"], "log": None})
    return jsonify({"job_id": job_id, "status": job["status"], "log": job["log"]})
