"""
XSS Security Lab — main application entrypoint.

Local-only educational XSS training platform, similar in spirit to
PortSwigger Web Security Academy labs. Every level contains an
intentionally introduced vulnerability -- see levels/levelN.py and
solutions/levelN.md for details. Do not deploy this application anywhere
other than localhost/a local container.
"""

import argparse
import os

from flask import Flask, render_template, redirect, url_for, jsonify, request, session

from database.db import init_db
from levels.config import all_levels, get_level
from levels.progress import completed_levels, get_flag_if_completed, mark_complete, reset_progress

from levels.level1 import bp as level1_bp
from levels.level2 import bp as level2_bp
from levels.level3 import bp as level3_bp
from levels.level4 import bp as level4_bp
from levels.level5 import bp as level5_bp
from levels.level6 import bp as level6_bp
from levels.level7 import bp as level7_bp
from levels.level8 import bp as level8_bp


def create_app() -> Flask:
    app = Flask(__name__)

    # Local single-player trainer: a persistent-ish secret is fine here, but
    # this is NOT a real credential and must never be reused outside this lab.
    app.config["SECRET_KEY"] = os.environ.get("XSS_LAB_SECRET_KEY", "local-xss-lab-dev-secret")

    for bp in (
        level1_bp, level2_bp, level3_bp, level4_bp,
        level5_bp, level6_bp, level7_bp, level8_bp,
    ):
        app.register_blueprint(bp)

    @app.route("/")
    def home():
        return render_template("index.html", levels=all_levels(), completed=completed_levels())

    @app.route("/progress")
    def progress_page():
        return render_template("progress.html", levels=all_levels(), completed=completed_levels())

    @app.route("/progress/reset", methods=["POST"])
    def reset_progress_route():
        reset_progress()
        return redirect(url_for("progress_page"))

    @app.route("/health")
    def health():
        return jsonify({"status": "ok"})

    @app.route("/api/report/<level_id>", methods=["POST"])
    def api_report(level_id):
        """
        Called by a successfully injected payload (via window.xssLabSolve)
        to report that it executed in the intended context. For stored/DOM
        levels with a simulated admin bot, completion is instead recorded
        server-side when the bot's review detects an executable payload --
        see levels/levelN.py `simulate_admin_review`.

        Known limitation: because this lab has no headless browser, this
        endpoint trusts any same-origin caller. On a shared/multi-user
        deployment this would let someone "complete" a level without truly
        exploiting it. That's an acceptable tradeoff for a local,
        single-player trainer -- see README.md.
        """
        if level_id not in {l.id for l in all_levels()}:
            return jsonify({"error": "unknown level"}), 404
        newly = mark_complete(level_id)
        return jsonify({"status": "ok", "newly_completed": newly, "flag": get_flag_if_completed(level_id)})

    @app.route("/api/progress")
    def api_progress():
        return jsonify({"completed": sorted(completed_levels())})

    return app


app = create_app()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="XSS Security Lab")
    parser.add_argument("--reset", action="store_true", help="Reset the database before starting")
    parser.add_argument("--host", default=os.environ.get("XSS_LAB_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("XSS_LAB_PORT", "5000")))
    args = parser.parse_args()

    init_db(reset=args.reset)

    app.run(host=args.host, port=args.port, debug=os.environ.get("XSS_LAB_DEBUG", "0") == "1")
else:
    # Ensure the DB exists when imported (e.g. by pytest or a WSGI server).
    init_db(reset=False)
