"""
Command Injection Lab
======================

A self-hosted, Docker-packaged set of eight progressive command-injection
challenges, in the same style as the earlier SQLi and XSS labs.

Run directly:
    python app.py

Run with Docker:
    docker compose up --build

Everything is bound to 127.0.0.1 by default (see HOST env var) and every
level's vulnerable code lives in levels/levelN.py with its own docstring
explaining the bug and the intended solution.
"""
import os

from flask import Flask, flash, redirect, render_template, request, session, url_for

from levels import level1, level2, level3, level4, level5, level6, level7, level8
from levels.utils import VALID_LEVELS, check_flag


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "cmdi-lab-dev-key")

    app.register_blueprint(level1.bp)
    app.register_blueprint(level2.bp)
    app.register_blueprint(level3.bp)
    app.register_blueprint(level4.bp)
    app.register_blueprint(level5.bp)
    app.register_blueprint(level6.bp)
    app.register_blueprint(level7.bp)
    app.register_blueprint(level8.bp)

    @app.context_processor
    def inject_lab_state():
        endpoint = request.endpoint or ""
        current_level = next(
            (name for name in VALID_LEVELS if endpoint.startswith(f"{name}.")),
            None,
        )
        return {
            "current_level": current_level,
            "solved_levels": set(session.get("solved_levels", [])),
        }

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/submit-flag", methods=["POST"])
    def submit_flag():
        level = request.form.get("level", "")
        if level not in VALID_LEVELS:
            return "Unknown level.", 404
        if check_flag(level, request.form.get("flag", "")):
            solved = set(session.get("solved_levels", []))
            solved.add(level)
            session["solved_levels"] = list(solved)
            flash("Flag accepted.", "success")
        else:
            flash("Incorrect flag.", "error")
        return redirect(url_for(f"{level}.view"))

    @app.errorhandler(404)
    def not_found(_e):
        return "404 Not Found: no matching route for this URL.", 404

    return app


app = create_app()

if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    print("Registered routes:")
    for rule in sorted(app.url_map.iter_rules(), key=lambda r: r.rule):
        methods = ",".join(sorted(rule.methods - {"HEAD", "OPTIONS"}))
        print(f"  {rule.rule:30s} [{methods}]")
    app.run(host=host, port=port, debug=debug)
