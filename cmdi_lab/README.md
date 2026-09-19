# Command Injection Lab

A self-hosted, Docker-packaged set of eight progressive OS command-injection
challenges, in the same style as the earlier SQLi and XSS labs. Flask +
Jinja2, dark terminal UI, one Blueprint per level, full pytest coverage,
flags gated on actual exploit execution.

**This lab is intentionally vulnerable. Run it only on localhost / in an
isolated container. Never expose it to an untrusted network.**

## Levels

| # | Name                  | Focus                                             |
|---|------------------------|----------------------------------------------------|
| 1 | Basic Command Injection | Raw shell concatenation, `shell=True`             |
| 2 | Blind Command Injection | No output returned; prove execution via timing    |
| 3 | Hidden Parameter        | The "obvious" field is safe; the other one isn't  |
| 4 | Blacklist Bypass        | Incomplete blacklist, bypass with a newline        |
| 5 | Argument Injection      | `shell=False`, but tokens get appended to argv     |
| 6 | Shell Parsing           | Allowlist + blacklist bypassed via `${IFS}` + `$()`|
| 7 | File Processing         | Path traversal is blocked; the other field isn't   |
| 8 | Async Command Injection | Background worker, job/log polling workflow        |

Each level has its own flag, its own vulnerable code path, and its own
write-up in `SOLUTIONS.md`. Solving one level does not solve any other.

## Running locally

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

The app binds to `127.0.0.1:5000` by default (see the `HOST`/`PORT` env
vars in `app.py`).

## Running with Docker

```bash
docker compose up --build
```

This builds a container with `ping`, `find`, and `file` installed (the
levels intentionally shell out to these), runs the app as a non-root user,
drops all Linux capabilities, and publishes the port bound to `127.0.0.1`
only.

Visit http://127.0.0.1:5000/.

## Running the tests

```bash
pip install -r requirements-dev.txt
python -m pytest -v
```

29 tests cover, for every level: a benign request that should **not**
reveal the flag, and the intended exploit that should. Level 4 and 6 also
assert that the "obvious" bypasses are correctly rejected before the real
technique is demonstrated.

## Project layout

```
app.py                  Flask app factory, registers all 8 blueprints
levels/
  utils.py              Shared helpers (flag reading, job ids, path safety)
  level1.py ... level8.py   One blueprint per level, vulnerability documented inline
templates/               Jinja2 templates, dark terminal theme
static/style.css
data/level7_workdir/     Sample files level 7 is allowed to process
flags/level1.txt ... level8.txt
tests/                   pytest suite (one file per level + conftest)
Dockerfile / docker-compose.yml
```

## Solutions

See `SOLUTIONS.md` for a full write-up of the vulnerability and the
intended payload for each level.
