# XSS Security Lab

A local-only, 8-level cross-site scripting (XSS) training platform built with
Python, Flask, SQLite, and vanilla JS/HTML/CSS — in the spirit of PortSwigger
Web Security Academy, but self-hosted and offline.

Every level contains one **intentional, distinct** real-world XSS
vulnerability: reflected, stored, attribute-context, DOM-based, JavaScript
string-context, blacklist-bypass, CSP-hardened, and a full multi-step attack
chain. Nothing here is fixed automatically, and the app never reveals the
vulnerability in its normal UI — that's the point of the exercise.

**This is intentionally vulnerable software. Run it locally only. Never
deploy it to a shared network or the public internet.**

---

## Project Tree

```text
xss-lab/
├── app.py
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── README.md
├── database/
│   ├── schema.sql
│   └── db.py
├── levels/
│   ├── config.py          # level metadata, flags, hints
│   ├── progress.py        # session-scoped completion tracking
│   ├── xss_detect.py      # heuristic "would this execute?" bot simulator
│   ├── level1.py .. level8.py
├── templates/
│   ├── base.html, index.html, progress.html, _hints_flag.html
│   └── level1.html .. level8.html (+ level8_login.html, level8_profile.html)
├── static/
│   ├── css/style.css
│   └── js/level4.js       # the DOM-XSS vulnerable client-side code
├── tests/
│   ├── conftest.py
│   ├── test_app.py
│   └── test_levels.py
└── solutions/
    └── level1.md .. level8.md
```

---

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run

```bash
python app.py
```

The app binds to `127.0.0.1:5000` by default:

```text
http://127.0.0.1:5000
```

To reset the database on startup:

```bash
python app.py --reset
```

Environment variables (all optional):

| Variable              | Default                     | Purpose                          |
|------------------------|------------------------------|-----------------------------------|
| `XSS_LAB_HOST`          | `127.0.0.1`                 | Bind address                     |
| `XSS_LAB_PORT`          | `5000`                       | Port                              |
| `XSS_LAB_DB`             | `database/lab.db`            | SQLite file path                 |
| `XSS_LAB_SECRET_KEY`     | dev default (change it)      | Flask session signing key        |
| `XSS_LAB_DEBUG`          | `0`                           | Set to `1` for Flask debug mode  |

## Docker

```bash
docker compose up --build
```

`docker-compose.yml` maps the container's port 5000 to
`127.0.0.1:5000` on the host only — it is not exposed to your network.

## Reset

```bash
python app.py --reset
```

Or, without restarting, click **Reset Progress** on the `/progress` page
(this clears your session's completion state; to fully reset stored
comments/bios too, restart with `--reset`).

---

## The 8 Levels

| # | Name                          | Difficulty      | Technique |
|---|--------------------------------|------------------|-----------|
| 1 | Reflected XSS in Search        | Easy             | Unescaped query param in HTML text |
| 2 | Stored XSS in Comments         | Easy → Medium    | `\|safe` rendering of stored user content |
| 3 | Attribute Context XSS          | Medium           | Unescaped quote breaks out of `value="..."` |
| 4 | DOM-Based XSS                  | Medium           | `location.hash` → `innerHTML` sink, client-side only |
| 5 | XSS in JavaScript Context      | Medium → Hard    | Unescaped value inside a JS string literal |
| 6 | Filter / WAF Bypass            | Hard             | Incomplete blacklist, unlisted event handlers |
| 7 | CSP + DOM XSS                  | Hard             | Nonced first-party script unsafely `eval()`s attacker data |
| 8 | Realistic Multi-Step XSS Chain | Expert           | Bio → comment → admin-context execution → privileged action |

Full write-ups, injection points, and defensive fixes for each level live in
`solutions/levelN.md` (not linked from the app UI — read them only after you
solve the level, or if you get stuck).

### Difficulty Progression
Levels build on each other conceptually: Level 1 teaches the *idea* of
reflected XSS in the simplest possible context (HTML text); Level 2 adds
persistence and a "victim" other than yourself; Levels 3 and 5 show that the
*same* underlying bug class needs *different* encoding depending on where
the injection lands (attribute vs. JS string); Level 4 moves the whole
vulnerability client-side; Level 6 shows why blacklists don't generalize;
Level 7 adds a real defense-in-depth control (CSP) and shows its limits;
Level 8 combines several of the earlier lessons into one realistic,
multi-step, privilege-crossing exploit chain.

### Flags & Hints
Every level has a unique flag (`FLAG{XSS_LEVEL_N_...}`), revealed only after
the level's specific completion condition is met — never before, and never
via a shortcut in the UI. Each level has 3 hints that get progressively more
specific but never hand you the final payload outright. Check overall
progress at `/progress`.

### How Completion Is Detected
This lab has no headless browser, so it detects real exploitation two ways:

1. **Self-triggered levels** (1, 3, 4, 5, 7): every page defines a global
   `window.xssLabSolve(levelId)` helper. A successfully injected payload
   calls it (or replicates its `fetch` call) to report completion.
2. **Victim-triggered levels** (2, 6, 8): a simulated "admin review" runs
   server-side after you post a comment, using a heuristic HTML/JS
   detector (`levels/xss_detect.py`) to decide whether your stored payload
   would have executed in a real browser, standing in for an actual admin
   loading the page.

**Known limitation:** because completion reporting is a same-origin API
call, a user could technically call `/api/report/<level>` directly without
exploiting anything. That's an accepted tradeoff for a local, single-player
trainer with no headless-browser infrastructure — the value of the lab is in
finding and understanding each vulnerability, not in tamper-proof scoring.

---

## Testing

```bash
pip install -r requirements.txt   # includes pytest
pytest tests/ -v
```

The suite checks:
- The app starts and the database initializes with expected seed data
- Every level page is reachable
- All 8 flags are unique and never appear before completion
- Each level's *actual vulnerable behavior* (e.g. "is a quote character left
  unescaped inside an HTML attribute?") using payloads distinct from the
  hint/solution examples — not a single hard-coded "correct" string
- Each level's completion/flag-issuance logic, including negative cases
  (safe input should **not** complete a level)
- Login, session handling, and access control for Level 8
- `/progress/reset` correctly clears completion state

---

## Security Concepts Learned

- Reflected vs. stored XSS
- Context-sensitive output encoding (HTML text vs. HTML attribute vs.
  JavaScript string)
- DOM XSS: sources, sinks, and why client-side bugs are invisible
  server-side
- Why blacklist/denylist filtering is fundamentally unreliable
- Content-Security-Policy: what it protects against, what it doesn't
  (`'unsafe-eval'`, trusted-script data-flow gadgets), and why it's
  defense-in-depth, not a replacement for output encoding
- How a single stored-XSS bug becomes a real, multi-step, privilege-crossing
  attack chain in a realistic small application

## Defensive Fixes Covered In The Solutions

- Let templating-engine autoescaping do its job; avoid `Markup()`/`|safe` on
  untrusted data
- Use context-aware encoding libraries for HTML attribute vs. JS-string vs.
  HTML-text contexts
- Prefer `textContent`/DOM-node construction over `innerHTML` for
  user-controlled data
- Replace denylists with allow-list HTML sanitizers (`bleach`, `DOMPurify`)
- Ship a real CSP, avoid `'unsafe-eval'`, and audit any first-party script
  that consumes attacker-influenceable data
- Apply least privilege / extra confirmation to session-authenticated
  privileged actions so that XSS impact is contained even if it occurs

---

## Security Boundaries

- Binds to `127.0.0.1` by default; Docker Compose maps only to
  `127.0.0.1:5000` on the host
- No external API calls, no internet dependency at runtime
- No real authentication secrets — seeded lab credentials are fake and
  documented in-app (`alice` / `lab-password-1`)
- All flags are fake, clearly-labeled training values
- No functionality targets or interacts with anything outside this
  application
