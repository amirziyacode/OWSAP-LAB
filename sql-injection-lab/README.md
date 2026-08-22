# SQL Injection CTF Lab

A local, self-contained SQL injection training lab built with Flask + SQLite.
10 levels, ordered easy → very hard, each with its own independent flag.

> ⚠️ **For localhost / authorized educational use only.** Every level is
> intentionally vulnerable to SQL injection. Do not deploy this application
> on a shared network or the public internet. Do not reuse any code, query
> style, or "filter" logic from this project in a real application.

---

## 1. Requirements

- Python 3.10+ (tested on 3.12), **or**
- Docker + Docker Compose

## 2. Run locally (no Docker)

```bash
cd sql-injection-lab
pip install -r requirements.txt
cd app
python app.py
```

The app starts on **http://127.0.0.1:5000**. The SQLite database
(`app/lab.db`) is created and seeded automatically the first time it runs.

## 3. Run with Docker

```bash
cd sql-injection-lab
docker compose up --build
```

The app is published to **http://127.0.0.1:5000** only (bound to localhost
in `docker-compose.yml`, not `0.0.0.0`, to reduce the chance of accidentally
exposing it on your network).

Stop it with `docker compose down`. Note: this repository was built and
verified against the plain Python/Flask dev server; the Dockerfile follows
the same standard `pip install` + `python app.py` flow, but if Docker isn't
available in your environment, running locally (Section 2) is fully
equivalent.

## 4. How the lab is organized

- `app/app.py` — Flask routes, session/progress handling, request logging, reset
- `app/database.py` — schema + deterministic seed data + flag values (server-side only)
- `app/levels/level*.py` — one module per level containing the actual
  (intentionally vulnerable) query-building logic
- `app/templates/` — one page per level, plus index/progress/logs pages
- `app/lab.db` — SQLite database file (recreated on reset)
- `app/requests.log` — plain-text request log (also viewable at `/logs`)

Each level has its own tables in the same SQLite file, so levels don't
interfere with each other and can be reasoned about independently.

## 5. Progress, reset, and logs

- **Progress page** (`/progress`): shows which levels you've completed.
  A level is marked complete when you submit its correct flag on that
  level's page.
- **Reset** (button on the home page, or `POST /reset`): wipes and
  re-seeds the entire database and clears your session progress. Use this
  any time you want a clean slate, or if you accidentally break something
  with a `DROP`/`DELETE` (a few levels do not filter those out — see
  Level 10's blacklist, which *does* block them).
- **Logs page** (`/logs`): shows the most recent requests (method, path,
  query args, status code, response time) — useful for watching how your
  payloads are actually being sent, especially for the timing-based level.

## 6. Levels

Solutions are **not** included here — see `SOLUTIONS.md` for full write-ups,
intended purely for verification/instructor use.

### Level 1 — Basic Authentication SQL Injection
**Difficulty: Easy**
A login form checks a username and password against the database. Find a
way to log in without knowing a valid password.
*Learning objective:* understand how string concatenation in a `WHERE`
clause lets an attacker alter query logic (authentication bypass).

### Level 2 — UNION-based SQL Injection
**Difficulty: Easy**
A product search box builds its query from your input directly. The
results table has a hidden `level2_secrets` table sitting alongside it in
the same database, holding this level's flag.
*Learning objective:* determine the number of columns returned by a query
and use `UNION SELECT` to pull data from a different table into the
visible output.

### Level 3 — Database Enumeration
**Difficulty: Medium**
Same style of injection as Level 2, but this time you aren't told where
the flag lives. You'll need to enumerate the database schema first.
*Learning objective:* use SQLite's `sqlite_master` table to discover table
and column names before extracting data — since there's no `information_schema`
in SQLite the way there is in MySQL/Postgres.

### Level 4 — Hidden Output
**Difficulty: Medium**
The injection point exists, but the application only ever renders a couple
of fields, and appends its own condition to your query server-side. You'll
need to reason about the full query being executed, not just what's shown
on screen, to get data that's normally filtered out.
*Learning objective:* recognize that "the page doesn't show me everything"
doesn't mean the query can't be shaped to return what you want.

### Level 5 — Boolean-based Blind SQL Injection
**Difficulty: Medium**
No query results and no database errors are ever shown — only a generic
"found" / "not found" message. That's still enough of a signal to work with.
*Learning objective:* build true/false conditions and extract data one
character at a time using functions like `SUBSTR()`.

### Level 6 — Time-based Blind SQL Injection
**Difficulty: Hard**
Here, the response text gives you no signal at all — true and false look
identical. The only thing you can observe is how long the response takes.
SQLite has no `SLEEP()` function; you'll need an expensive query
(SQLite has no built-in delay function the way MySQL/Postgres do) as the
equivalent trick.
*Learning objective:* extract data using timing side-channels when there is
no visible difference in application behavior at all.

### Level 7 — Filtered SQL Injection
**Difficulty: Hard**
A basic keyword filter blocks a handful of obviously dangerous words before
your input reaches the query. The filter is naive in more than one way.
*Learning objective:* understand why blacklists are fragile — case
sensitivity, alternative syntax, and different comment styles are all
common gaps in naive filters.

### Level 8 — WAF Bypass
**Difficulty: Hard**
A more "realistic" filtering layer strips dangerous keywords out of your
input before using it. Think about *how* that stripping actually works,
not just *what* it blocks.
*Learning objective:* understand a very common real-world filter bug —
removing a forbidden substring once, without re-checking the result, can
leave a new, unintended copy of that substring behind.

### Level 9 — Second-order SQL Injection
**Difficulty: Very Hard**
This level has two steps: something you submit (safely, via a
parameterized query), and something else that happens later, in a
different operation, using data that was already stored. The vulnerability
isn't where you'd first look.
*Learning objective:* understand that "this endpoint uses parameterized
queries" doesn't automatically mean stored data is safe everywhere else
it's later used.

### Level 10 — Advanced Combined Challenge
**Difficulty: Very Hard**
The final level chains several of the earlier concepts together across
multiple endpoints: you'll need to authenticate, then use a filtered
endpoint to enumerate the schema, and finally pull the flag out of a table
that has nothing to do with the page you found it on.
*Learning objective:* combine authentication bypass, enumeration, and
UNION-based extraction into a single multi-step attack chain, the way a
real assessment usually plays out.

## 7. How to verify each level works

Each level page shows you the raw SQL query that was executed (except
Levels 5 and 6, which are blind by design — that's the point). If a level
seems "stuck":

1. Check the query shown on the page against what you typed — string
   concatenation bugs are easy to misjudge without seeing the literal
   query.
2. Check `/logs` to confirm your request actually reached the server the
   way you expected (URL-encoding issues are a common culprit).
3. Use **Reset Lab** to rule out state you may have mutated on a previous
   attempt (a couple of levels don't filter out `DROP`/`DELETE`/`UPDATE`).
4. Cross-check your approach against `SOLUTIONS.md` if you're an
   instructor verifying the lab rather than a player solving it.

## 8. Automated smoke tests

`tests/test_lab.py` starts the app in-process (via Flask's test client) and
exercises the intended exploit path for all 10 levels, plus reset and
progress tracking. Run it with:

```bash
cd sql-injection-lab
pip install -r requirements.txt
pip install pytest
pytest tests/ -v
```
