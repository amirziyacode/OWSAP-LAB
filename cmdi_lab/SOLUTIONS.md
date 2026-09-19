# Solutions

Spoilers below. Each section covers the vulnerability, the intended
payload, and why it works.

---

## Level 1 — Basic Command Injection

**Bug:** `host` is dropped directly into an f-string and run with
`subprocess.run(cmd, shell=True)`. No validation, no quoting.

**Payload:**
```
127.0.0.1; cat flags/level1.txt
```
Any standard separator works: `&&`, `|`, `` ` ` ``, `$()`.

---

## Level 2 — Blind Command Injection

**Bug:** Same unsafe concatenation as level 1, but the job runs in a
background thread and only a job id is returned. Raw output is never
sent back to the client.

**Payload:**
```
127.0.0.1; sleep 5
```
Poll `GET /level2/status?job_id=...`. A normal ping finishes in well
under a second; a job that takes ≥4s proves the injected `sleep` ran.
Once the server detects that, it treats it as proof of execution and
includes the flag in the status response — that's the "signal" a real
blind-injection exploit would otherwise have to build itself (e.g. via
character-by-character conditional sleeps).

---

## Level 3 — Hidden Parameter

**Bug:** Two fields, `filename` and `format`. `filename` *looks*
dangerous but is checked against a strict allowlist regex
(`^[A-Za-z0-9_\-]{1,40}$`) and is placed inside single quotes in the
shell command, so it's inert either way. `format` looks cosmetic (just
an output extension) but is concatenated unquoted and unvalidated.

**Payload:**
```
filename = diag01
format   = txt; cat flags/level3.txt
```

---

## Level 4 — Blacklist Bypass

**Bug:** The `host` field is checked against a blacklist:
`; & | \` $ ( ) < >`. That blocks every level-1-style payload. The
blacklist never considers that a literal newline byte also terminates
a shell statement.

**Payload:** a `host` value containing a real newline, e.g. via curl:
```bash
curl --data-urlencode 'host=127.0.0.1
cat flags/level4.txt' http://127.0.0.1:5000/level4
```
(A browser text `<input>` won't let you type a raw newline easily —
that's intentional; it nudges you toward a scriptable client.)

---

## Level 5 — Argument Injection

**Bug:** `shell=False` throughout — no shell metacharacters do anything
here. But the "search pattern" is tokenized with `shlex.split()` and the
resulting tokens are appended straight onto the `find` argv list:
```python
args = ["find", SEARCH_DIR, "-type", "f", "-name"] + shlex.split(pattern)
```
Since the player fully controls those extra tokens, they can inject new
`find` flags — most usefully `-exec`.

**Payload:**
```
* -exec cat /app/flags/level5.txt ;
```
(Use the absolute flag path — in the Docker image that's
`/app/flags/level5.txt`; when running locally it's
`<repo>/flags/level5.txt`.)

---

## Level 6 — Shell Parsing / Expansion

**Bug:** Two defenses: an allowlist regex (`^[A-Za-z0-9./\-${}()]+$`)
and a blacklist of classic separators and whitespace
(`; & | \` <space> <newline> <CR>`). Both were written with "command
separators" in mind and both still permit `$`, `(`, `)`, `{`, `}`, `/` —
exactly what's needed for POSIX command substitution, and `${IFS}`
expands to whitespace, sidestepping the fact that a literal space is
blocked.

**Payload:**
```
$(cat${IFS}flags/level6.txt)
```
No separator is used at all — the whole thing is one command
substitution. The shell expands `${IFS}` to a space, runs
`cat flags/level6.txt` inside the substitution, and splices the flag
into the `ping` command as the "hostname", which surfaces in ping's
error output.

---

## Level 7 — File Processing

**Bug:** `filename` is properly defended — resolved against a fixed
working directory with a realpath/commonpath check that rejects
traversal. `operation` is meant to be one of `info` / `mime` /
`encoding`, mapped to a `file(1)` flag via a dict — but unrecognized
values fall through to being used **as the raw flag text itself**.

**Payload:**
```
filename  = notes.txt
operation = brief; cat ../../flags/level7.txt #
```
The subprocess runs with its cwd set to the working directory, so the
flag is two directories up from there. The trailing `#` comments out the
rest of the original command so the shell doesn't choke on the leftover
quote.

---

## Level 8 — Async Command Injection

**Bug:** `POST /level8` stores the submitted `host` under an
unpredictable job id and returns immediately — the HTTP request itself
never touches a shell. A background `threading.Thread` worker picks the
job up later and runs the same unsafe concatenation as level 1, writing
whatever the command produces to a per-job log.

**Workflow:**
1. `POST /level8` with `host = 127.0.0.1; cat flags/level8.txt`
2. Poll `GET /level8/job/<job_id>` until `"status": "done"`
3. `GET /level8/log/<job_id>` — the flag is in the captured log output
   alongside the ping output.
