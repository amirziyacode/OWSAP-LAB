# Level 7 — CSP + DOM XSS

## Vulnerability
The page sets a real, restrictive Content-Security-Policy with a per-request
nonce (`script-src 'self' 'nonce-<random>' 'unsafe-eval'; object-src 'none';
base-uri 'self'`). This blocks any attacker-injected `<script>` tag or
inline event handler, since those won't carry a valid nonce. However, the
page's own first-party, correctly-nonced inline script contains an
`eval()` call that unsafely incorporates a `?theme=` query parameter.

## Injection Point
`templates/level7.html`:

```html
<script nonce="{{ nonce }}">
    function applyTheme(themeName) { ... }
    eval("applyTheme('{{ theme|safe }}')");
</script>
```

`levels/level7.py` reflects `request.args.get("theme", "dark")` straight
into that template with `|safe`, bypassing Jinja2 autoescaping.

## How To Identify The Context
1. Try the "obvious" attack first: inject `<script>alert(1)</script>` via
   any input on the page. It won't run — check DevTools console, which will
   show a CSP violation report, confirming the policy is real and active.
2. Read the response headers to see the exact policy, including
   `'unsafe-eval'` — a flag that specifically permits `eval()`/`Function()`
   calls, which is unusual and worth investigating.
3. View source and find the one inline script CSP trusts (it carries the
   nonce) — that script is your only route to script execution.

## Exploitation Methodology
Because CSP restricts *where scripts come from*, not *what an already
trusted script does with its data*, an attacker who can influence the data
consumed by a trusted `eval()` call can still get arbitrary JS to run —
without ever needing to inject a new `<script>` tag.

1. Confirm `?theme=` flows into the `eval()` call by trying a distinctive
   marker value and viewing source.
2. Since the value is dropped into a single-quoted JS string inside the
   `eval()`'d string, break out with a literal `'`.
3. Close the `applyTheme(...)` call, add a `;`, then write your own
   statement, then comment out (or otherwise neutralize) anything after.

## Example Payload
```
http://127.0.0.1:5000/level7/?theme=x'); xssLabSolve('level7'); //
```

This makes the evaluated string:
```js
applyTheme('x'); xssLabSolve('level7'); //')
```

## Why It Works
CSP's `script-src` directive governs *script sources* — where a `<script>`
element or handler is allowed to come from — not the internal logic of a
script CSP has already permitted to run. `'unsafe-eval'` further weakens
the policy by allowing that permitted script to dynamically evaluate new
code from strings. Combining "a nonced script exists" with "that script
`eval()`s attacker-influenced data" recreates a full script-execution
primitive despite the strict-looking policy.

## Correct Defensive Fix
1. Never pass user-controlled data into `eval()`, `Function()`,
   `setTimeout(string)`, or `setInterval(string)` — call `applyTheme(theme)`
   directly as a function argument instead of building a string to evaluate.
2. Drop `'unsafe-eval'` from the CSP entirely unless a specific,
   unavoidable legacy dependency requires it — and if it must be kept,
   treat every `eval`-adjacent call path as untrusted-data-sensitive code.
3. Validate `theme` against an allow-list of known theme names before using
   it anywhere.

## CWE Classification
CWE-79 (Cross-site Scripting) combined with CWE-95 (Improper Neutralization
of Directives in Dynamically Evaluated Code / 'Eval Injection').

## OWASP Category
A03:2021 — Injection. Also relevant: A05:2021 — Security Misconfiguration
(the `'unsafe-eval'` CSP directive).
