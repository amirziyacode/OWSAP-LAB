# Level 5 — XSS in JavaScript String Context

## Vulnerability
The username is interpolated directly into an inline `<script>` block as a
JavaScript string literal. The only "sanitization" applied strips `<` and
`>` characters (aimed at the *HTML* context) — it does nothing to escape
characters that matter in a *JavaScript string* context, like `"`, `\`, or
newlines.

## Injection Point
`levels/level5.py`:

```python
SCRIPT_FRAGMENT = """
<script>
    const username = "{username}";
    ...
</script>
"""
username_for_js = str(username).replace("<", "").replace(">", "")
script_html = Markup(SCRIPT_FRAGMENT.format(username=username_for_js))
```

## How To Identify The Context
View source and find where your username appears — it's inside a
`<script>` tag, assigned to a JS variable as a quoted string, not sitting in
HTML text or an HTML attribute.

## Exploitation Methodology
1. Recognize that HTML-encoding is irrelevant here — you're already inside
   a `<script>` block, so `<` / `>` stripping (or even full HTML-entity
   encoding) does nothing to stop you, since the browser's JS parser reads
   raw characters here, not HTML entities.
2. What matters is JavaScript string syntax: a literal `"` closes the
   string early.
3. Follow the closing quote with a semicolon to cleanly end the statement,
   then write your own JavaScript statement(s), then optionally comment out
   or otherwise neutralize the rest of the original line so it doesn't
   throw a syntax error.

## Example Payload
```
x"; xssLabSolve('level5'); //
```

Submitting this as the username produces:
```html
<script>
    const username = "x"; xssLabSolve('level5'); //";
    ...
</script>
```
The `//` comments out the remainder of the original line.

## Why It Works
The developer correctly worried about *HTML* injection (stripping `<`/`>`)
but never considered that the same value also needs *JavaScript-string*
escaping when placed inside a `<script>` block. These are two entirely
different encoding schemes with different special characters.

## Correct Defensive Fix
Never hand-build JS string literals by concatenating untrusted data. Either:
- Pass data to the client via a safe channel, e.g. a `data-*` HTML attribute
  (properly attribute-encoded) that JS reads with `dataset`, or a JSON
  `<script type="application/json">` block parsed with `JSON.parse`, or
- If you must inline it, use a JSON-safe serializer (e.g. Python's
  `json.dumps(username)`) which correctly escapes quotes, backslashes, and
  `</script>` sequences for safe embedding in a `<script>` block.

## CWE Classification
CWE-79: Improper Neutralization of Input During Web Page Generation
('Cross-site Scripting') — JavaScript-context injection.

## OWASP Category
A03:2021 — Injection
