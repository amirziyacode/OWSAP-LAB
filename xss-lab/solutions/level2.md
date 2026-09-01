# Level 2 — Stored XSS in Comments

## Vulnerability
Comment bodies are stored verbatim (parameterized SQL — storage is fine) and
rendered with Jinja2's `|safe` filter, which disables autoescaping for that
value on every page load, for every visitor.

## Injection Point
`templates/level2.html`:

```html
<span>{{ c.body|safe }}</span>
```

`levels/level2.py` inserts the raw comment body with a parameterized query
(no SQL injection), but nothing sanitizes the HTML/JS content itself.

## How To Identify The Context
Post a comment containing an HTML tag and reload the page (or have someone
else load it) — if the tag renders as a real element instead of literal
text, the output isn't being escaped.

## Exploitation Methodology
1. Post a comment containing a payload that self-executes on render (no
   click required), since you can't rely on the admin interacting with it.
2. The lab simulates an admin who periodically reviews new comments on this
   post — your payload runs in that "admin's" render pass.
3. Call `xssLabSolve('level2')` (or the app's own detection logic recognizes
   the executable markup and completes the level for you).

## Example Payload
```
<svg onload=xssLabSolve('level2')>
```
or
```
<img src=x onerror=xssLabSolve('level2')>
```

## Why It Works
Because storage and rendering both happen without sanitization, the payload
becomes part of the page's real DOM for every viewer — this is what makes
stored XSS more dangerous than reflected XSS: no need to trick a victim into
clicking a crafted link, they just need to view a page that already contains
your payload.

## Correct Defensive Fix
Never use `|safe` on user-controlled content. Let Jinja2 autoescape
(`{{ c.body }}`), or if limited HTML formatting is a real requirement, run
the content through a well-vetted HTML sanitizer allow-list (e.g. `bleach`)
before storage or rendering — never a denylist.

## CWE Classification
CWE-79: Improper Neutralization of Input During Web Page Generation
('Cross-site Scripting')

## OWASP Category
A03:2021 — Injection
