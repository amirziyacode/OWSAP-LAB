# Level 1 — Reflected XSS in Search

## Vulnerability
The `/level1/search?q=` endpoint reflects the `q` parameter directly into an
HTML fragment that is then wrapped in `Markup()`, which disables Jinja2's
automatic HTML-escaping for that content.

## Injection Point
`levels/level1.py`, `search()`:

```python
RESULTS_FRAGMENT = """
<div class="panel">
  <h3>Search results for: {query}</h3>
  ...
"""
results_html = Markup(RESULTS_FRAGMENT.format(query=q, items=items_html))
```

`q` comes straight from `request.args.get("q", "")` with no encoding.

## How To Identify The Context
View source on the results page after searching for something distinctive
(e.g. `zzz123`). You'll find it inside `<h3>Search results for: zzz123</h3>`
— i.e. plain HTML text content.

## Exploitation Methodology
1. Confirm reflection with a harmless marker.
2. Since you're in HTML text content, any tag you inject is parsed as a tag,
   not text — no need to "close" anything first.
3. Use a self-executing tag: an inline `<script>` runs immediately, or an
   `<img src=x onerror=...>` runs on load failure without needing a click.
4. Call `xssLabSolve('level1')` to report exploitation.

## Example Payload
```
/level1/search?q=<img src=x onerror=xssLabSolve('level1')>
```

## Why It Works
The server treats `q` as trusted HTML and skips encoding. The browser parses
`<img ...>` as a real element; because `src=x` fails to load, `onerror` fires
immediately, running arbitrary JavaScript in the victim's session.

## Correct Defensive Fix
Let Jinja2's default autoescaping do its job — render with `{{ q }}` inside a
normal template instead of hand-building HTML and wrapping it in `Markup()`.
If you must build a fragment manually, HTML-encode with something like
`markupsafe.escape(q)` before interpolation.

## CWE Classification
CWE-79: Improper Neutralization of Input During Web Page Generation
('Cross-site Scripting')

## OWASP Category
A03:2021 — Injection (OWASP Top 10 2021)
