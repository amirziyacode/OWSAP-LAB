# Level 6 — Filter / Blacklist Bypass

## Vulnerability
Same unsafe `|safe` rendering as Level 2, but comments are first checked
against a short, case-insensitive substring blacklist. The blacklist blocks
the most obvious payload patterns but has no real understanding of HTML or
JavaScript.

## Injection Point
`levels/level6.py`:

```python
BLACKLIST = ["<script", "onerror", "onload", "javascript:"]

def is_blocked(body: str) -> bool:
    lowered = body.lower()
    return any(bad in lowered for bad in BLACKLIST)
```

If `is_blocked()` returns `False`, the comment is stored and rendered
unescaped — identical vulnerability to Level 2.

## How To Identify The Context
Try an obvious payload (`<script>alert(1)</script>`) — it gets rejected with
a flash message. Try variations to map out exactly what's blocked: submit
`onerror`, `onload`, `javascript:`, and confirm each is individually
rejected, then start looking for equivalents that aren't on the list.

## Exploitation Methodology
HTML defines dozens of event-handler attributes and several tags that
naturally trigger JavaScript, and this filter only recognizes four
substrings. Any of the following bypass it entirely:
- Different event handlers: `onfocus`, `onpointerover`, `onanimationstart`,
  `onmouseover`, etc. — none of these contain the blocked substrings.
- Different tags: `<svg>`, `<details>/<summary>`, `<body>` (blocked via
  `onload` only, not the tag itself) combined with an allowed handler.
- Case tricks are irrelevant here since the filter lowercases first, but
  many real-world blacklists forget to do even that.

An element that gets focus automatically (`autofocus`) combined with an
unblocked handler (`onfocus`) fires without any victim interaction.

## Example Payload
```
<input autofocus onfocus=xssLabSolve('level6')>
```

## Why It Works
Denylists enumerate specific *known-bad* strings, but the actual attack
surface (every tag × every event-handler attribute × every alternative
syntax for triggering script execution) is enormous and constantly growing
as browsers add features. A denylist can only ever cover the subset its
author thought of.

## Correct Defensive Fix
Don't use a denylist for this at all. Either escape all HTML metacharacters
on output (removing the need for input filtering entirely — the correct fix
here is identical to Level 2's: stop using `|safe`), or, if raw HTML input
must be accepted, use a maintained allow-list HTML sanitizer library (e.g.
`bleach` in Python, `DOMPurify` client-side) that parses HTML properly
rather than string-matching.

## CWE Classification
CWE-79: Improper Neutralization of Input During Web Page Generation
('Cross-site Scripting'); the filter itself is an instance of
CWE-184: Incomplete Denylist.

## OWASP Category
A03:2021 — Injection
