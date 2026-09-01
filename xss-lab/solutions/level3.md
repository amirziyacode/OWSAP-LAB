# Level 3 — Attribute Context XSS

## Vulnerability
The display name is spliced directly into an HTML attribute
(`value="..."`) with plain `str.format()`, with no attribute-context
encoding — specifically, no encoding of the double-quote character.

## Injection Point
`levels/level3.py`:

```python
INPUT_FRAGMENT = '<input type="text" name="display_name" value="{name}">'
raw_html = INPUT_FRAGMENT.format(name=name)
input_html = Markup(raw_html)
```

## How To Identify The Context
View source of the settings page. Your input lands inside `value="..."` on
an `<input>` element — you're inside an HTML *attribute*, not the page's
visible text content.

## Exploitation Methodology
1. A payload like `<script>alert(1)</script>` would just become inert text
   inside the `value` attribute string — it won't execute, because you're
   not in a text-content context.
2. HTML-encoding `<` and `>` (a very common but incomplete fix) doesn't
   matter here at all, because you don't need those characters — you need a
   literal double-quote to terminate the attribute.
3. Once the attribute is closed, the parser is back in tag context, so you
   can add a brand new attribute: an event handler.
4. Use an event that fires without user interaction — `autofocus` +
   `onfocus` works well on an `<input>` since focus is granted automatically
   on page load if nothing else has focus first.

## Example Payload
```
x" autofocus onfocus="xssLabSolve('level3')
```

Submitting this as the display name produces:
```html
<input type="text" name="display_name" value="x" autofocus onfocus="xssLabSolve('level3')">
```

## Why It Works
The browser's HTML parser doesn't know or care that `value="..."` was meant
to hold "just a name" — it only understands HTML syntax. A literal `"`
inside what the developer intended as a fully-contained string is enough to
end that string early from the parser's point of view.

## Correct Defensive Fix
Use context-aware encoding for HTML attributes specifically — encode `"`
(and `'`, `<`, `>`, `&`) before placing any user data inside an attribute
value. In Jinja2, simply rendering with `{{ name }}` inside a real template
(rather than hand-built strings wrapped in `Markup()`) uses Jinja2's
built-in HTML-attribute-safe autoescaping automatically.

## CWE Classification
CWE-79: Improper Neutralization of Input During Web Page Generation
('Cross-site Scripting') — specifically the attribute-context variant,
sometimes cross-referenced as CWE-83.

## OWASP Category
A03:2021 — Injection
