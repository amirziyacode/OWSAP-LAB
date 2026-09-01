# Level 4 — DOM-Based XSS

## Vulnerability
Purely client-side. `static/js/level4.js` reads `window.location.hash`
(everything after `#` in the URL, which is never sent to the server) and
writes it into the page using `element.innerHTML`.

## Injection Point
`static/js/level4.js`:

```js
const hash = window.location.hash;
const match = hash.match(/name=(.*)$/);
const rawName = match ? decodeURIComponent(match[1]) : "";
...
el.innerHTML = "Welcome, " + rawName;   // <-- unsafe sink
```

- **Source:** `window.location.hash`
- **Sink:** `innerHTML`

## How To Identify The Context
Because the server never sees this data (fragments aren't sent over HTTP),
inspecting server responses or logs won't reveal anything. You have to read
the client-side JavaScript to find where a URL-derived value flows into a
dangerous DOM API.

## Exploitation Methodology
1. Search the JS for common XSS *sources* (`location`, `document.URL`,
   `document.referrer`) and *sinks* (`innerHTML`, `outerHTML`,
   `document.write`, `eval`).
2. Here, the fragment is read, decoded, concatenated into a greeting string,
   and assigned to `innerHTML` — that's a classic DOM XSS pattern.
3. Craft a URL fragment containing a tag with a self-firing event handler
   (a `<script>` tag inserted via `innerHTML` will NOT execute in most
   browsers, but an `<img onerror=...>` will).
4. No page reload/network request is required — just navigate to the URL.

## Example Payload
```
http://127.0.0.1:5000/level4/#name=<img src=x onerror=xssLabSolve('level4')>
```

## Why It Works
`innerHTML` parses its input as real HTML and inserts live elements into the
DOM — it does not treat the string as inert text the way `textContent`
would. The browser then evaluates the `onerror` handler because the `<img>`
element fails to load `src=x`.

## Correct Defensive Fix
Use `element.textContent = "Welcome, " + rawName;` instead of `innerHTML`
when inserting plain text. If HTML formatting is genuinely required, build
DOM nodes explicitly (`document.createElement`, `.textContent` on child
nodes) or run the string through a sanitizer designed for DOM contexts
(e.g. `DOMPurify`) before assigning to `innerHTML`.

## CWE Classification
CWE-79: Improper Neutralization of Input During Web Page Generation
('Cross-site Scripting') — client-side / DOM-based subtype.

## OWASP Category
A03:2021 — Injection
