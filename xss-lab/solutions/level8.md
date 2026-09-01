# Level 8 — Realistic Multi-Step XSS Chain

## Vulnerability
Every user has a profile `bio`. Wherever a comment is displayed, the app
also renders a small "preview card" showing the comment author's bio —
unescaped, with `|safe` — exactly like Level 2's comment body bug, but this
time the injected content is your *bio*, not the comment text itself, and
the target page is one a simulated **admin** account periodically reviews.

## Injection Point
`templates/level8.html`:

```html
<div class="bio-preview" ...>
    {{ (c.author_bio or '')|safe }}
</div>
```

`levels/level8.py` stores the bio verbatim (parameterized SQL — no SQLi
here) via `/level8/profile`.

## How To Identify The Context
1. Log in (`alice` / `lab-password-1`).
2. Set your bio to a distinctive HTML marker and post any comment on the
   Announcements post.
3. Reload the page as yourself — notice your bio marker renders as real
   HTML next to your comment, not as escaped text.
4. Recognize the app describes an admin who "reviews new comments" — that
   means an *admin-context* render of this exact page happens on its own,
   without you doing anything else.

## Exploitation Methodology
This is a chain, not a single injection:
1. **Stage the payload:** set your bio to a self-firing payload (an
   `<img onerror=...>` works without needing a click), via
   `POST /level8/profile`.
2. **Trigger the render for the target:** post a comment on the
   Announcements post, via `POST /level8/comment` — this is the page the
   admin reviews, and your bio preview will render there.
3. **Wait for the privileged victim:** the app's simulated admin review
   loads that page and renders your bio in *its own* session context.
4. Because your payload now executes as the admin, it can call
   session-authenticated, privileged endpoints the admin has access to
   (in this lab, `/level8/api/promote`) that a plain user's session cannot
   meaningfully use — demonstrating that XSS impact isn't limited to
   `alert()` boxes, it's full action-on-behalf-of-the-victim.

## Example Payload
Set as your bio:
```
<img src=x onerror=xssLabSolve('level8')>
```
Then post any comment. The simulated admin review renders your bio preview
next to that comment and "executes" it in the admin's context.

## Why It Works
The chain works because a single unescaped rendering point (the bio
preview) is reachable from a lower-privilege account (your own profile) but
gets *rendered inside a higher-privilege session* (the admin's) whenever
that privileged user views a page containing your content. This is the
real-world pattern behind many serious XSS-to-account-takeover bugs: the
vulnerable input and the high-value target are different users entirely.

## Correct Defensive Fix
- Stop rendering `bio` with `|safe` — let Jinja2 autoescape it, or run it
  through an allow-list HTML sanitizer if limited formatting is a genuine
  product requirement.
- Apply the principle of least privilege to session-authenticated actions:
  a script running in an admin's browser inherits that admin's ambient
  authority by default, so sensitive actions ideally deserve extra
  confirmation (re-authentication, a CSRF-protected explicit action) rather
  than being reachable from any authenticated GET/click.
- Set a strong CSP as defense-in-depth (see Level 7) so that even if
  unescaped HTML is rendered, arbitrary inline script still can't execute.

## CWE Classification
CWE-79: Improper Neutralization of Input During Web Page Generation
('Cross-site Scripting'), combined with CWE-863 (Incorrect Authorization) in
spirit, since the ultimate impact depends on a privileged session executing
unprivileged user content.

## OWASP Category
A03:2021 — Injection. Also relevant: A01:2021 — Broken Access Control
(impact amplified by lack of extra protection around privileged actions).
