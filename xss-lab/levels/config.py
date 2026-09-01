"""
Central registry of level metadata: names, difficulty, flags, and hints.

Flags are only ever handed to the client through get_flag_if_completed(),
which checks the `progress` table first. Nothing in this module is reachable
from a normal page render.
"""

from dataclasses import dataclass, field
from typing import List


@dataclass
class LevelInfo:
    id: str
    number: int
    name: str
    difficulty: str
    flag: str
    hints: List[str] = field(default_factory=list)
    summary: str = ""


LEVELS = {
    "level1": LevelInfo(
        id="level1",
        number=1,
        name="Reflected XSS in Search",
        difficulty="Easy",
        flag="FLAG{XSS_LEVEL_1_reflected_search_no_encoding}",
        hints=[
            "Hint 1 — Your search term is echoed back into the page. Where exactly does it land in the HTML?",
            "Hint 2 — Check the page source (not just what's visually shown) for the text 'Search results for:'. Is your input inside a tag's text content or an attribute?",
            "Hint 3 — If you're in HTML text content, closing tags like </script> aren't needed — a bare <script>...</script> or an <img onerror=...> will do. Try injecting a tag that runs JS on load/error.",
        ],
        summary="A product search page reflects the ?q= parameter directly into the results heading without HTML-encoding it.",
    ),
    "level2": LevelInfo(
        id="level2",
        number=2,
        name="Stored XSS in Comments",
        difficulty="Easy → Medium",
        flag="FLAG{XSS_LEVEL_2_stored_comment_hits_admin}",
        hints=[
            "Hint 1 — Comments are saved to a database and re-rendered on every page load, for every visitor, including the admin who periodically reviews new comments.",
            "Hint 2 — Look at how the comment body is inserted into the template. Is it treated as plain text or raw HTML?",
            "Hint 3 — A payload that works for you when you view the page will also run for the admin when they view it. You don't need to trick anyone — just get the admin to load the page.",
        ],
        summary="Blog comments are stored in SQLite and rendered with the |safe filter, so any HTML/JS in a comment executes for every viewer, including a simulated admin who reviews comments periodically.",
    ),
    "level3": LevelInfo(
        id="level3",
        number=3,
        name="Attribute Context XSS",
        difficulty="Medium",
        flag="FLAG{XSS_LEVEL_3_broke_out_of_attribute}",
        hints=[
            "Hint 1 — Your display name ends up inside value=\"...\" on the settings page, not in the page's text content.",
            "Hint 2 — HTML-encoding text content (like escaping < and >) doesn't help if you can still inject a literal double-quote to close the attribute early.",
            "Hint 3 — If you can close the value=\" attribute, the parser is back in tag context. You don't need a new <script> tag — a new attribute like onmouseover or autofocus onfocus can execute JS on an <input>.",
        ],
        summary="A profile settings page places the user's display name inside an unquoted-unsafe HTML attribute (value=\"...\") without attribute-context encoding.",
    ),
    "level4": LevelInfo(
        id="level4",
        number=4,
        name="DOM-Based XSS",
        difficulty="Medium",
        flag="FLAG{XSS_LEVEL_4_dom_innerhtml_fragment}",
        hints=[
            "Hint 1 — Nothing is sent to the server here. Look at the client-side JavaScript that reads window.location.hash.",
            "Hint 2 — The 'source' is the URL fragment after #name=, and the 'sink' is where that value gets written into the page. Search the JS for innerHTML.",
            "Hint 3 — Fragments (#...) never reach the server, so this must be triggered purely by visiting a crafted URL. Build a #name= value containing an HTML tag with an event handler.",
        ],
        summary="Client-side JavaScript reads the #name= URL fragment and writes it into the DOM using innerHTML instead of textContent.",
    ),
    "level5": LevelInfo(
        id="level5",
        number=5,
        name="XSS in JavaScript String Context",
        difficulty="Medium → Hard",
        flag="FLAG{XSS_LEVEL_5_broke_out_of_js_string}",
        hints=[
            "Hint 1 — Your username isn't dropped into HTML text this time — it's dropped straight into a <script> block as a JavaScript string literal.",
            "Hint 2 — HTML-encoding (&lt; &gt;) doesn't matter at all here, because you're already inside a <script> tag. What matters is JavaScript string syntax.",
            "Hint 3 — If you can inject a literal double-quote followed by a semicolon, you can terminate the assignment and start writing your own JavaScript statements before the rest of the original line runs.",
        ],
        summary="A username is interpolated directly into a JavaScript string literal inside an inline <script> block, without JS-string escaping.",
    ),
    "level6": LevelInfo(
        id="level6",
        number=6,
        name="Filter / Blacklist Bypass",
        difficulty="Hard",
        flag="FLAG{XSS_LEVEL_6_blacklist_bypass_svg}",
        hints=[
            "Hint 1 — The comment form rejects input containing the literal substrings '<script', 'onerror', 'onload', and 'javascript:'. That's the entire filter.",
            "Hint 2 — HTML has dozens of elements that can execute JavaScript via event handlers. The filter only checks a handful of well-known ones, case-sensitively adjacent tricks aside.",
            "Hint 3 — Event handlers the filter doesn't know about (like onpointerover, onfocus, onanimationstart) still work, as do less common tags such as <svg> or <details>/<summary>. Combine an allowed tag with a blocked-list-evading handler.",
        ],
        summary="A comment field is 'protected' by a blacklist that string-matches a handful of known-bad substrings (<script, onerror, onload, javascript:) but still renders the result unescaped.",
    ),
    "level7": LevelInfo(
        id="level7",
        number=7,
        name="CSP + DOM XSS",
        difficulty="Hard",
        flag="FLAG{XSS_LEVEL_7_csp_bypass_via_nonce_gadget}",
        hints=[
            "Hint 1 — Open the response headers. There's a Content-Security-Policy that blocks inline <script> without a matching nonce, so alert(1) via a plain injected <script> tag won't fire.",
            "Hint 2 — CSP restricts *script execution*, not HTML injection. Look at what other DOM sinks or already-trusted (nonced) inline scripts exist on the page that you might be able to influence.",
            "Hint 3 — There's an inline script on the page that already carries a valid nonce and reads a value from the DOM (or from a JS variable populated from user input) and passes it to a dangerous sink like eval() or setTimeout(string). If you can influence *that* trusted script's data, you don't need your own <script> tag at all.",
        ],
        summary="A page ships a real CSP with a per-request nonce that blocks attacker-injected <script> tags, but a nonced first-party inline script unsafely passes DOM data into eval(), giving a script-tag-free DOM XSS path.",
    ),
    "level8": LevelInfo(
        id="level8",
        number=8,
        name="Realistic Multi-Step XSS Chain",
        difficulty="Expert",
        flag="FLAG{XSS_LEVEL_8_stored_xss_to_admin_session_action}",
        hints=[
            "Hint 1 — This mimics a small forum: you can log in as a low-privilege user, post a profile bio and comments, and there's an admin who periodically reviews the newest comments on the announcements post.",
            "Hint 2 — Your bio is rendered unsafely wherever your username is displayed to other users — including inside comments you post, via a 'preview card' that shows your bio on hover.",
            "Hint 3 — Chain it: put a payload in your bio, then post a comment (which shows your bio preview) on the announcements post the admin reviews. When the admin's bot loads that page, your bio-based payload executes in the admin's session and can call the app's own privileged API to trigger the flag.",
        ],
        summary="A stored bio field is rendered unsafely inside a hover-preview card shown on comments. An admin bot periodically reviews new comments on the announcements post, so a payload staged via bio + comment executes in the admin's session and can call a privileged app endpoint.",
    ),
}


def get_level(level_id: str) -> LevelInfo:
    return LEVELS[level_id]


def all_levels():
    return sorted(LEVELS.values(), key=lambda l: l.number)
