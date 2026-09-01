"""
Heuristic "would this execute as JavaScript in a browser?" detector.

This lab doesn't ship a headless browser, so for stored/DOM levels where a
simulated admin or bot "views" attacker-controlled content, we approximate
real browser parsing with pattern matching. This is intentionally similar to
(and just as fallible as) the kind of naive detection real blacklist filters
use — see Level 6, which exploits exactly this class of weakness.

This module is only used to decide whether the *simulated victim* would have
executed a script — it is NOT used as a defensive filter anywhere in the
vulnerable levels themselves.
"""

import re

_SCRIPT_TAG = re.compile(r"<\s*script[^>]*>", re.IGNORECASE)
_ON_EVENT_ATTR = re.compile(r"\son[a-z]+\s*=", re.IGNORECASE)
_JAVASCRIPT_URI = re.compile(r"javascript\s*:", re.IGNORECASE)
_DANGEROUS_TAGS = re.compile(r"<\s*(svg|img|iframe|body|input|details|video|audio)\b", re.IGNORECASE)


def looks_executable(raw_html: str) -> bool:
    """Rough heuristic for 'this raw HTML would run attacker JS in a real browser'."""
    if not raw_html:
        return False
    if _SCRIPT_TAG.search(raw_html):
        return True
    if _JAVASCRIPT_URI.search(raw_html):
        return True
    if _ON_EVENT_ATTR.search(raw_html) and _DANGEROUS_TAGS.search(raw_html):
        return True
    if _ON_EVENT_ATTR.search(raw_html) and "<" in raw_html:
        # Any tag carrying an on*= handler is enough in most browsers.
        return True
    return False
