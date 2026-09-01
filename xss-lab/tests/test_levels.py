"""
Level-specific tests. These check the *actual vulnerable behavior* (e.g.
"is user input reflected without HTML/JS/attribute encoding?") and the
*actual completion mechanism* (e.g. "does the simulated admin bot correctly
distinguish executable payloads from inert text?") rather than hard-coding
one exact payload as the only path to a pass.
"""


# ---------------------------------------------------------------------------
# Level 1 — Reflected XSS in search
# ---------------------------------------------------------------------------

def test_level1_reflects_input_without_html_encoding(client):
    payload = "<b>hello-world-marker</b>"
    resp = client.get(f"/level1/search?q={payload}")
    body = resp.get_data(as_text=True)
    # The real vulnerability: raw tags survive instead of being turned into
    # &lt;b&gt; entities. We check for the tag surviving, not one exact XSS PoC.
    assert "<b>hello-world-marker</b>" in body


def test_level1_safe_query_does_not_report_completion(client):
    resp = client.get("/level1/search?q=normal search term")
    assert resp.status_code == 200
    assert "FLAG{" not in resp.get_data(as_text=True)


# ---------------------------------------------------------------------------
# Level 2 — Stored XSS in comments (+ simulated admin review)
# ---------------------------------------------------------------------------

def test_level2_plain_text_comment_does_not_complete_level(client):
    client.post("/level2/comment", data={"author": "bob", "body": "just saying hi, no markup here"})
    resp = client.get("/level2/")
    assert "FLAG{" not in resp.get_data(as_text=True)


def test_level2_executable_comment_triggers_admin_review_and_flag(client):
    # A different executable payload than the one used in manual QA/docs,
    # to prove the detection logic evaluates real behavior, not a fixed string.
    client.post(
        "/level2/comment",
        data={"author": "mallory", "body": "<svg onload=xssLabSolve('level2')>"},
    )
    resp = client.get("/level2/")
    assert "FLAG{XSS_LEVEL_2" in resp.get_data(as_text=True)


def test_level2_comment_is_stored_verbatim(client):
    client.post("/level2/comment", data={"author": "carol", "body": "<i>stored-marker</i>"})
    resp = client.get("/level2/")
    assert "<i>stored-marker</i>" in resp.get_data(as_text=True)


# ---------------------------------------------------------------------------
# Level 3 — Attribute context XSS
# ---------------------------------------------------------------------------

def test_level3_quote_character_is_not_attribute_encoded(client):
    client.post("/level3/", data={"display_name": 'marker" data-broke-out="1'})
    resp = client.get("/level3/")
    body = resp.get_data(as_text=True)
    # A safe implementation would render &#34; for the quote; the vulnerable
    # implementation lets it through, which lets the attribute be closed.
    assert 'value="marker" data-broke-out="1"' in body


# ---------------------------------------------------------------------------
# Level 4 — DOM-based XSS (client-side; verify the unsafe sink exists)
# ---------------------------------------------------------------------------

def test_level4_page_loads_and_ships_vulnerable_js(client):
    resp = client.get("/level4/")
    assert resp.status_code == 200
    js_resp = client.get("/static/js/level4.js")
    assert js_resp.status_code == 200
    js = js_resp.get_data(as_text=True)
    # The real vulnerability: writing to innerHTML from a URL-derived source.
    assert "innerHTML" in js
    assert "location.hash" in js


# ---------------------------------------------------------------------------
# Level 5 — XSS in JavaScript string context
# ---------------------------------------------------------------------------

def test_level5_quote_breaks_out_of_js_string(client):
    # Different payload than the manual QA example, still testing the same
    # underlying property: a literal double-quote is not JS-escaped.
    client.post("/level5/", data={"username": 'z"; console.log("marker'})
    resp = client.get("/level5/")
    body = resp.get_data(as_text=True)
    assert 'const username = "z"; console.log("marker";' in body


# ---------------------------------------------------------------------------
# Level 6 — Filter/blacklist bypass
# ---------------------------------------------------------------------------

def test_level6_blacklisted_patterns_are_rejected(client):
    for bad in [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<body onload=alert(1)>",
        "<a href=javascript:alert(1)>click</a>",
    ]:
        client.post("/level6/comment", data={"author": "eve", "body": bad})
    resp = client.get("/level6/")
    body = resp.get_data(as_text=True)
    assert "FLAG{" not in body
    # None of the rejected bodies should have been stored/rendered.
    assert "alert(1)" not in body


def test_level6_unlisted_event_handler_bypasses_filter_and_completes(client):
    # onfocus/autofocus is not on the blacklist, unlike onerror/onload.
    client.post(
        "/level6/comment",
        data={"author": "eve", "body": "<input autofocus onfocus=xssLabSolve('level6')>"},
    )
    resp = client.get("/level6/")
    assert "FLAG{XSS_LEVEL_6" in resp.get_data(as_text=True)


# ---------------------------------------------------------------------------
# Level 7 — CSP + DOM XSS
# ---------------------------------------------------------------------------

def test_level7_sends_restrictive_csp_with_nonce(client):
    resp = client.get("/level7/")
    csp = resp.headers.get("Content-Security-Policy", "")
    assert "nonce-" in csp
    assert "object-src 'none'" in csp
    # Attacker-injected script tags (no nonce) should not be allowed by this policy.
    assert "script-src" in csp


def test_level7_theme_param_reaches_eval_unescaped(client):
    resp = client.get("/level7/?theme=z'); console.log('marker")
    body = resp.get_data(as_text=True)
    assert "eval(\"applyTheme('z'); console.log('marker')\")" in body


# ---------------------------------------------------------------------------
# Level 8 — Multi-step chain
# ---------------------------------------------------------------------------

def test_level8_requires_login_to_comment(client):
    resp = client.post("/level8/comment", data={"body": "hello"}, follow_redirects=True)
    assert "log in" in resp.get_data(as_text=True).lower()


def test_level8_full_chain_completes_via_admin_review(client):
    login = client.post(
        "/level8/login", data={"username": "alice", "password": "lab-password-1"}
    )
    assert login.status_code in (301, 302)

    client.post(
        "/level8/profile",
        data={"bio": "<img src=x onerror=xssLabSolve('level8')>"},
    )
    client.post("/level8/comment", data={"body": "hello from alice"})

    resp = client.get("/level8/")
    assert "FLAG{XSS_LEVEL_8" in resp.get_data(as_text=True)


def test_level8_wrong_password_rejected(client):
    resp = client.post(
        "/level8/login", data={"username": "alice", "password": "wrong"}, follow_redirects=True
    )
    assert "invalid credentials" in resp.get_data(as_text=True).lower()


def test_level8_benign_bio_does_not_complete_level(client):
    client.post("/level8/login", data={"username": "alice", "password": "lab-password-1"})
    client.post("/level8/profile", data={"bio": "I like hiking."})
    client.post("/level8/comment", data={"body": "just a normal comment"})
    resp = client.get("/level8/")
    assert "FLAG{" not in resp.get_data(as_text=True)
