import re


def test_health_endpoint(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ok"


def test_homepage_lists_all_levels(client):
    resp = client.get("/")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    for n in range(1, 9):
        assert f"[{n}]" in body


def test_all_levels_reachable(client):
    for i in range(1, 9):
        resp = client.get(f"/level{i}/")
        assert resp.status_code == 200, f"level{i} did not load"


def test_progress_page_reachable(client):
    resp = client.get("/progress")
    assert resp.status_code == 200


def test_flags_are_unique():
    from levels.config import all_levels
    flags = [lvl.flag for lvl in all_levels()]
    assert len(flags) == len(set(flags)), "duplicate flags detected"
    assert len(flags) == 8


def test_each_level_has_three_hints():
    from levels.config import all_levels
    for lvl in all_levels():
        assert len(lvl.hints) == 3, f"{lvl.id} does not have exactly 3 hints"


def test_flag_not_revealed_before_completion(client):
    resp = client.get("/level1/")
    body = resp.get_data(as_text=True)
    assert "FLAG{" not in body


def test_database_initializes(app):
    from database.db import query
    rows = query("SELECT username FROM users")
    usernames = {r["username"] for r in rows}
    assert {"alice", "admin"}.issubset(usernames)


def test_reset_progress_clears_completion(client):
    client.post("/api/report/level1")
    resp = client.get("/level1/")
    assert "FLAG{" in resp.get_data(as_text=True)

    client.post("/progress/reset")
    resp = client.get("/level1/")
    assert "FLAG{" not in resp.get_data(as_text=True)
