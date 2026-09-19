from levels.utils import read_flag


def test_each_level_page_has_flag_input(client):
    for i in range(1, 9):
        resp = client.get(f"/level{i}")
        assert resp.status_code == 200
        body = resp.get_data(as_text=True)
        assert 'name="flag"' in body
        assert 'action="/submit-flag"' in body


def test_correct_flag_is_accepted(client):
    resp = client.post(
        "/submit-flag",
        data={"level": "level1", "flag": read_flag("level1")},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert b"Flag accepted." in resp.data
    assert b"This level is solved." in resp.data

    index = client.get("/")
    assert b"Level 1" in index.data
    assert b"solved" in index.data


def test_wrong_flag_is_rejected(client):
    resp = client.post(
        "/submit-flag",
        data={"level": "level1", "flag": "FLAG{nope}"},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert b"Incorrect flag." in resp.data
    assert b"This level is solved." not in resp.data


def test_flag_for_one_level_does_not_solve_another(client):
    client.post("/submit-flag", data={"level": "level2", "flag": read_flag("level1")})
    resp = client.get("/level2")
    assert b"This level is solved." not in resp.data


def test_unknown_level_submit_is_404(client):
    resp = client.post("/submit-flag", data={"level": "level99", "flag": "FLAG{x}"})
    assert resp.status_code == 404
