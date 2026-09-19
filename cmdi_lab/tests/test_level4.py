from levels.utils import read_flag


def test_level4_benign_request(client):
    resp = client.post("/level4", data={"host": "127.0.0.1"})
    assert "bytes of data" in resp.get_data(as_text=True)


def test_level4_classic_separators_are_blocked(client):
    payloads = [
        "127.0.0.1; cat flags/level4.txt",
        "127.0.0.1 && cat flags/level4.txt",
        "127.0.0.1 | cat flags/level4.txt",
        "$(cat flags/level4.txt)",
        "`cat flags/level4.txt`",
    ]
    for payload in payloads:
        resp = client.post("/level4", data={"host": payload})
        body = resp.get_data(as_text=True)
        assert "Rejected" in body
        assert read_flag("level4") not in body


def test_level4_newline_bypasses_blacklist(client):
    resp = client.post("/level4", data={"host": "127.0.0.1\ncat flags/level4.txt"})
    body = resp.get_data(as_text=True)
    assert read_flag("level4") in body
