from levels.utils import read_flag


def test_level3_benign_request(client):
    resp = client.post("/level3", data={"filename": "diag01", "format": "txt"})
    body = resp.get_data(as_text=True)
    assert read_flag("level3") not in body
    assert "preparing report" in body


def test_level3_filename_injection_is_blocked_by_validation(client):
    resp = client.post(
        "/level3", data={"filename": "diag01; cat flags/level3.txt", "format": "txt"}
    )
    body = resp.get_data(as_text=True)
    assert read_flag("level3") not in body
    assert "Invalid filename" in body


def test_level3_format_injection_reveals_flag(client):
    resp = client.post(
        "/level3", data={"filename": "diag01", "format": "txt; cat flags/level3.txt"}
    )
    body = resp.get_data(as_text=True)
    assert read_flag("level3") in body
