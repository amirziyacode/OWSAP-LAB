from levels.utils import read_flag


def test_level7_benign_request(client):
    resp = client.post("/level7", data={"filename": "notes.txt", "operation": "info"})
    body = resp.get_data(as_text=True)
    assert "ASCII text" in body or "text" in body
    assert read_flag("level7") not in body


def test_level7_path_traversal_blocked(client):
    resp = client.post(
        "/level7", data={"filename": "../../app.py", "operation": "info"}
    )
    body = resp.get_data(as_text=True)
    assert "Rejected" in body


def test_level7_absolute_path_blocked(client):
    resp = client.post("/level7", data={"filename": "/etc/passwd", "operation": "info"})
    body = resp.get_data(as_text=True)
    assert "Rejected" in body


def test_level7_operation_injection_reveals_flag(client):
    resp = client.post(
        "/level7",
        data={"filename": "notes.txt", "operation": "brief; cat ../../flags/level7.txt #"},
    )
    body = resp.get_data(as_text=True)
    assert read_flag("level7") in body
