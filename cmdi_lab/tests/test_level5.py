import os

from levels.utils import FLAGS_DIR, read_flag


def test_level5_benign_search(client):
    resp = client.post("/level5", data={"pattern": "*.txt"})
    body = resp.get_data(as_text=True)
    assert "notes.txt" in body
    assert read_flag("level5") not in body


def test_level5_shell_metacharacters_are_inert(client):
    # No shell is involved, so these should just be treated as literal
    # (and likely non-matching) filename patterns - not injection vectors.
    resp = client.post("/level5", data={"pattern": "*.txt; cat flags/level5.txt"})
    body = resp.get_data(as_text=True)
    assert read_flag("level5") not in body


def test_level5_exec_flag_injection_reveals_flag(client):
    flag_path = os.path.join(FLAGS_DIR, "level5.txt")
    resp = client.post("/level5", data={"pattern": f"* -exec cat {flag_path} ;"})
    body = resp.get_data(as_text=True)
    assert read_flag("level5") in body
