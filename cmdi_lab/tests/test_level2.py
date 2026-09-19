import re

from levels.utils import read_flag
from .conftest import poll_until_done


def _extract_job_id(html: str) -> str:
    m = re.search(r'const jobId = "([a-f0-9]+)"', html)
    assert m, "job id not found in response"
    return m.group(1)


def test_level2_get_shows_form(client):
    resp = client.get("/level2")
    assert resp.status_code == 200


def test_level2_benign_input_completes_quickly_no_flag(client):
    resp = client.post("/level2", data={"host": "127.0.0.1"})
    job_id = _extract_job_id(resp.get_data(as_text=True))
    result = poll_until_done(client, f"/level2/status?job_id={job_id}")
    assert result["duration"] < 3
    assert "flag" not in result


def test_level2_sleep_injection_reveals_flag(client):
    resp = client.post("/level2", data={"host": "127.0.0.1; sleep 5"})
    job_id = _extract_job_id(resp.get_data(as_text=True))
    result = poll_until_done(client, f"/level2/status?job_id={job_id}", timeout=25)
    assert result["duration"] >= 4
    assert result["flag"] == read_flag("level2")


def test_level2_unknown_job_returns_404(client):
    resp = client.get("/level2/status?job_id=doesnotexist")
    assert resp.status_code == 404
