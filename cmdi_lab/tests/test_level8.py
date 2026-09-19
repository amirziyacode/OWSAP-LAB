import re

from levels.utils import read_flag
from .conftest import poll_until_done


def _extract_job_id(html: str) -> str:
    m = re.search(r'const jobId = "([a-f0-9]+)"', html)
    assert m, "job id not found in response"
    return m.group(1)


def test_level8_benign_job_no_flag_in_log(client):
    resp = client.post("/level8", data={"host": "127.0.0.1"})
    job_id = _extract_job_id(resp.get_data(as_text=True))

    status_result = poll_until_done(client, f"/level8/job/{job_id}")
    assert status_result["status"] == "done"

    log_resp = client.get(f"/level8/log/{job_id}")
    log = log_resp.get_json()["log"]
    assert read_flag("level8") not in log
    assert "bytes of data" in log


def test_level8_injection_reveals_flag_in_log(client):
    resp = client.post("/level8", data={"host": "127.0.0.1; cat flags/level8.txt"})
    job_id = _extract_job_id(resp.get_data(as_text=True))

    poll_until_done(client, f"/level8/job/{job_id}")

    log_resp = client.get(f"/level8/log/{job_id}")
    log = log_resp.get_json()["log"]
    assert read_flag("level8") in log


def test_level8_log_not_available_before_done(client):
    resp = client.post("/level8", data={"host": "127.0.0.1"})
    job_id = _extract_job_id(resp.get_data(as_text=True))
    log_resp = client.get(f"/level8/log/{job_id}")
    data = log_resp.get_json()
    assert data["status"] in ("queued", "running", "done")


def test_level8_unknown_job_404(client):
    assert client.get("/level8/job/doesnotexist").status_code == 404
    assert client.get("/level8/log/doesnotexist").status_code == 404
