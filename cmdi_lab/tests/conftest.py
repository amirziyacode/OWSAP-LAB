import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app  # noqa: E402


@pytest.fixture()
def app():
    application = create_app()
    application.config.update({"TESTING": True})
    yield application


@pytest.fixture()
def client(app):
    return app.test_client()


def poll_until_done(client, status_url, timeout=20, interval=0.3):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        resp = client.get(status_url)
        last = resp.get_json()
        if last.get("status") == "done":
            return last
        time.sleep(interval)
    raise TimeoutError(f"job did not finish in time: {last}")
