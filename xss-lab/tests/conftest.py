import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


@pytest.fixture()
def app():
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.environ["XSS_LAB_DB"] = db_path

    # Re-import app fresh so it picks up the temp DB path and initializes it.
    import importlib
    import database.db as db_module
    importlib.reload(db_module)
    import app as app_module
    importlib.reload(app_module)

    app_module.init_db(reset=True)
    app_module.app.config.update(TESTING=True)

    yield app_module.app

    os.close(db_fd)
    os.unlink(db_path)


@pytest.fixture()
def client(app):
    return app.test_client()
