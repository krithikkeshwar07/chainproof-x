import os
import shutil
import tempfile
from pathlib import Path

import pytest


# backend.app exposes a module-level FastAPI object, so importing it initializes
# a database. Redirect that import-time instance before pytest collects tests.
PYTEST_DATA_ROOT = Path(tempfile.mkdtemp(prefix='chainproof-pytest-')).resolve()
os.environ['CHAINPROOF_DB'] = str(PYTEST_DATA_ROOT / 'module-app.sqlite3')
os.environ['CHAINPROOF_EVIDENCE_DIR'] = str(PYTEST_DATA_ROOT / 'evidence')
os.environ['CHAINPROOF_DEPLOYMENT_FILE'] = str(PYTEST_DATA_ROOT / 'deployment.json')


@pytest.fixture(autouse=True)
def isolated_api_access_tokens(monkeypatch: pytest.MonkeyPatch):
    # Test-only credentials. Never used by the application launcher.
    monkeypatch.setenv('CPX_API_VIEWER_TOKEN', 'viewer-test-token-' + 'v' * 50)
    monkeypatch.setenv('CPX_API_ANALYST_TOKEN', 'analyst-test-token-' + 'a' * 50)


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    # This path is created for this pytest process and is never caller-supplied.
    if PYTEST_DATA_ROOT.name.startswith('chainproof-pytest-') and PYTEST_DATA_ROOT.parent == Path(tempfile.gettempdir()).resolve():
        shutil.rmtree(PYTEST_DATA_ROOT)
