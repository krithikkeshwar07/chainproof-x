from fastapi import FastAPI
from fastapi.testclient import TestClient


TEST_ANALYST_TOKEN = 'analyst-test-token-' + 'a' * 50


def authorized_client(app: FastAPI) -> TestClient:
    return TestClient(app, headers={'Authorization': f'Bearer {TEST_ANALYST_TOKEN}'})
