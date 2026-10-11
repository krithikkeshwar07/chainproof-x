from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.app import create_app


VIEWER = 'viewer-test-token-' + 'v' * 50
ANALYST = 'analyst-test-token-' + 'a' * 50


def test_health_is_public_but_case_data_requires_authentication(tmp_path: Path):
    with TestClient(create_app(tmp_path / 'db.sqlite3', tmp_path / 'evidence')) as client:
        assert client.get('/health').status_code == 200
        assert client.get('/api/v1/cases').status_code == 401
        assert client.post('/api/v1/cases', json={'name': 'unauthenticated'}).status_code == 401
        case_id = '8be9e1e3-a413-4984-a999-5ef1a06e1e5e'
        evidence_id = '3e5ecbb3-5931-435f-b9f5-c8de8f263027'
        assert client.get(f'/api/v1/cases/{case_id}/investigations').status_code == 401
        assert client.get(f'/api/v1/evidence/{evidence_id}/verify').status_code == 401
        assert client.get(f'/api/v1/cases/{case_id}/reports/forensic.json').status_code == 401
        assert client.get(f"/api/v1/anchors/{'0x' + '1' * 64}/verify").status_code == 401


def test_viewer_can_read_but_cannot_change_case_state(tmp_path: Path):
    with TestClient(create_app(tmp_path / 'db.sqlite3', tmp_path / 'evidence')) as client:
        viewer = {'Authorization': f'Bearer {VIEWER}'}
        assert client.get('/api/v1/session', headers=viewer).json() == {'role': 'viewer'}
        assert client.get('/api/v1/cases', headers=viewer).status_code == 200
        assert client.post('/api/v1/cases', headers=viewer, json={'name': 'denied'}).status_code == 403


def test_analyst_can_create_case_and_bad_tokens_are_rejected(tmp_path: Path):
    with TestClient(create_app(tmp_path / 'db.sqlite3', tmp_path / 'evidence')) as client:
        analyst = {'Authorization': f'Bearer {ANALYST}'}
        assert client.get('/api/v1/session', headers=analyst).json() == {'role': 'analyst'}
        created = client.post('/api/v1/cases', headers=analyst, json={'name': 'authorized'} )
        assert created.status_code == 201
        assert created.json()['name'] == 'authorized'
        assert client.get('/api/v1/cases', headers={'Authorization': 'Bearer wrong'}).status_code == 401


def test_missing_or_weak_server_tokens_fail_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv('CPX_API_VIEWER_TOKEN', raising=False)
    monkeypatch.delenv('CPX_API_ANALYST_TOKEN', raising=False)
    with TestClient(create_app(tmp_path / 'db.sqlite3', tmp_path / 'evidence')) as client:
        response = client.get('/api/v1/cases')
        assert response.status_code == 503
        assert 'authentication is not configured' in response.json()['detail']

    monkeypatch.setenv('CPX_API_ANALYST_TOKEN', 'short')
    with TestClient(create_app(tmp_path / 'weak.sqlite3', tmp_path / 'weak-evidence')) as client:
        response = client.get('/api/v1/cases')
        assert response.status_code == 503


def test_same_token_cannot_be_assigned_two_roles(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    token = 'same-test-token-' + 's' * 50
    monkeypatch.setenv('CPX_API_VIEWER_TOKEN', token)
    monkeypatch.setenv('CPX_API_ANALYST_TOKEN', token)
    with TestClient(create_app(tmp_path / 'db.sqlite3', tmp_path / 'evidence')) as client:
        response = client.get('/api/v1/cases', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 503
