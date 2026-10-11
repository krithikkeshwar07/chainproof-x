from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from auth_test_helpers import authorized_client
from backend.app import create_app


def _ingest(client: TestClient, case_id: str, event: dict[str, str]) -> dict:
    response = client.post(
        f'/api/v1/cases/{case_id}/evidence',
        files={'file': (f"{event['eventId']}.log", event['eventId'].encode(), 'text/plain')},
        data={'event': json.dumps(event)},
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_investigation_references_evidence_and_correlation_and_appears_in_graph_and_report(tmp_path: Path):
    with authorized_client(create_app(tmp_path / 'db.sqlite3', tmp_path / 'evidence')) as client:
        case = client.post('/api/v1/cases', json={'name': 'Investigation case'}).json()
        events = [
            {'format': 'windows_event_v1', 'eventId': 'evt-invest-win', 'sourceId': 'win-a', 'occurredAt': '2026-10-10T12:35:00.000Z', 'eventType': 'logon', 'account': 'analyst@example.test', 'computer': 'srv-01'},
            {'format': 'linux_audit_v1', 'eventId': 'evt-invest-linux', 'sourceId': 'linux-a', 'occurredAt': '2026-10-10T12:35:05.000Z', 'eventType': 'login', 'user': 'analyst@example.test', 'host': 'srv-01'},
        ]
        evidence = [_ingest(client, case['id'], event) for event in events]
        correlations = client.post(f"/api/v1/cases/{case['id']}/correlations/recompute").json()['correlations']
        assert correlations
        correlation_id = correlations[0]['id']

        created = client.post(f"/api/v1/cases/{case['id']}/investigations", json={
            'title': 'Review shared account activity', 'summary': 'Analyst review; causation is not established.',
            'evidence_ids': [item['evidence_id'] for item in evidence], 'correlation_ids': [correlation_id],
        })
        assert created.status_code == 201, created.text
        investigation = created.json()
        assert investigation['status'] == 'open'
        assert set(investigation['evidence_ids']) == {item['evidence_id'] for item in evidence}
        assert investigation['correlation_ids'] == [correlation_id]
        assert client.get(f"/api/v1/cases/{case['id']}/investigations").json() == [investigation]

        graph = client.get(f"/api/v1/cases/{case['id']}/trust-graph").json()
        node = next(item for item in graph['nodes'] if item['id'] == f"investigation:{investigation['id']}")
        assert node['type'] == 'investigation'
        assert any(edge['relationship'] == 'references_evidence' for edge in graph['edges'])
        assert any(edge['relationship'] == 'reviews_correlation_candidate' for edge in graph['edges'])

        report = client.get(f"/api/v1/cases/{case['id']}/reports/forensic.json").json()
        assert report['investigations'] == [investigation]
        assert any('do not establish causation' in item for item in report['verification_limitations'])

        closed = client.post(f"/api/v1/investigations/{investigation['id']}/status", json={'status': 'closed'})
        assert closed.status_code == 200
        assert closed.json()['status'] == 'closed'
        assert client.post(f"/api/v1/investigations/{investigation['id']}/status", json={'status': 'purged'}).status_code == 422


def test_investigation_rejects_cross_case_or_duplicate_references(tmp_path: Path):
    with authorized_client(create_app(tmp_path / 'db.sqlite3', tmp_path / 'evidence')) as client:
        case_a = client.post('/api/v1/cases', json={'name': 'Case A'}).json()
        case_b = client.post('/api/v1/cases', json={'name': 'Case B'}).json()
        event = {'eventId': 'evt-a', 'sourceId': 'src', 'occurredAt': '2026-10-10T12:35:00.000Z', 'eventType': 'login.success', 'actor': 'analyst@example.test', 'target': 'srv-01'}
        evidence = _ingest(client, case_a['id'], event)['evidence_id']
        cross_case = client.post(f"/api/v1/cases/{case_b['id']}/investigations", json={
            'title': 'Cross case', 'evidence_ids': [evidence],
        })
        assert cross_case.status_code == 422
        duplicate = client.post(f"/api/v1/cases/{case_a['id']}/investigations", json={
            'title': 'Duplicate ref', 'evidence_ids': [evidence, evidence],
        })
        assert duplicate.status_code == 422
        assert client.get(f"/api/v1/cases/{case_a['id']}/investigations").json() == []


def test_recomputing_linked_correlation_preserves_stable_reference(tmp_path: Path):
    with authorized_client(create_app(tmp_path / 'db.sqlite3', tmp_path / 'evidence')) as client:
        case = client.post('/api/v1/cases', json={'name': 'Stable correlation'}).json()
        events = [
            {'format': 'windows_event_v1', 'eventId': 'evt-stable-win', 'sourceId': 'win-a', 'occurredAt': '2026-10-10T12:35:00.000Z', 'eventType': 'logon', 'account': 'analyst@example.test', 'computer': 'srv-01'},
            {'format': 'linux_audit_v1', 'eventId': 'evt-stable-linux', 'sourceId': 'linux-a', 'occurredAt': '2026-10-10T12:35:05.000Z', 'eventType': 'login', 'user': 'analyst@example.test', 'host': 'srv-01'},
        ]
        [_ingest(client, case['id'], event) for event in events]
        correlation = client.post(f"/api/v1/cases/{case['id']}/correlations/recompute").json()['correlations'][0]
        created = client.post(f"/api/v1/cases/{case['id']}/investigations", json={
            'title': 'Track deterministic finding', 'correlation_ids': [correlation['id']],
        }).json()
        repeated = client.post(f"/api/v1/cases/{case['id']}/correlations/recompute")
        assert repeated.status_code == 200, repeated.text
        assert repeated.json()['correlations'][0]['id'] == correlation['id']
        assert client.get(f"/api/v1/cases/{case['id']}/investigations").json()[0]['id'] == created['id']
