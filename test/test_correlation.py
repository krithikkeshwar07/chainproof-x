from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from fastapi.testclient import TestClient

from auth_test_helpers import authorized_client
from backend.app import create_app


def _at(seconds: int) -> str:
    from datetime import datetime, timedelta, timezone
    return (datetime(2026, 10, 10, 12, 0, 0, 0, tzinfo=timezone.utc) + timedelta(seconds=seconds)).isoformat(timespec='milliseconds').replace('+00:00', 'Z')


def _windows(event_id: str, source: str, second: int, account: str = 'ACME\\alice', computer: str = 'WS-01') -> dict[str, str]:
    return {'format': 'windows_event_v1', 'eventId': event_id, 'sourceId': source, 'occurredAt': _at(second),
            'eventType': 'logon_success', 'account': account, 'computer': computer}


def _linux(event_id: str, source: str, second: int, user: str = 'acme\\alice', host: str = 'ws-01') -> dict[str, str]:
    return {'format': 'linux_audit_v1', 'eventId': event_id, 'sourceId': source, 'occurredAt': _at(second),
            'eventType': 'USER_LOGIN', 'user': user, 'host': host}


def _network(event_id: str, source: str, second: int, hostname: str = 'WS-01', destination: str = '192.0.2.5') -> dict[str, str]:
    return {'format': 'network_event_v1', 'eventId': event_id, 'sourceId': source, 'occurredAt': _at(second),
            'eventType': 'connection', 'hostname': hostname, 'destinationIp': destination}


def _make_client(tmp_path: Path) -> TestClient:
    return authorized_client(create_app(tmp_path / 'correlation.sqlite3', tmp_path / 'evidence'))


def _create_case(client: TestClient) -> str:
    response = client.post('/api/v1/cases', json={'name': 'Synthetic correlation case'})
    assert response.status_code == 201, response.text
    return response.json()['id']


def _ingest(client: TestClient, case_id: str, event: dict[str, str]):
    return client.post(
        f'/api/v1/cases/{case_id}/evidence',
        files={'file': (f"{event['eventId']}.json", json.dumps(event).encode('utf-8'), 'application/json')},
        data={'event': json.dumps(event)},
    )


def test_source_adapters_normalize_three_synthetic_formats_and_correlate_with_references(tmp_path: Path):
    client = _make_client(tmp_path)
    with client:
        case_id = _create_case(client)
        inputs = [
            _windows('evt-win-1', 'windows-host-a', 0),
            _linux('evt-linux-1', 'linux-host-b', 300),
            _network('evt-net-1', 'sensor-c', 600),
        ]
        uploaded = [_ingest(client, case_id, item) for item in inputs]
        assert [item.status_code for item in uploaded] == [201, 201, 201]
        normalized = [item.json()['event'] for item in uploaded]
        assert normalized[0]['eventType'] == 'windows.logon_success'
        assert normalized[0]['actor'] == 'ACME\\alice'
        assert normalized[1]['eventType'] == 'linux_audit.USER_LOGIN'
        assert normalized[2]['eventType'] == 'network.connection'
        assert normalized[2]['target'] == '192.0.2.5'

        first_run = client.post(f'/api/v1/cases/{case_id}/correlations/recompute')
        assert first_run.status_code == 200, first_run.text
        body = first_run.json()
        assert body['event_count'] == 3
        assert body['correlation_count'] == 2
        assert body['window_seconds'] == 300
        assert all(record['rule_id'] == 'shared-entity-window-v1' for record in body['correlations'])
        assert [record['matched_entities'] for record in body['correlations']] == [
            ['host:ws-01', 'user:acme\\alice'], ['host:ws-01'],
        ]
        assert all(len(record['events']) == 2 and all(ref['evidence_id'] for ref in record['events']) for record in body['correlations'])
        assert all('distinct sources' in record['explanation'] for record in body['correlations'])

        second_run = client.post(f'/api/v1/cases/{case_id}/correlations/recompute').json()
        assert [row['id'] for row in second_run['correlations']] == [row['id'] for row in body['correlations']]
        with sqlite3.connect(tmp_path / 'correlation.sqlite3') as connection:
            assert connection.execute('SELECT count(*) FROM correlations').fetchone()[0] == 2
            assert connection.execute('SELECT count(*) FROM correlation_events').fetchone()[0] == 4

        graph = client.get(f'/api/v1/cases/{case_id}/trust-graph')
        assert graph.status_code == 200
        graph_body = graph.json()
        node_types = {node['type'] for node in graph_body['nodes']}
        assert {'case', 'event', 'evidence', 'entity', 'incident'} <= node_types
        assert graph_body['correlation_count'] == 2
        correlated_edges = [edge for edge in graph_body['edges'] if edge['relationship'] == 'correlated_by']
        assert len(correlated_edges) == 4
        assert all(edge['rule_id'] == 'shared-entity-window-v1' and edge['evidence_ids'] for edge in correlated_edges)


def test_unrelated_source_events_do_not_correlate(tmp_path: Path):
    client = _make_client(tmp_path)
    with client:
        case_id = _create_case(client)
        assert _ingest(client, case_id, _windows('evt-win-2', 'win-source', 0)).status_code == 201
        assert _ingest(client, case_id, _linux('evt-linux-2', 'linux-source', 10, user='other-user', host='other-host')).status_code == 201
        response = client.post(f'/api/v1/cases/{case_id}/correlations/recompute')
        assert response.status_code == 200
        assert response.json()['correlations'] == []


def test_time_window_is_inclusive_at_300_seconds_and_excludes_301_seconds(tmp_path: Path):
    client = _make_client(tmp_path)
    with client:
        case_id = _create_case(client)
        assert _ingest(client, case_id, _windows('evt-win-edge', 'win-one', 0)).status_code == 201
        assert _ingest(client, case_id, _linux('evt-linux-edge', 'linux-two', 300)).status_code == 201
        assert _ingest(client, case_id, _network('evt-net-outside', 'net-three', 601)).status_code == 201
        result = client.post(f'/api/v1/cases/{case_id}/correlations/recompute').json()
        pairs = [{event['event_id'] for event in item['events']} for item in result['correlations']]
        assert pairs == [{'evt-win-edge', 'evt-linux-edge'}]


def test_duplicate_event_ids_are_rejected_and_not_double_counted(tmp_path: Path):
    client = _make_client(tmp_path)
    with client:
        case_id = _create_case(client)
        original = _windows('evt-duplicate', 'win-one', 0)
        assert _ingest(client, case_id, original).status_code == 201
        duplicate = _windows('evt-duplicate', 'win-two', 5, account='ACME\\alice', computer='WS-01')
        rejected = _ingest(client, case_id, duplicate)
        assert rejected.status_code == 409
        result = client.post(f'/api/v1/cases/{case_id}/correlations/recompute').json()
        assert result['event_count'] == 1
        assert result['correlation_count'] == 0


def test_explicit_organization_and_graph_api_failures_and_empty_states(tmp_path: Path):
    client = _make_client(tmp_path)
    with client:
        case_id = _create_case(client)
        empty = client.get(f'/api/v1/cases/{case_id}/trust-graph')
        assert empty.status_code == 200
        assert empty.json() == {'case_id': case_id, 'nodes': [], 'edges': [], 'correlation_count': 0}
        missing = '00000000-0000-4000-8000-000000000000'
        assert client.get(f'/api/v1/cases/{missing}/trust-graph').status_code == 404

        association = client.post(f'/api/v1/cases/{case_id}/organizations', json={'name': 'Synthetic Organization'})
        assert association.status_code == 201
        assert association.json()['relationship_basis'] == 'explicit_case_metadata'
        assert client.post(f'/api/v1/cases/{case_id}/organizations', json={'name': 'Another Org'}).status_code == 409
        graph = client.get(f'/api/v1/cases/{case_id}/trust-graph').json()
        assert {node['type'] for node in graph['nodes']} == {'case', 'organization'}
        assert graph['edges'][0]['relationship'] == 'associated_with'
