from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.app import MAX_UPLOAD_BYTES, create_app


SYNTHETIC_EVENT = {
    'eventId': 'evt-001',
    'sourceId': 'synthetic-host',
    'occurredAt': '2026-10-10T12:34:56.789Z',
    'eventType': 'login.success',
    'actor': 'josé@example.test',
    'target': 'srv-01',
}


@pytest.fixture
def client(tmp_path: Path):
    app = create_app(tmp_path / 'case.sqlite3', tmp_path / 'evidence')
    with TestClient(app) as test_client:
        yield test_client


def create_case(client: TestClient, name: str = 'Incident 1') -> str:
    response = client.post('/api/v1/cases', json={'name': name})
    assert response.status_code == 201, response.text
    return response.json()['id']


def ingest(client: TestClient, case_id: str, *, content: bytes = b'original evidence bytes', event: dict | str | None = None, filename: str = 'evidence.log'):
    if event is None:
        event = SYNTHETIC_EVENT
    event_json = event if isinstance(event, str) else json.dumps(event, ensure_ascii=False)
    return client.post(
        f'/api/v1/cases/{case_id}/evidence',
        files={'file': (filename, content, 'application/octet-stream')},
        data={'event': event_json},
    )


def test_case_validation_and_schema_are_created(client: TestClient, tmp_path: Path):
    assert client.get('/health').json() == {'status': 'ok'}
    assert client.post('/api/v1/cases', json={'name': '   '}).status_code == 422
    assert client.post('/api/v1/cases', json={'name': 'bad\u0001name'}).status_code == 422
    assert client.post('/api/v1/cases', json={'name': 'case', 'extra': True}).status_code == 422
    with sqlite3.connect(tmp_path / 'case.sqlite3') as connection:
        table_names = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {'cases', 'evidence_objects', 'event_records'} <= table_names
    case_id = create_case(client, 'Visible Case')
    listed = client.get('/api/v1/cases').json()
    assert listed[0]['id'] == case_id
    assert listed[0]['evidence_count'] == 0
    assert client.get(f'/api/v1/cases/{case_id}/evidence').json() == {'items': [], 'total': 0, 'limit': 50, 'offset': 0}


def test_ingestion_preserves_raw_bytes_and_stores_normalized_event_separately(client: TestClient, tmp_path: Path):
    case_id = create_case(client)
    original = b'{\n  "host": "synthetic", "record": 7, "padding": "source bytes stay exact"\n}\n'
    response = ingest(client, case_id, content=original, filename='../../logs/auth.json')
    assert response.status_code == 201, response.text
    result = response.json()
    digest = hashlib.sha256(original).hexdigest()
    assert result['sha256'] == digest
    assert result['filename'] == 'auth.json'
    assert result['event'] == SYNTHETIC_EVENT

    object_path = tmp_path / 'evidence' / digest[:2] / f'{digest}.bin'
    assert object_path.read_bytes() == original
    assert client.get(f"/api/v1/evidence/{result['evidence_id']}/verify").json()['valid'] is True
    listing = client.get(f'/api/v1/cases/{case_id}/evidence?limit=1').json()
    assert listing['total'] == 1
    assert listing['items'][0]['evidence_id'] == result['evidence_id']
    assert listing['items'][0]['event'] == SYNTHETIC_EVENT

    with sqlite3.connect(tmp_path / 'case.sqlite3') as connection:
        evidence = connection.execute('SELECT byte_length, sha256, storage_key FROM evidence_objects').fetchone()
        event_row = connection.execute(
            'SELECT event_id, normalized_json, canonical_sha256, evidence_id FROM event_records'
        ).fetchone()
    assert evidence == (len(original), digest, f'{digest[:2]}/{digest}.bin')
    assert event_row[0] == SYNTHETIC_EVENT['eventId']
    assert event_row[1] == '{"eventId":"evt-001","sourceId":"synthetic-host","occurredAt":"2026-10-10T12:34:56.789Z","eventType":"login.success","actor":"josé@example.test","target":"srv-01"}'
    assert event_row[2] == hashlib.sha256(event_row[1].encode()).hexdigest()
    assert event_row[3] == result['evidence_id']
    assert 'normalized_json' not in {row[1] for row in connection.execute('PRAGMA table_info(evidence_objects)')}


def test_invalid_and_ambiguous_events_do_not_store_evidence(client: TestClient, tmp_path: Path):
    case_id = create_case(client)
    malformed = {**SYNTHETIC_EVENT, 'occurredAt': '2026-02-30T12:34:56.000Z'}
    assert ingest(client, case_id, event=malformed).status_code == 422
    duplicate_json_key = '{"eventId":"one","eventId":"two"}'
    assert ingest(client, case_id, event=duplicate_json_key).status_code == 422
    unsupported_number = '{"unexpected":1e999}'
    assert ingest(client, case_id, event=unsupported_number).status_code == 422
    assert list((tmp_path / 'evidence').glob('*/*.bin')) == []
    with sqlite3.connect(tmp_path / 'case.sqlite3') as connection:
        assert connection.execute('SELECT count(*) FROM evidence_objects').fetchone()[0] == 0
        assert connection.execute('SELECT count(*) FROM event_records').fetchone()[0] == 0


def test_event_ids_are_unique_per_case_and_failed_insert_rolls_back(client: TestClient, tmp_path: Path):
    case_id = create_case(client)
    first = ingest(client, case_id, content=b'first').json()
    second = ingest(client, case_id, content=b'second')
    assert first['event']['eventId'] == SYNTHETIC_EVENT['eventId']
    assert second.status_code == 409
    with sqlite3.connect(tmp_path / 'case.sqlite3') as connection:
        assert connection.execute('SELECT count(*) FROM evidence_objects').fetchone()[0] == 1
        assert connection.execute('SELECT count(*) FROM event_records').fetchone()[0] == 1
    assert len(list((tmp_path / 'evidence').glob('*/*.bin'))) == 1


def test_upload_limit_and_missing_case_are_rejected(client: TestClient, tmp_path: Path):
    oversized = b'x' * (MAX_UPLOAD_BYTES + 1)
    unknown_case = '00000000-0000-4000-8000-000000000000'
    assert ingest(client, unknown_case, content=b'x').status_code == 404
    case_id = create_case(client)
    assert ingest(client, case_id, content=oversized).status_code == 413
    assert list((tmp_path / 'evidence').glob('ingest-*.part')) == []


def test_multipart_request_limit_rejects_oversized_body_before_storage(client: TestClient, tmp_path: Path):
    case_id = create_case(client)
    oversized_body = b'x' * (MAX_UPLOAD_BYTES + 128 * 1024 + 1)
    response = ingest(client, case_id, content=oversized_body)
    assert response.status_code == 413
    assert list((tmp_path / 'evidence').glob('ingest-*.part')) == []
    assert list((tmp_path / 'evidence').glob('*/*.bin')) == []


def test_verification_detects_modified_missing_and_invalid_storage_paths(client: TestClient, tmp_path: Path):
    case_id = create_case(client)
    result = ingest(client, case_id, content=b'checked bytes').json()
    path = tmp_path / 'evidence' / result['sha256'][:2] / f"{result['sha256']}.bin"
    path.write_bytes(b'tampered')
    mismatch = client.get(f"/api/v1/evidence/{result['evidence_id']}/verify").json()
    assert mismatch['valid'] is False
    assert mismatch['reason'] == 'digest_or_length_mismatch'
    path.unlink()
    missing = client.get(f"/api/v1/evidence/{result['evidence_id']}/verify").json()
    assert missing['valid'] is False
    assert missing['reason'] == 'stored_object_missing'

    result = ingest(client, case_id, content=b'another event', event={**SYNTHETIC_EVENT, 'eventId': 'evt-002'}).json()
    with sqlite3.connect(tmp_path / 'case.sqlite3') as connection:
        connection.execute('UPDATE evidence_objects SET storage_key = ? WHERE id = ?', ('../../outside', result['evidence_id']))
    invalid_path = client.get(f"/api/v1/evidence/{result['evidence_id']}/verify")
    assert invalid_path.status_code == 500
    assert invalid_path.json()['detail'] == 'stored evidence path is invalid'


def test_verification_integrity_hasher_unavailable_is_an_api_error(client: TestClient, monkeypatch: pytest.MonkeyPatch):
    case_id = create_case(client)
    evidence = ingest(client, case_id).json()

    def unavailable(_path: Path) -> str:
        from fastapi import HTTPException
        raise HTTPException(status_code=503, detail='integrity hasher is unavailable')

    monkeypatch.setattr('backend.app.integrity_sha256_file', unavailable)
    response = client.get(f"/api/v1/evidence/{evidence['evidence_id']}/verify")
    assert response.status_code == 503
    assert response.json() == {'detail': 'integrity hasher is unavailable'}


def test_duplicate_content_reuses_immutable_blob_but_creates_distinct_evidence_record(client: TestClient, tmp_path: Path):
    case_id = create_case(client)
    first = ingest(client, case_id, content=b'same bytes', event=SYNTHETIC_EVENT).json()
    second = ingest(client, case_id, content=b'same bytes', event={**SYNTHETIC_EVENT, 'eventId': 'evt-002'}).json()
    assert first['evidence_id'] != second['evidence_id']
    assert first['sha256'] == second['sha256']
    with sqlite3.connect(tmp_path / 'case.sqlite3') as connection:
        assert connection.execute('SELECT count(*) FROM evidence_objects').fetchone()[0] == 2
        assert connection.execute('SELECT count(*) FROM event_records').fetchone()[0] == 2
    assert len(list((tmp_path / 'evidence').glob('*/*.bin'))) == 1
