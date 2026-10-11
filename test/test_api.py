from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from auth_test_helpers import authorized_client
from backend.app import MAX_UPLOAD_BYTES, create_app
from backend.chain import AnchorReceipt, ChainUnavailable


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
    with authorized_client(app) as test_client:
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
    assert client.get('/health').json() == {'status': 'ok', 'workspace_mode': 'local'}
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


def test_health_identifies_the_isolated_demo_workspace(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setenv('CPX_WORKSPACE_MODE', 'competition-demo')
    app = create_app(tmp_path / 'demo.sqlite3', tmp_path / 'demo-evidence')
    with authorized_client(app) as client:
        assert client.get('/health').json() == {'status': 'ok', 'workspace_mode': 'competition-demo'}


def test_state_changing_browser_requests_reject_remote_origins(client: TestClient):
    rejected = client.post('/api/v1/cases', json={'name': 'remote origin'}, headers={'origin': 'https://attacker.example'})
    assert rejected.status_code == 403
    assert rejected.json()['detail'] == 'state-changing browser requests require a local ChainProof X origin'
    accepted = client.post('/api/v1/cases', json={'name': 'local origin'}, headers={'origin': 'http://127.0.0.1:5173'})
    assert accepted.status_code == 201, accepted.text
    # Origin-free API clients remain available for local CLI and automated use.
    assert client.post('/api/v1/cases', json={'name': 'local client'}).status_code == 201


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
        evidence_columns = {row[1] for row in connection.execute('PRAGMA table_info(evidence_objects)')}
    assert evidence == (len(original), digest, f'{digest[:2]}/{digest}.bin')
    assert event_row[0] == SYNTHETIC_EVENT['eventId']
    assert event_row[1] == '{"eventId":"evt-001","sourceId":"synthetic-host","occurredAt":"2026-10-10T12:34:56.789Z","eventType":"login.success","actor":"josé@example.test","target":"srv-01"}'
    assert event_row[2] == hashlib.sha256(event_row[1].encode()).hexdigest()
    assert event_row[3] == result['evidence_id']
    assert 'normalized_json' not in evidence_columns


def _insert_recorded_anchor(database: Path, case_id: str) -> dict[str, object]:
    values: dict[str, object] = {
        'batch_id': '0x' + '1' * 64,
        'case_id': case_id,
        'merkle_root': '0x' + '2' * 64,
        'leaf_count': 1,
        'tree_version': 'cpx-merkle-v1',
        'chain_id': 31337,
        'contract_address': '0x' + 'a' * 40,
        'sender_address': '0x' + 'b' * 40,
        'tx_hash': '0x' + '3' * 64,
        'block_number': 8,
        'block_hash': '0x' + '4' * 64,
        'anchored_at': 1791633600,
        'created_at': '2026-10-10T12:00:00Z',
    }
    with sqlite3.connect(database) as connection:
        connection.execute(
            '''INSERT INTO blockchain_anchors
               (batch_id, case_id, merkle_root, leaf_count, tree_version, chain_id,
                contract_address, sender_address, tx_hash, block_number, block_hash,
                anchored_at, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            tuple(values[key] for key in (
                'batch_id', 'case_id', 'merkle_root', 'leaf_count', 'tree_version', 'chain_id',
                'contract_address', 'sender_address', 'tx_hash', 'block_number', 'block_hash',
                'anchored_at', 'created_at',
            )),
        )
    return values


def test_stored_anchor_is_recorded_and_unavailable_rpc_is_not_verified(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    case_id = create_case(client, 'Recorded anchor state')
    anchor = _insert_recorded_anchor(tmp_path / 'case.sqlite3', case_id)

    listed = client.get(f'/api/v1/cases/{case_id}/anchors')
    assert listed.status_code == 200
    assert listed.json()[0]['verification_status'] == 'recorded'
    detail = client.get(f"/api/v1/anchors/{anchor['batch_id']}")
    assert detail.status_code == 200
    assert detail.json()['verification_status'] == 'recorded'

    class UnavailableVerifier:
        contract_address = str(anchor['contract_address'])

        @staticmethod
        def verify_receipt(*_args: object, **_kwargs: object) -> AnchorReceipt:
            raise ChainUnavailable('Local Hardhat RPC is unavailable.')

    monkeypatch.setattr('backend.app.configured_chain_client', UnavailableVerifier)
    unavailable = client.get(f"/api/v1/anchors/{anchor['batch_id']}/verify")
    assert unavailable.status_code == 503
    assert unavailable.json().get('verification_status') != 'verified'


def test_successful_anchor_verifier_returns_verified(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    case_id = create_case(client, 'Verified anchor state')
    anchor = _insert_recorded_anchor(tmp_path / 'case.sqlite3', case_id)
    receipt = AnchorReceipt(
        tx_hash=str(anchor['tx_hash']), block_number=int(anchor['block_number']),
        block_hash=str(anchor['block_hash']), chain_id=int(anchor['chain_id']),
        contract_address=str(anchor['contract_address']), sender_address=str(anchor['sender_address']),
        merkle_root=str(anchor['merkle_root']), batch_id=str(anchor['batch_id']),
        anchored_at=int(anchor['anchored_at']),
    )

    class SuccessfulVerifier:
        contract_address = str(anchor['contract_address'])

        @staticmethod
        def verify_receipt(*_args: object, **_kwargs: object) -> AnchorReceipt:
            return receipt

    monkeypatch.setattr('backend.app.configured_chain_client', SuccessfulVerifier)
    verified = client.get(f"/api/v1/anchors/{anchor['batch_id']}/verify")
    assert verified.status_code == 200
    assert verified.json()['verification_status'] == 'verified'


def test_evidence_storage_and_sqlite_files_are_owner_only_on_posix(client: TestClient, tmp_path: Path):
    if os.name != 'posix':
        pytest.skip('POSIX permission-bit checks do not apply on Windows')
    case_id = create_case(client)
    evidence = ingest(client, case_id, content=b'private synthetic bytes').json()
    evidence_path = tmp_path / 'evidence' / evidence['sha256'][:2] / f"{evidence['sha256']}.bin"
    assert stat.S_IMODE((tmp_path / 'case.sqlite3').stat().st_mode) == 0o600
    assert stat.S_IMODE((tmp_path / 'evidence').stat().st_mode) == 0o700
    assert stat.S_IMODE(evidence_path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(evidence_path.stat().st_mode) == 0o600


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

    def unavailable(_root: Path, _storage_key: str) -> tuple[None, None, None]:
        from fastapi import HTTPException
        raise HTTPException(status_code=503, detail='integrity hasher is unavailable')

    monkeypatch.setattr('backend.app._hash_evidence_blob', unavailable)
    response = client.get(f"/api/v1/evidence/{evidence['evidence_id']}/verify")
    assert response.status_code == 503
    assert response.json() == {'detail': 'integrity hasher is unavailable'}


def test_verification_and_report_reject_symlinked_blob_without_reading_outside(client: TestClient, tmp_path: Path):
    case_id = create_case(client)
    evidence = ingest(client, case_id, content=b'evidence original').json()
    outside = tmp_path / 'outside.bin'
    outside.write_bytes(b'evidence original')
    stored = tmp_path / 'evidence' / evidence['sha256'][:2] / f"{evidence['sha256']}.bin"
    stored.unlink()
    stored.symlink_to(outside)

    check = client.get(f"/api/v1/evidence/{evidence['evidence_id']}/verify").json()
    assert check['valid'] is False
    assert check['reason'] == 'stored_object_path_invalid'
    report = client.get(f'/api/v1/cases/{case_id}/reports/forensic.json').json()
    assert report['evidence'][0]['byte_integrity_check']['valid'] is False
    assert report['evidence'][0]['byte_integrity_check']['reason'] == 'stored_object_path_invalid'
    assert outside.read_bytes() == b'evidence original'


def test_normalized_event_tampering_fails_closed_for_integrity_context_and_reports(client: TestClient, tmp_path: Path):
    case_id = create_case(client)
    item = ingest(client, case_id).json()
    with sqlite3.connect(tmp_path / 'case.sqlite3') as connection:
        connection.execute(
            'UPDATE event_records SET normalized_json = ? WHERE event_id = ?',
            (json.dumps({**SYNTHETIC_EVENT, 'target': 'attacker-controlled'}), SYNTHETIC_EVENT['eventId']),
        )
    context = client.get(f'/api/v1/cases/{case_id}/verification/context')
    assert context.status_code == 409
    assert 'normalized event integrity mismatch' in context.json()['detail']
    report = client.get(f'/api/v1/cases/{case_id}/reports/forensic.json')
    assert report.status_code == 409
    assert client.get(f'/api/v1/cases/{case_id}/evidence').status_code == 409
    assert client.get(f'/api/v1/cases/{case_id}/trust-graph').status_code == 409
    assert client.post(f'/api/v1/cases/{case_id}/correlations/recompute').status_code == 409
    assert client.post(f'/api/v1/cases/{case_id}/anchors', json={'batch_id': '0x' + '9' * 64}).status_code == 409
    assert client.get(f"/api/v1/evidence/{item['evidence_id']}/verify").json()['valid'] is True


def test_ingestion_refuses_symlinked_content_addressed_prefix(client: TestClient, tmp_path: Path):
    case_id = create_case(client)
    payload = b'evidence must remain inside configured root'
    digest = hashlib.sha256(payload).hexdigest()
    outside = tmp_path / 'outside'
    outside.mkdir()
    prefix = tmp_path / 'evidence' / digest[:2]
    prefix.symlink_to(outside, target_is_directory=True)

    response = ingest(client, case_id, content=payload)
    assert response.status_code == 500
    assert response.json()['detail'] == 'evidence object storage path is invalid'
    assert list(outside.iterdir()) == []
    with sqlite3.connect(tmp_path / 'case.sqlite3') as connection:
        assert connection.execute('SELECT count(*) FROM evidence_objects').fetchone()[0] == 0
        assert connection.execute('SELECT count(*) FROM event_records').fetchone()[0] == 0


def test_app_refuses_symlinked_evidence_root(tmp_path: Path):
    outside = tmp_path / 'outside-root'
    outside.mkdir()
    link = tmp_path / 'evidence-link'
    link.symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match='evidence storage root must not be a symlink'):
        create_app(tmp_path / 'db.sqlite3', link)
    assert list(outside.iterdir()) == []


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
