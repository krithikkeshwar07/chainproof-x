from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
import subprocess
from pathlib import Path

from fastapi.testclient import TestClient

from auth_test_helpers import authorized_client
from backend.app import create_app

EVENT = {
    'eventId': 'evt-report-01', 'sourceId': 'synthetic-host', 'occurredAt': '2026-10-10T12:34:56.789Z',
    'eventType': 'login.success', 'actor': 'analyst@example.test', 'target': 'srv-01',
}


def _signed_material(root: str, leaf_count: int, batch_id: str = 'verification-lab') -> dict[str, str]:
    script = """
import { createPublicKey } from 'node:crypto';
import { signBatch, publicKeyId, testOnlyPrivateKeyFromSeed } from './src/integrity.ts';
let input=''; for await (const part of process.stdin) input += part;
const { root, leafCount, batchId } = JSON.parse(input);
const privateKey = testOnlyPrivateKeyFromSeed(Buffer.alloc(32, 7));
const publicKey = createPublicKey(privateKey);
const keyId = publicKeyId(publicKey);
const batch = { version: 'cpx-signed-batch-v1', batchId, keyId, treeVersion: 'cpx-merkle-v1', leafCount, rootHash: root };
process.stdout.write(JSON.stringify({ keyId, publicKeyDer: publicKey.export({ format: 'der', type: 'spki' }).toString('base64'), signature: signBatch(batch, privateKey).toString('hex') }));
"""
    result = subprocess.run(
        ['node', '--experimental-strip-types', '--input-type=module', '-e', script],
        input=json.dumps({'root': root, 'leafCount': leaf_count, 'batchId': batch_id}),
        text=True, capture_output=True, check=True,
    )
    return json.loads(result.stdout)


def _setup(tmp_path: Path) -> tuple[TestClient, str, dict[str, str]]:
    app = create_app(tmp_path / 'report.sqlite3', tmp_path / 'evidence')
    client = authorized_client(app)
    case = client.post('/api/v1/cases', json={'name': '<Case> & Review'}).json()
    original = b'{ "raw": "source bytes", "id": 1 }\n'
    ingested = client.post(
        f"/api/v1/cases/{case['id']}/evidence",
        files={'file': ('source.json', original, 'application/json')},
        data={'event': json.dumps(EVENT)},
    )
    assert ingested.status_code == 201, ingested.text
    return client, case['id'], ingested.json()


def test_merkle_context_valid_and_invalid_proof_cases(tmp_path: Path):
    client, case_id, _ = _setup(tmp_path)
    context_response = client.get(f'/api/v1/cases/{case_id}/verification/context')
    assert context_response.status_code == 200, context_response.text
    context = context_response.json()
    proof_record = context['proofs'][0]
    body = {'event_id': EVENT['eventId'], 'expected_root': context['root_hash'], 'proof': proof_record['proof']}
    valid = client.post(f'/api/v1/cases/{case_id}/verification/proof', json=body).json()
    assert valid['valid'] is True
    assert valid['failed_check'] is None
    assert valid['reason'] == 'proof_valid'

    invalid = client.post(f'/api/v1/cases/{case_id}/verification/proof', json={**body, 'proof': {**body['proof'], 'leafIndex': 1}}).json()
    assert invalid['valid'] is False
    assert invalid['failed_check'] == 'merkle_inclusion_proof'
    assert invalid['reason'] == 'proof_malformed_or_root_mismatch'
    wrong_root = client.post(f'/api/v1/cases/{case_id}/verification/proof', json={**body, 'expected_root': '0' * 64}).json()
    assert wrong_root['valid'] is False
    assert wrong_root['reason'] == 'proof_malformed_or_root_mismatch'
    malformed = client.post(f'/api/v1/cases/{case_id}/verification/proof', json={**body, 'proof': {}})
    assert malformed.status_code == 422

    malformed_shape = client.post(f'/api/v1/cases/{case_id}/verification/proof', json={
        **body, 'proof': {**body['proof'], 'steps': [{'side': 'promote', 'hash': '0' * 64}]},
    })
    assert malformed_shape.status_code == 422
    unknown_field = client.post(f'/api/v1/cases/{case_id}/verification/proof', json={
        **body, 'proof': {**body['proof'], 'unexpected': 'ignored? no'},
    })
    assert unknown_field.status_code == 422
    too_many_steps = client.post(f'/api/v1/cases/{case_id}/verification/proof', json={
        **body, 'proof': {**body['proof'], 'steps': [{'side': 'promote'}] * 13},
    })
    assert too_many_steps.status_code == 422
    oversized_input = client.post(
        f'/api/v1/cases/{case_id}/verification/proof',
        content=b'{"proof":"' + b'x' * (32 * 1024) + b'"}',
        headers={'content-type': 'application/json'},
    )
    assert oversized_input.status_code == 413


def test_ed25519_registration_valid_invalid_signature_and_invalid_key(tmp_path: Path):
    client, case_id, _ = _setup(tmp_path)
    context = client.get(f'/api/v1/cases/{case_id}/verification/context').json()
    material = _signed_material(context['root_hash'], context['leaf_count'])
    registered = client.post('/api/v1/signing-keys', json={'public_key_der_base64': material['publicKeyDer']})
    assert registered.status_code == 201, registered.text
    assert registered.json()['key_id'] == material['keyId']
    valid = client.post(f'/api/v1/cases/{case_id}/verification/signature', json={
        'batch_id': 'verification-lab', 'key_id': material['keyId'], 'signature_hex': material['signature'],
    }).json()
    assert valid['valid'] is True
    assert valid['result'] == 'valid'

    invalid_signature = ('00' if material['signature'][:2] != '00' else '01') + material['signature'][2:]
    invalid = client.post(f'/api/v1/cases/{case_id}/verification/signature', json={
        'batch_id': 'verification-lab', 'key_id': material['keyId'], 'signature_hex': invalid_signature,
    }).json()
    assert invalid['valid'] is False
    assert invalid['failed_check'] == 'ed25519_signature'
    assert invalid['reason'] == 'signature_invalid_or_key_mismatch'

    bad_key = client.post('/api/v1/signing-keys', json={'public_key_der_base64': base64.b64encode(b'not a key').decode()})
    assert bad_key.status_code == 422


def test_manifest_reports_missing_and_unexpected_event_ids(tmp_path: Path):
    client, case_id, _ = _setup(tmp_path)
    missing = client.get(f'/api/v1/cases/{case_id}/completeness').json()
    assert missing['manifest_present'] is False
    assert missing['complete'] is None
    assert missing['reason'] == 'expected_event_manifest_not_configured'

    manifest = client.put(f'/api/v1/cases/{case_id}/expected-events', json={
        'expected_event_ids': [EVENT['eventId'], 'evt-not-ingested'],
    })
    assert manifest.status_code == 200, manifest.text
    result = client.get(f'/api/v1/cases/{case_id}/completeness').json()
    assert result['complete'] is False
    assert result['missing_event_ids'] == ['evt-not-ingested']
    assert result['unexpected_event_ids'] == []
    assert result['reason'] == 'expected_events_missing'
    assert client.put(f'/api/v1/cases/{case_id}/expected-events', json={'expected_event_ids': [EVENT['eventId'], EVENT['eventId']]}).status_code == 422


def test_candidate_copy_detects_modified_bytes_without_replacing_original(tmp_path: Path):
    client, _case_id, evidence = _setup(tmp_path)
    valid = client.post(f"/api/v1/evidence/{evidence['evidence_id']}/verify-candidate", files={'file': ('copy.bin', b'{ "raw": "source bytes", "id": 1 }\n', 'application/octet-stream')})
    assert valid.status_code == 200
    assert valid.json()['valid'] is True
    assert valid.json()['candidate_stored'] is False
    changed = client.post(f"/api/v1/evidence/{evidence['evidence_id']}/verify-candidate", files={'file': ('changed.bin', b'modified bytes', 'application/octet-stream')}).json()
    assert changed['valid'] is False
    assert changed['failed_check'] == 'candidate_original_sha256'
    assert changed['reason'] == 'candidate_digest_or_length_mismatch'
    assert client.get(f"/api/v1/evidence/{evidence['evidence_id']}/verify").json()['valid'] is True


def test_forensic_json_and_html_report_accuracy_and_escaping(tmp_path: Path):
    client, case_id, evidence = _setup(tmp_path)
    source_events = [
        {'format': 'windows_event_v1', 'eventId': 'evt-win', 'sourceId': 'windows-a', 'occurredAt': '2026-10-10T12:35:00.000Z', 'eventType': 'logon', 'account': 'analyst@example.test', 'computer': 'srv-01'},
        {'format': 'linux_audit_v1', 'eventId': 'evt-linux', 'sourceId': 'linux-a', 'occurredAt': '2026-10-10T12:35:05.000Z', 'eventType': 'login', 'user': 'analyst@example.test', 'host': 'srv-01'},
    ]
    for index, source_event in enumerate(source_events):
        ingested = client.post(f'/api/v1/cases/{case_id}/evidence', files={'file': (f'source-{index}.json', b'synthetic raw bytes', 'application/json')}, data={'event': json.dumps(source_event)})
        assert ingested.status_code == 201, ingested.text
    correlation = client.post(f'/api/v1/cases/{case_id}/correlations/recompute')
    assert correlation.status_code == 200, correlation.text
    assert correlation.json()['correlation_count'] > 0
    context = client.get(f'/api/v1/cases/{case_id}/verification/context').json()
    signature_material = _signed_material(context['root_hash'], context['leaf_count'])
    key_registration = client.post('/api/v1/signing-keys', json={'public_key_der_base64': signature_material['publicKeyDer']})
    assert key_registration.status_code == 201, key_registration.text
    signature_check = client.post(f'/api/v1/cases/{case_id}/verification/signature', json={
        'batch_id': 'verification-lab', 'key_id': signature_material['keyId'], 'signature_hex': signature_material['signature'],
    })
    assert signature_check.json()['valid'] is True
    client.post(f'/api/v1/cases/{case_id}/verification/proof', json={
        'event_id': EVENT['eventId'], 'expected_root': context['root_hash'],
        'proof': next(item['proof'] for item in context['proofs'] if item['event_id'] == EVENT['eventId']),
    })
    client.put(f'/api/v1/cases/{case_id}/expected-events', json={'expected_event_ids': [EVENT['eventId'], 'evt-missing']})

    response = client.get(f'/api/v1/cases/{case_id}/reports/forensic.json')
    assert response.status_code == 200
    assert response.headers['content-disposition'].endswith('.json"')
    report = response.json()
    assert report['case']['id'] == case_id
    assert report['case']['name'] == '<Case> & Review'
    assert report['generated_at'].endswith('Z')
    recorded_evidence = next(item for item in report['evidence'] if item['evidence_id'] == evidence['evidence_id'])
    assert recorded_evidence['sha256'] == evidence['sha256']
    assert recorded_evidence['byte_integrity_check']['valid'] is True
    assert recorded_evidence['event'] == EVENT
    assert report['merkle']['root_hash'] == context['root_hash']
    assert any(item['event_id'] == EVENT['eventId'] for item in report['merkle']['inclusion_proofs'])
    assert report['signature_checks'][0]['result'] == 'valid'
    assert report['signature_checks'][0]['root_hash'] == context['root_hash']
    assert report['signature_checks'][0]['leaf_count'] == context['leaf_count']
    assert report['proof_checks'][0]['valid'] is True
    assert report['completeness']['complete'] is False
    assert report['completeness']['missing_event_ids'] == ['evt-missing']
    assert report['blockchain_transaction_references'] == []
    assert report['correlation_rules'][0]['rule_id'] == 'shared-entity-window-v1'
    assert len(report['correlation_rules'][0]['source_event_references']) == 2
    assert any('does not prove source-log truth' in reason for reason in report['verification_limitations'])

    html = client.get(f'/api/v1/cases/{case_id}/reports/forensic.html')
    assert html.status_code == 200
    assert html.headers['content-type'].startswith('text/html')
    assert '&lt;Case&gt; &amp; Review' in html.text
    assert '<Case> & Review' not in html.text
    assert 'evt-missing' in html.text

    raw_path = tmp_path / 'evidence' / evidence['sha256'][:2] / f"{evidence['sha256']}.bin"
    raw_path.write_bytes(b'tampered original bytes')
    changed = client.get(f'/api/v1/cases/{case_id}/reports/forensic.json').json()
    changed_item = next(item for item in changed['evidence'] if item['evidence_id'] == evidence['evidence_id'])
    assert changed_item['byte_integrity_check']['valid'] is False
    assert changed_item['byte_integrity_check']['reason'] == 'digest_or_length_mismatch'


def test_report_refuses_tampered_storage_path_without_reading_outside_object_root(tmp_path: Path):
    client, case_id, evidence = _setup(tmp_path)
    outside = tmp_path / 'outside.bin'
    outside.write_bytes(b'path traversal sentinel')
    with sqlite3.connect(tmp_path / 'report.sqlite3') as connection:
        connection.execute('UPDATE evidence_objects SET storage_key = ? WHERE id = ?', ('../../outside.bin', evidence['evidence_id']))
    response = client.get(f'/api/v1/cases/{case_id}/reports/forensic.json')
    assert response.status_code == 200
    item = response.json()['evidence'][0]
    assert item['byte_integrity_check'] == {
        'valid': False, 'actual_sha256': None, 'actual_byte_length': None, 'reason': 'stored_object_path_invalid',
    }
    assert hashlib.sha256(outside.read_bytes()).hexdigest() not in response.text
