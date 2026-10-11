from __future__ import annotations

import json
import os
import socket
import subprocess
import time
import urllib.request
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from auth_test_helpers import authorized_client
from backend.app import create_app


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _rpc(url: str, method: str, params: list[object] | None = None) -> object:
    payload = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or []}).encode()
    request = urllib.request.Request(url, data=payload, headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=2) as response:
        return json.loads(response.read())['result']


@pytest.fixture
def isolated_hardhat(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    with socket.socket() as candidate:
        candidate.bind(('127.0.0.1', 0))
        port = candidate.getsockname()[1]
    url = f'http://127.0.0.1:{port}'
    metadata_path = tmp_path / 'deployment.json'
    log_path = tmp_path / 'isolated-hardhat.log'
    log = log_path.open('w+', encoding='utf-8')
    env = os.environ.copy()
    env.update({
        'CHAINPROOF_RPC_URL': url,
        'CHAINPROOF_CHAIN_ID': '31337',
        'CHAINPROOF_DEPLOYMENT_FILE': str(metadata_path),
        'CHAINPROOF_DB': str(tmp_path / 'api-global.sqlite3'),
        'CHAINPROOF_EVIDENCE_DIR': str(tmp_path / 'api-global-evidence'),
    })
    node = subprocess.Popen(
        ['node_modules/.bin/hardhat', 'node', '--hostname', '127.0.0.1', '--port', str(port)],
        cwd=PROJECT_ROOT, env=env, stdout=log, stderr=subprocess.STDOUT,
    )
    try:
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            if node.poll() is not None:
                log.flush()
                raise RuntimeError(f'isolated Hardhat stopped unexpectedly:\n{log_path.read_text()}')
            try:
                if _rpc(url, 'eth_chainId') == '0x7a69':
                    break
            except (OSError, ValueError, KeyError):
                time.sleep(0.1)
        else:
            raise RuntimeError(f'isolated Hardhat did not become ready:\n{log_path.read_text()}')
        deployment = subprocess.run(
            ['node_modules/.bin/hardhat', 'run', 'scripts/deploy.cjs', '--network', 'localhost'],
            cwd=PROJECT_ROOT, env=env, text=True, capture_output=True, timeout=60, check=False,
        )
        assert deployment.returncode == 0, deployment.stdout + deployment.stderr
        monkeypatch.setenv('CHAINPROOF_RPC_URL', url)
        monkeypatch.setenv('CHAINPROOF_CHAIN_ID', '31337')
        monkeypatch.setenv('CHAINPROOF_DEPLOYMENT_FILE', str(metadata_path))
        yield {'url': url, 'metadata': json.loads(metadata_path.read_text(encoding='utf-8'))}
    finally:
        node.terminate()
        try:
            node.wait(timeout=5)
        except subprocess.TimeoutExpired:
            node.kill()
            node.wait(timeout=5)
        log.close()


def _sign_batch(batch_id: str, key_id: str, root_hash: str, leaf_count: int) -> dict[str, str]:
    source = """
import { createPublicKey } from 'node:crypto';
import { publicKeyId, signBatch, testOnlyPrivateKeyFromSeed } from './src/integrity.ts';
let input = ''; for await (const part of process.stdin) input += part;
const value = JSON.parse(input);
const privateKey = testOnlyPrivateKeyFromSeed(Buffer.alloc(32, 23));
const publicKey = createPublicKey(privateKey);
const keyId = publicKeyId(publicKey);
if (keyId !== value.keyId) throw new Error('fixture key ID mismatch');
const batch = { version: 'cpx-signed-batch-v1', batchId: value.batchId, keyId,
  treeVersion: 'cpx-merkle-v1', leafCount: value.leafCount, rootHash: value.rootHash };
process.stdout.write(JSON.stringify({ signature: signBatch(batch, privateKey).toString('hex') }));
"""
    result = subprocess.run(
        ['node', '--experimental-strip-types', '--input-type=module', '-e', source],
        cwd=PROJECT_ROOT, input=json.dumps({'batchId': batch_id, 'keyId': key_id, 'rootHash': root_hash, 'leafCount': leaf_count}),
        text=True, capture_output=True, timeout=10, check=False,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_isolated_authenticated_evidence_to_receipt_and_report_flow(tmp_path: Path, isolated_hardhat):
    client = authorized_client(create_app(tmp_path / 'case.sqlite3', tmp_path / 'evidence'))
    with client:
        case_response = client.post('/api/v1/cases', json={'name': 'Isolated authenticated rehearsal'})
        assert case_response.status_code == 201, case_response.text
        case_id = case_response.json()['id']

        events = [
            {'format': 'windows_event_v1', 'eventId': 'evt-e2e-win', 'sourceId': 'windows-e2e', 'occurredAt': '2026-10-11T11:00:00.000Z', 'eventType': 'logon', 'account': 'demo@example.test', 'computer': 'e2e-ws-01'},
            {'format': 'linux_audit_v1', 'eventId': 'evt-e2e-linux', 'sourceId': 'linux-e2e', 'occurredAt': '2026-10-11T11:00:05.000Z', 'eventType': 'login', 'user': 'demo@example.test', 'host': 'e2e-ws-01'},
            {'format': 'network_event_v1', 'eventId': 'evt-e2e-net', 'sourceId': 'network-e2e', 'occurredAt': '2026-10-11T11:00:10.000Z', 'eventType': 'connection', 'hostname': 'e2e-ws-01', 'destinationIp': '192.0.2.77'},
        ]
        evidence = []
        for index, event in enumerate(events):
            original = f'original synthetic source bytes {index}\n'.encode()
            response = client.post(
                f'/api/v1/cases/{case_id}/evidence',
                files={'file': (f'e2e-{index}.json', original, 'application/json')},
                data={'event': json.dumps(event)},
            )
            assert response.status_code == 201, response.text
            item = response.json()
            evidence.append(item)
            checked = client.get(f"/api/v1/evidence/{item['evidence_id']}/verify")
            assert checked.status_code == 200 and checked.json()['valid'] is True

        altered = client.post(
            f"/api/v1/evidence/{evidence[0]['evidence_id']}/verify-candidate",
            files={'file': ('edited.json', b'altered source bytes', 'application/json')},
        )
        assert altered.status_code == 200 and altered.json()['valid'] is False
        assert altered.json()['candidate_stored'] is False

        context = client.get(f'/api/v1/cases/{case_id}/verification/context').json()
        proof_entry = context['proofs'][0]
        proof_body = {'event_id': proof_entry['event_id'], 'expected_root': context['root_hash'], 'proof': proof_entry['proof']}
        assert client.post(f'/api/v1/cases/{case_id}/verification/proof', json=proof_body).json()['valid'] is True
        altered_proof = json.loads(json.dumps(proof_body))
        altered_proof['proof']['leafIndex'] = altered_proof['proof']['leafIndex'] + 1
        assert client.post(f'/api/v1/cases/{case_id}/verification/proof', json=altered_proof).json()['valid'] is False

        key_generation = subprocess.run(
            ['node', '--experimental-strip-types', '--input-type=module', '-e', "import {createPublicKey} from 'node:crypto'; import {publicKeyId,testOnlyPrivateKeyFromSeed} from './src/integrity.ts'; const key=createPublicKey(testOnlyPrivateKeyFromSeed(Buffer.alloc(32,23))); process.stdout.write(JSON.stringify({keyId:publicKeyId(key), publicKeyDerBase64:key.export({format:'der',type:'spki'}).toString('base64')}));"],
            cwd=PROJECT_ROOT, text=True, capture_output=True, timeout=10, check=False,
        )
        assert key_generation.returncode == 0, key_generation.stderr
        key = json.loads(key_generation.stdout)
        registered = client.post('/api/v1/signing-keys', json={'public_key_der_base64': key['publicKeyDerBase64']})
        assert registered.status_code == 201, registered.text
        assert registered.json()['key_id'] == key['keyId']
        batch_id = 'e2e-batch-001'
        signed = _sign_batch(batch_id, key['keyId'], context['root_hash'], context['leaf_count'])
        signature_request = {'batch_id': batch_id, 'key_id': key['keyId'], 'signature_hex': signed['signature']}
        assert client.post(f'/api/v1/cases/{case_id}/verification/signature', json=signature_request).json()['valid'] is True
        bad_signature = {**signature_request, 'signature_hex': '00' * 64}
        assert client.post(f'/api/v1/cases/{case_id}/verification/signature', json=bad_signature).json()['valid'] is False

        anchored = client.post(f'/api/v1/cases/{case_id}/anchors', json={'batch_id': '0x' + 'ab' * 32})
        assert anchored.status_code == 201, anchored.text
        assert anchored.json()['verification_status'] == 'verified'
        assert anchored.json()['chain_id'] == 31337
        listed = client.get(f'/api/v1/cases/{case_id}/anchors')
        assert listed.status_code == 200 and listed.json()[0]['verification_status'] == 'recorded'
        verified = client.get(f"/api/v1/anchors/{anchored.json()['batch_id']}/verify")
        assert verified.status_code == 200 and verified.json()['verification_status'] == 'verified'
        assert verified.json()['merkle_root'] == anchored.json()['merkle_root']

        correlations = client.post(f'/api/v1/cases/{case_id}/correlations/recompute')
        assert correlations.status_code == 200 and correlations.json()['correlation_count'] > 0
        correlation_id = correlations.json()['correlations'][0]['id']
        created = client.post(f'/api/v1/cases/{case_id}/investigations', json={
            'title': 'Review shared account activity', 'summary': 'Candidate correlation; no causal conclusion.',
            'evidence_ids': [entry['evidence_id'] for entry in evidence], 'correlation_ids': [correlation_id],
        })
        assert created.status_code == 201, created.text
        graph = client.get(f'/api/v1/cases/{case_id}/trust-graph').json()
        assert any(node['type'] == 'investigation' for node in graph['nodes'])
        assert any(edge['relationship'] == 'reviews_correlation_candidate' for edge in graph['edges'])

        report_json = client.get(f'/api/v1/cases/{case_id}/reports/forensic.json')
        report_html = client.get(f'/api/v1/cases/{case_id}/reports/forensic.html')
        assert report_json.status_code == report_html.status_code == 200
        report = report_json.json()
        assert report['case']['id'] == case_id
        assert {item['evidence_id'] for item in report['evidence']} == {item['evidence_id'] for item in evidence}
        assert report['signature_checks'] and report['proof_checks']
        anchor_reference = report['blockchain_transaction_references'][0]
        assert anchor_reference['tx_hash'] == anchored.json()['tx_hash']
        assert anchor_reference['merkle_root'] == verified.json()['merkle_root']
        assert 'verification_status' not in anchor_reference  # export is stored metadata, not a live RPC check
        assert any('source' in text.lower() and 'truth' in text.lower() for text in report['verification_limitations'])
        assert case_id in report_html.text
        assert 'recorded' in report_html.text
