from __future__ import annotations

import json
import os
import socket
import sqlite3
import subprocess
import time
import urllib.request
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from auth_test_helpers import authorized_client
from backend.app import create_app, integrity_merkle_batch
from backend.chain import ChainUnavailable, EvidenceRegistryRpc


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SYNTHETIC_EVENT = {
    'eventId': 'evt-chain-001',
    'sourceId': 'synthetic-host',
    'occurredAt': '2026-10-10T12:34:56.789Z',
    'eventType': 'login.success',
    'actor': 'synthetic-user',
    'target': 'synthetic-service',
}


@pytest.mark.parametrize('url', [
    'https://127.0.0.1:8545',
    'http://127.0.0.1.evil.example:8545',
    'http://127.0.0.1:8545@evil.example',
    'http://localhost@evil.example:8545',
    'http://example.com:8545',
    'http://127.0.0.1:not-a-port',
    'http://127.0.0.1:8545/rpc?redirect=https://example.com',
])
def test_chain_rpc_configuration_rejects_non_loopback_or_ambiguous_urls(url: str):
    with pytest.raises(ChainUnavailable):
        EvidenceRegistryRpc(url, 31337, '0x' + '11' * 20)


def _free_port() -> int:
    with socket.socket() as candidate:
        candidate.bind(('127.0.0.1', 0))
        return candidate.getsockname()[1]


def _rpc(url: str, method: str, params: list[object] | None = None) -> object:
    payload = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or []}).encode()
    request = urllib.request.Request(url, data=payload, headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=1) as response:
        return json.loads(response.read())['result']


@pytest.fixture
def local_hardhat(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    port = _free_port()
    rpc_url = f'http://127.0.0.1:{port}'
    deployment_file = tmp_path / 'deployment.json'
    log_path = tmp_path / 'hardhat-node.log'
    log = log_path.open('w+')
    env = os.environ.copy()
    env.update({
        'CHAINPROOF_RPC_URL': rpc_url,
        'CHAINPROOF_CHAIN_ID': '31337',
        'CHAINPROOF_DEPLOYMENT_FILE': str(deployment_file),
    })
    server = subprocess.Popen(
        ['node_modules/.bin/hardhat', 'node', '--hostname', '127.0.0.1', '--port', str(port)],
        cwd=PROJECT_ROOT,
        env=env,
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if server.poll() is not None:
                log.flush()
                raise RuntimeError(f'Hardhat node stopped unexpectedly:\n{log_path.read_text()}')
            try:
                if _rpc(rpc_url, 'eth_chainId') == '0x7a69':
                    break
            except (OSError, ValueError, KeyError):
                time.sleep(0.1)
        else:
            raise RuntimeError(f'Hardhat node did not become ready:\n{log_path.read_text()}')

        deployed = subprocess.run(
            ['node_modules/.bin/hardhat', 'run', 'scripts/deploy.cjs', '--network', 'localhost'],
            cwd=PROJECT_ROOT,
            env=env,
            text=True,
            capture_output=True,
            timeout=60,
            check=False,
        )
        assert deployed.returncode == 0, deployed.stdout + deployed.stderr
        deployment = json.loads(deployment_file.read_text(encoding='utf-8'))
        monkeypatch.setenv('CHAINPROOF_RPC_URL', rpc_url)
        monkeypatch.setenv('CHAINPROOF_CHAIN_ID', '31337')
        monkeypatch.setenv('CHAINPROOF_DEPLOYMENT_FILE', str(deployment_file))
        yield deployment
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=5)
        log.close()


def test_fastapi_anchors_real_case_merkle_root_and_independently_verifies_receipt(
    tmp_path: Path, local_hardhat: dict[str, object],
):
    client = authorized_client(create_app(tmp_path / 'case.sqlite3', tmp_path / 'evidence'))
    with client:
        case_response = client.post('/api/v1/cases', json={'name': 'Local anchor integration'})
        assert case_response.status_code == 201
        case_id = case_response.json()['id']
        upload = client.post(
            f'/api/v1/cases/{case_id}/evidence',
            files={'file': ('source.log', b'original synthetic bytes', 'text/plain')},
            data={'event': json.dumps(SYNTHETIC_EVENT)},
        )
        assert upload.status_code == 201, upload.text

        batch_id = '0x' + '12' * 32
        anchored = client.post(f'/api/v1/cases/{case_id}/anchors', json={'batch_id': batch_id})
        assert anchored.status_code == 201, anchored.text
        body = anchored.json()
        assert body['verification_status'] == 'verified'
        assert body['batch_id'] == batch_id
        assert body['chain_id'] == 31337
        assert body['contract_address'].lower() == str(local_hardhat['contract_address']).lower()
        expected_root, expected_leaves, expected_version = integrity_merkle_batch([SYNTHETIC_EVENT])
        assert body['merkle_root'] == '0x' + expected_root
        assert body['tree_version'] == expected_version
        assert body['leaf_count'] == expected_leaves == 1
        assert body['tx_hash'].startswith('0x') and len(body['tx_hash']) == 66
        assert body['block_number'] > local_hardhat['deployment_block_number']

        listed = client.get(f'/api/v1/cases/{case_id}/anchors')
        assert listed.status_code == 200
        assert listed.json()[0]['tx_hash'] == body['tx_hash']
        assert listed.json()[0]['verification_status'] == 'recorded'
        detail = client.get(f'/api/v1/anchors/{batch_id}')
        assert detail.status_code == 200
        assert detail.json()['verification_status'] == 'recorded'
        verified = client.get(f'/api/v1/anchors/{batch_id}/verify')
        assert verified.status_code == 200, verified.text
        assert verified.json()['verification_status'] == 'verified'
        assert verified.json()['merkle_root'] == body['merkle_root']

        with sqlite3.connect(tmp_path / 'case.sqlite3') as connection:
            connection.execute('UPDATE blockchain_anchors SET merkle_root = ? WHERE batch_id = ?', ('0x' + 'ff' * 32, batch_id))
        failed = client.get(f'/api/v1/anchors/{batch_id}/verify')
        assert failed.status_code == 409
        assert 'calldata does not commit the expected' in failed.json()['detail'] or 'storage' in failed.json()['detail']


def test_fastapi_rejects_chain_id_mismatch_during_independent_verification(
    tmp_path: Path, local_hardhat: dict[str, object], monkeypatch: pytest.MonkeyPatch,
):
    client = authorized_client(create_app(tmp_path / 'case.sqlite3', tmp_path / 'evidence'))
    with client:
        case_id = client.post('/api/v1/cases', json={'name': 'Wrong chain verification'}).json()['id']
        upload = client.post(
            f'/api/v1/cases/{case_id}/evidence',
            files={'file': ('source.log', b'bytes', 'text/plain')},
            data={'event': json.dumps(SYNTHETIC_EVENT)},
        )
        assert upload.status_code == 201
        batch_id = '0x' + '34' * 32
        anchored = client.post(f'/api/v1/cases/{case_id}/anchors', json={'batch_id': batch_id})
        assert anchored.status_code == 201, anchored.text

        monkeypatch.setenv('CHAINPROOF_CHAIN_ID', '1')
        failed = client.get(f'/api/v1/anchors/{batch_id}/verify')
        assert failed.status_code == 409
        assert 'chain ID' in failed.json()['detail']


def test_evidence_to_anchor_verification_detects_tampering_missing_tx_and_offline_node(
    tmp_path: Path, local_hardhat: dict[str, object], monkeypatch: pytest.MonkeyPatch,
):
    database = tmp_path / 'case.sqlite3'
    evidence_root = tmp_path / 'evidence'
    client = authorized_client(create_app(database, evidence_root))
    with client:
        case_id = client.post('/api/v1/cases', json={'name': 'End-to-end verification failures'}).json()['id']
        source_bytes = b'original synthetic authentication event bytes\n'
        uploaded = client.post(
            f'/api/v1/cases/{case_id}/evidence',
            files={'file': ('source.log', source_bytes, 'text/plain')},
            data={'event': json.dumps(SYNTHETIC_EVENT)},
        )
        assert uploaded.status_code == 201, uploaded.text
        evidence = uploaded.json()
        batch_id = '0x' + '56' * 32
        anchored = client.post(f'/api/v1/cases/{case_id}/anchors', json={'batch_id': batch_id})
        assert anchored.status_code == 201, anchored.text
        original_anchor = anchored.json()
        expected_root, expected_count, _ = integrity_merkle_batch([SYNTHETIC_EVENT])
        assert original_anchor['merkle_root'] == '0x' + expected_root
        assert original_anchor['leaf_count'] == expected_count == 1
        assert client.get(f'/api/v1/anchors/{batch_id}/verify').status_code == 200

        # Original uploaded bytes are independent from normalized-event anchoring.
        raw_object = evidence_root / evidence['sha256'][:2] / f"{evidence['sha256']}.bin"
        raw_object.write_bytes(b'tampered source evidence')
        evidence_check = client.get(f"/api/v1/evidence/{evidence['evidence_id']}/verify")
        assert evidence_check.status_code == 200
        assert evidence_check.json()['valid'] is False
        # The root still faithfully commits the normalized event, not a claim that source bytes are truthful.
        assert client.get(f'/api/v1/anchors/{batch_id}/verify').status_code == 200

        with sqlite3.connect(database) as connection:
            connection.execute('UPDATE blockchain_anchors SET merkle_root = ? WHERE batch_id = ?', ('0x' + 'ff' * 32, batch_id))
        wrong_root = client.get(f'/api/v1/anchors/{batch_id}/verify')
        assert wrong_root.status_code == 409
        assert 'expected' in wrong_root.json()['detail'] or 'storage' in wrong_root.json()['detail']

        with sqlite3.connect(database) as connection:
            connection.execute('UPDATE blockchain_anchors SET merkle_root = ?, tx_hash = ? WHERE batch_id = ?',
                               (original_anchor['merkle_root'], '0x' + '99' * 32, batch_id))
        missing_transaction = client.get(f'/api/v1/anchors/{batch_id}/verify')
        assert missing_transaction.status_code == 409

        monkeypatch.setenv('CHAINPROOF_RPC_URL', f'http://127.0.0.1:{_free_port()}')
        offline_verify = client.get(f'/api/v1/anchors/{batch_id}/verify')
        assert offline_verify.status_code == 503
        assert offline_verify.json().get('verification_status') != 'verified'
        offline_anchor = client.post(f'/api/v1/cases/{case_id}/anchors', json={'batch_id': '0x' + '78' * 32})
        assert offline_anchor.status_code == 503
        assert offline_verify.json()['detail']
        assert offline_anchor.json()['detail']
