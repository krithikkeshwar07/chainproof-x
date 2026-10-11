"""Minimal JSON-RPC client for the local EvidenceRegistry.

Transactions use an unlocked local Hardhat account; no private key is read or
stored by this service. Every submitted transaction is independently checked
against JSON-RPC receipt, transaction, event-log, and contract storage data.
"""
from __future__ import annotations

import json
import ipaddress
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any


ADDRESS_RE = re.compile(r'^0x[0-9a-fA-F]{40}$')
BYTES32_RE = re.compile(r'^0x[0-9a-f]{64}$')
TX_HASH_RE = re.compile(r'^0x[0-9a-f]{64}$')

# Selectors/topics are Keccak-256 ABI identifiers from EvidenceRegistry.sol.
ANCHOR_ROOT_SELECTOR = '79edcd1a'  # anchorRoot(bytes32,bytes32)
GET_BATCH_SELECTOR = 'ed42136f'  # getBatch(bytes32)
ANCHOR_EVENT_TOPIC = '0x193c8f2b661446c4d48d27c42e25c2a1715f72ece7bb87ab31ee249b8c83bde2'
ALREADY_ANCHORED_ERROR = '0x213d8d34'  # BatchAlreadyAnchored(bytes32)


class ChainError(RuntimeError):
    """Base error raised for an unavailable or inconsistent chain response."""


class ChainUnavailable(ChainError):
    pass


class ChainVerificationFailed(ChainError):
    pass


class BatchAlreadyAnchored(ChainError):
    pass


@dataclass(frozen=True)
class AnchorReceipt:
    tx_hash: str
    block_number: int
    block_hash: str
    chain_id: int
    contract_address: str
    sender_address: str
    merkle_root: str
    batch_id: str
    anchored_at: int

    def as_dict(self) -> dict[str, Any]:
        return {
            'tx_hash': self.tx_hash,
            'block_number': self.block_number,
            'block_hash': self.block_hash,
            'chain_id': self.chain_id,
            'contract_address': self.contract_address,
            'sender_address': self.sender_address,
            'merkle_root': self.merkle_root,
            'batch_id': self.batch_id,
            'anchored_at': self.anchored_at,
        }


class EvidenceRegistryRpc:
    def __init__(
        self,
        rpc_url: str,
        expected_chain_id: int,
        contract_address: str,
        sender_address: str | None = None,
        timeout_seconds: float = 5,
    ) -> None:
        try:
            parsed_rpc = urllib.parse.urlsplit(rpc_url)
            hostname = parsed_rpc.hostname
            port = parsed_rpc.port
            ip = ipaddress.ip_address(hostname) if hostname else None
            loopback = (hostname == 'localhost' or ip is not None and ip.is_loopback)
        except ValueError:
            loopback = False
            parsed_rpc = urllib.parse.urlsplit('')
            port = None
        if (parsed_rpc.scheme != 'http' or not loopback or port is None
                or parsed_rpc.username is not None or parsed_rpc.password is not None
                or parsed_rpc.query or parsed_rpc.fragment):
            raise ChainUnavailable('Evidence anchoring is restricted to a local Hardhat RPC endpoint.')
        if not ADDRESS_RE.fullmatch(contract_address):
            raise ChainUnavailable('EvidenceRegistry deployment address is invalid.')
        if sender_address is not None and not ADDRESS_RE.fullmatch(sender_address):
            raise ChainUnavailable('Configured anchor account is invalid.')
        if not isinstance(expected_chain_id, int) or isinstance(expected_chain_id, bool) or expected_chain_id <= 0:
            raise ChainUnavailable('Expected local chain ID is invalid.')
        self.rpc_url = rpc_url
        self.expected_chain_id = expected_chain_id
        self.contract_address = contract_address.lower()
        self.sender_address = sender_address.lower() if sender_address else None
        self.timeout_seconds = timeout_seconds
        self._request_id = 0

    def _rpc(self, method: str, params: list[Any]) -> Any:
        self._request_id += 1
        body = json.dumps({'jsonrpc': '2.0', 'id': self._request_id, 'method': method, 'params': params}).encode()
        request = urllib.request.Request(self.rpc_url, data=body, headers={'Content-Type': 'application/json'}, method='POST')
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                raw = response.read(1024 * 1024 + 1)
        except (OSError, TimeoutError, urllib.error.URLError) as exc:
            raise ChainUnavailable('Local Hardhat RPC is unavailable.') from exc
        if len(raw) > 1024 * 1024:
            raise ChainUnavailable('Local Hardhat RPC returned an oversized response.')
        try:
            value = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ChainUnavailable('Local Hardhat RPC returned malformed JSON.') from exc
        if not isinstance(value, dict) or value.get('id') != self._request_id:
            raise ChainUnavailable('Local Hardhat RPC returned an invalid response envelope.')
        if 'error' in value:
            error = value['error']
            message = error.get('message', '') if isinstance(error, dict) else ''
            error_data = error.get('data', '') if isinstance(error, dict) else ''
            if method == 'eth_sendTransaction' and (
                'BatchAlreadyAnchored' in message
                or isinstance(error_data, str) and ALREADY_ANCHORED_ERROR in error_data.lower()
            ):
                raise BatchAlreadyAnchored('The batch ID has already been anchored on this chain.')
            raise ChainUnavailable(f'Local Hardhat RPC rejected {method}.')
        if 'result' not in value:
            raise ChainUnavailable('Local Hardhat RPC response has no result.')
        return value['result']

    @staticmethod
    def _quantity(value: Any, field: str) -> int:
        if not isinstance(value, str) or not re.fullmatch(r'0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)', value):
            raise ChainVerificationFailed(f'Chain response has an invalid {field}.')
        return int(value, 16)

    @staticmethod
    def _hex(value: Any, size: int | None, field: str) -> str:
        if not isinstance(value, str) or not value.startswith('0x') or len(value) % 2:
            raise ChainVerificationFailed(f'Chain response has an invalid {field}.')
        if size is not None and len(value) != 2 + size * 2:
            raise ChainVerificationFailed(f'Chain response has an invalid {field}.')
        if not re.fullmatch(r'0x[0-9a-fA-F]*', value):
            raise ChainVerificationFailed(f'Chain response has an invalid {field}.')
        return value.lower()

    def _check_network_and_code(self) -> int:
        actual_chain_id = self._quantity(self._rpc('eth_chainId', []), 'chain ID')
        if actual_chain_id != self.expected_chain_id:
            raise ChainVerificationFailed('Connected chain ID does not match the configured Hardhat chain.')
        code = self._hex(self._rpc('eth_getCode', [self.contract_address, 'latest']), None, 'contract code')
        if code == '0x':
            raise ChainVerificationFailed('No contract is deployed at the configured EvidenceRegistry address.')
        return actual_chain_id

    def _get_sender(self) -> str:
        if self.sender_address:
            return self.sender_address
        accounts = self._rpc('eth_accounts', [])
        if not isinstance(accounts, list) or not accounts or not all(ADDRESS_RE.fullmatch(item) for item in accounts):
            raise ChainUnavailable('Hardhat returned no usable unlocked account.')
        return accounts[0].lower()

    def anchor_root(self, batch_id: str, merkle_root: str) -> AnchorReceipt:
        if not BYTES32_RE.fullmatch(batch_id) or not BYTES32_RE.fullmatch(merkle_root):
            raise ChainVerificationFailed('Batch ID and Merkle root must be lowercase bytes32 values.')
        chain_id = self._check_network_and_code()
        sender = self._get_sender()
        calldata = '0x' + ANCHOR_ROOT_SELECTOR + batch_id[2:] + merkle_root[2:]
        tx_hash = self._rpc('eth_sendTransaction', [{'from': sender, 'to': self.contract_address, 'data': calldata}])
        if not isinstance(tx_hash, str) or not TX_HASH_RE.fullmatch(tx_hash):
            raise ChainVerificationFailed('Hardhat returned an invalid transaction hash.')

        deadline = time.monotonic() + 10
        receipt: Any = None
        while time.monotonic() < deadline:
            receipt = self._rpc('eth_getTransactionReceipt', [tx_hash])
            if receipt is not None:
                break
            time.sleep(0.05)
        if receipt is None:
            raise ChainVerificationFailed('Anchor transaction receipt was not available before timeout.')
        return self.verify_receipt(tx_hash, batch_id, merkle_root, receipt=receipt, expected_sender=sender, expected_chain_id=chain_id)

    def verify_receipt(
        self,
        tx_hash: str,
        batch_id: str,
        merkle_root: str,
        *,
        receipt: Any | None = None,
        expected_sender: str | None = None,
        expected_chain_id: int | None = None,
    ) -> AnchorReceipt:
        if not TX_HASH_RE.fullmatch(tx_hash) or not BYTES32_RE.fullmatch(batch_id) or not BYTES32_RE.fullmatch(merkle_root):
            raise ChainVerificationFailed('Stored anchor identifiers are malformed.')
        chain_id = self._check_network_and_code()
        if expected_chain_id is not None and chain_id != expected_chain_id:
            raise ChainVerificationFailed('Current chain ID differs from the recorded anchor chain ID.')
        receipt = receipt if receipt is not None else self._rpc('eth_getTransactionReceipt', [tx_hash])
        if (not isinstance(receipt, dict) or not isinstance(receipt.get('transactionHash'), str)
                or receipt['transactionHash'].lower() != tx_hash.lower()):
            raise ChainVerificationFailed('Transaction receipt is missing or does not match the recorded transaction hash.')
        if self._hex(receipt.get('to'), 20, 'receipt contract address')[2:] != self.contract_address[2:]:
            raise ChainVerificationFailed('Transaction receipt contract address does not match EvidenceRegistry.')
        if self._quantity(receipt.get('status'), 'receipt status') != 1:
            raise ChainVerificationFailed('Anchor transaction did not succeed.')
        block_number = self._quantity(receipt.get('blockNumber'), 'receipt block number')
        block_hash = self._hex(receipt.get('blockHash'), 32, 'receipt block hash')

        transaction = self._rpc('eth_getTransactionByHash', [tx_hash])
        if (not isinstance(transaction, dict) or not isinstance(transaction.get('hash'), str)
                or transaction['hash'].lower() != tx_hash.lower()):
            raise ChainVerificationFailed('Transaction lookup does not match the recorded transaction hash.')
        if self._hex(transaction.get('to'), 20, 'transaction contract address')[2:] != self.contract_address[2:]:
            raise ChainVerificationFailed('Transaction target does not match EvidenceRegistry.')
        sender = self._hex(transaction.get('from'), 20, 'transaction sender')
        if expected_sender is not None and sender != expected_sender.lower():
            raise ChainVerificationFailed('Transaction sender differs from the submitted anchor account.')
        input_data = self._hex(transaction.get('input'), 68, 'transaction input')
        expected_input = '0x' + ANCHOR_ROOT_SELECTOR + batch_id[2:] + merkle_root[2:]
        if input_data != expected_input:
            raise ChainVerificationFailed('Transaction calldata does not commit the expected batch ID and Merkle root.')
        tx_chain_id = transaction.get('chainId')
        if tx_chain_id is not None and self._quantity(tx_chain_id, 'transaction chain ID') != chain_id:
            raise ChainVerificationFailed('Transaction chain ID does not match the connected chain.')

        matching_logs = []
        logs = receipt.get('logs')
        if not isinstance(logs, list):
            raise ChainVerificationFailed('Transaction receipt has malformed logs.')
        for log in logs:
            if not isinstance(log, dict) or not isinstance(log.get('address'), str) or log['address'].lower() != self.contract_address:
                continue
            topics = log.get('topics')
            if isinstance(topics, list) and topics and isinstance(topics[0], str) and topics[0].lower() == ANCHOR_EVENT_TOPIC:
                matching_logs.append((topics, log.get('data')))
        if len(matching_logs) != 1:
            raise ChainVerificationFailed('Receipt does not contain exactly one EvidenceBatchAnchored event from this contract.')
        topics, log_data = matching_logs[0]
        if (len(topics) != 4 or not all(isinstance(topic, str) for topic in topics)
                or topics[1].lower() != batch_id or topics[2].lower() != merkle_root):
            raise ChainVerificationFailed('Anchor event does not commit the expected batch ID and Merkle root.')
        event_sender_word = self._hex(topics[3], 32, 'anchor event submitter')
        if event_sender_word[:26] != '0x' + '0' * 24 or ('0x' + event_sender_word[-40:]) != sender:
            raise ChainVerificationFailed('Anchor event submitter does not match the transaction sender.')
        data = self._hex(log_data, 32, 'anchor event data')
        anchored_at = int(data, 16)

        call_data = '0x' + GET_BATCH_SELECTOR + batch_id[2:]
        stored = self._hex(self._rpc('eth_call', [{'to': self.contract_address, 'data': call_data}, hex(block_number)]), 64, 'committed batch state')
        stored_root = '0x' + stored[2:66]
        stored_timestamp = int(stored[66:], 16)
        if stored_root != merkle_root or stored_timestamp != anchored_at:
            raise ChainVerificationFailed('Contract storage does not contain the root and timestamp emitted in the receipt.')
        if self._quantity(self._rpc('eth_chainId', []), 'chain ID') != chain_id:
            raise ChainVerificationFailed('Chain ID changed during receipt verification.')
        return AnchorReceipt(
            tx_hash=tx_hash.lower(), block_number=block_number, block_hash=block_hash,
            chain_id=chain_id, contract_address=self.contract_address, sender_address=sender,
            merkle_root=stored_root, batch_id=batch_id, anchored_at=anchored_at,
        )
