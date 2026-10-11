from __future__ import annotations

import hashlib
import hmac
import base64
import ipaddress
import json
import os
import re
import sqlite3
import stat
import subprocess
import tempfile
import urllib.parse
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterator, Literal

from fastapi import FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from backend.chain import (
    BatchAlreadyAnchored,
    ChainUnavailable,
    ChainVerificationFailed,
    EvidenceRegistryRpc,
)
from backend.correlation import (
    MAX_CORRELATION_EVENTS,
    RULE_ID,
    RULE_VERSION,
    WINDOW_SECONDS,
    NormalizationError,
    correlate_events,
    entity_keys,
    normalize_source_event,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = PROJECT_ROOT / 'backend' / 'schema.sql'
INTEGRITY_CLI = PROJECT_ROOT / 'src' / 'integrity_cli.ts'
MAX_UPLOAD_BYTES = 16 * 1024 * 1024
MAX_INGEST_REQUEST_BYTES = MAX_UPLOAD_BYTES + 128 * 1024
MAX_PROOF_REQUEST_BYTES = 32 * 1024
UPLOAD_CHUNK_BYTES = 1024 * 1024
EVENT_FORM_MAX_BYTES = 48 * 1024
SHA256_RE = re.compile(r'^[0-9a-f]{64}$')
MEDIA_TYPE_RE = re.compile(r'^[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+$')


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')


class CaseCreate(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True, strict=True)
    name: str = Field(min_length=1, max_length=120)

    @field_validator('name')
    @classmethod
    def reject_controls(cls, value: str) -> str:
        if any(ord(char) < 32 or 0x7F <= ord(char) <= 0x9F for char in value):
            raise ValueError('name must not contain control characters')
        return value


class AnchorCreate(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    batch_id: str = Field(pattern=r'^0x[0-9a-f]{64}$')


class OrganizationCreate(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True, strict=True)
    name: str = Field(min_length=1, max_length=160)

    @field_validator('name')
    @classmethod
    def reject_controls(cls, value: str) -> str:
        if any(ord(char) < 32 or 0x7F <= ord(char) <= 0x9F for char in value):
            raise ValueError('name must not contain control characters')
        return value


class PublicKeyCreate(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    public_key_der_base64: str = Field(min_length=1, max_length=256)


class SignatureCheckBody(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    batch_id: str = Field(pattern=r'^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$')
    key_id: str = Field(pattern=r'^[0-9a-f]{64}$')
    signature_hex: str = Field(pattern=r'^(?:[0-9a-fA-F]{2}){64}$')


class MerkleProofStepBody(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    side: Literal['left', 'right', 'promote']
    hash: str | None = None

    @field_validator('hash')
    @classmethod
    def validate_step_hash(cls, value: str | None) -> str | None:
        if value is not None and not SHA256_RE.fullmatch(value):
            raise ValueError('proof step hash must be a lowercase SHA-256 hex digest')
        return value

    @model_validator(mode='after')
    def validate_side_hash(self) -> 'MerkleProofStepBody':
        if (self.side == 'promote') != (self.hash is None):
            raise ValueError('promote steps must omit hash; sibling steps must include hash')
        return self


class MerkleProofBody(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    version: Literal['cpx-merkle-v1']
    leafIndex: int = Field(ge=0, le=4095)
    leafCount: int = Field(ge=1, le=4096)
    steps: list[MerkleProofStepBody] = Field(max_length=12)


class ProofCheckBody(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    event_id: str = Field(min_length=1, max_length=128)
    expected_root: str = Field(pattern=r'^[0-9a-f]{64}$')
    proof: MerkleProofBody


class ManifestBody(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    expected_event_ids: list[str] = Field(min_length=1, max_length=4096)

    @field_validator('expected_event_ids')
    @classmethod
    def validate_ids(cls, value: list[str]) -> list[str]:
        if any(not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,127}', item) for item in value):
            raise ValueError('expected event IDs must use the canonical event ID syntax')
        if len(value) != len(set(value)):
            raise ValueError('expected event IDs must not contain duplicates')
        return value


class InvestigationCreate(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True, strict=True)
    title: str = Field(min_length=1, max_length=160)
    summary: str = Field(default='', max_length=4000)
    evidence_ids: list[str] = Field(default_factory=list, max_length=256)
    correlation_ids: list[str] = Field(default_factory=list, max_length=256)

    @field_validator('evidence_ids')
    @classmethod
    def validate_evidence_ids(cls, value: list[str]) -> list[str]:
        try:
            normalized = [str(uuid.UUID(item)) for item in value]
        except (ValueError, TypeError, AttributeError) as exc:
            raise ValueError('evidence IDs must be UUIDs') from exc
        if len(normalized) != len(set(normalized)):
            raise ValueError('evidence IDs must not contain duplicates')
        return normalized

    @field_validator('correlation_ids')
    @classmethod
    def validate_correlation_ids(cls, value: list[str]) -> list[str]:
        if any(not SHA256_RE.fullmatch(item) for item in value):
            raise ValueError('correlation IDs must be lowercase SHA-256 identifiers')
        if len(value) != len(set(value)):
            raise ValueError('correlation IDs must not contain duplicates')
        return value


class InvestigationStatusBody(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    status: Literal['open', 'closed']


def _configured_api_tokens() -> list[tuple[str, bytes]]:
    """Return role-tagged bearer-token digests; token values never enter logs or storage."""
    configured: list[tuple[str, bytes]] = []
    for role, variable in (('viewer', 'CPX_API_VIEWER_TOKEN'), ('analyst', 'CPX_API_ANALYST_TOKEN')):
        token = os.environ.get(variable, '')
        if not token:
            continue
        if len(token) < 43 or len(token) > 512 or any(ord(char) < 0x21 or ord(char) > 0x7e for char in token):
            raise RuntimeError(f'{variable} must be 43-512 printable non-space ASCII characters')
        digest = hashlib.sha256(token.encode('ascii')).digest()
        if any(hmac.compare_digest(digest, prior) for _, prior in configured):
            raise RuntimeError('viewer and analyst API tokens must be different')
        configured.append((role, digest))
    if {role for role, _ in configured} != {'viewer', 'analyst'}:
        raise RuntimeError('both viewer and analyst API tokens must be configured')
    return configured


def _authenticate_api_request(scope: Scope) -> tuple[int, str | None]:
    """Fail closed for API calls; GETs need viewer, state changes need analyst."""
    try:
        configured = _configured_api_tokens()
    except RuntimeError:
        return 503, None
    headers = [value for key, value in scope.get('headers', []) if key.lower() == b'authorization']
    if len(headers) != 1:
        return 401, None
    try:
        scheme, token = headers[0].decode('ascii').split(' ', 1)
    except (UnicodeDecodeError, ValueError):
        return 401, None
    if scheme.lower() != 'bearer' or not token or len(token) > 512 or ' ' in token:
        return 401, None
    supplied_digest = hashlib.sha256(token.encode('ascii')).digest()
    matching_role = None
    for role, expected_digest in configured:
        if hmac.compare_digest(supplied_digest, expected_digest):
            matching_role = role
    if matching_role is None:
        return 401, None
    if scope.get('method') in {'POST', 'PUT', 'PATCH', 'DELETE'} and matching_role != 'analyst':
        return 403, matching_role
    return 200, matching_role


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'duplicate JSON key: {key}')
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f'invalid JSON constant: {value}')


def parse_event_json(raw: str) -> dict[str, Any]:
    if len(raw.encode('utf-8', errors='surrogatepass')) > EVENT_FORM_MAX_BYTES:
        raise HTTPException(status_code=413, detail='event JSON exceeds the request limit')
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise HTTPException(status_code=422, detail='event must be unambiguous valid JSON') from exc
    if not isinstance(value, dict):
        raise HTTPException(status_code=422, detail='event must be a JSON object')
    return value


def canonicalize_with_existing_module(event: dict[str, Any]) -> tuple[dict[str, Any], bytes, str]:
    try:
        payload = json.dumps(event, ensure_ascii=True, separators=(',', ':'), allow_nan=False)
    except (TypeError, ValueError, RecursionError) as exc:
        raise HTTPException(status_code=422, detail='event contains an unsupported JSON value') from exc
    node = os.environ.get('CHAINPROOF_NODE', 'node')
    try:
        result = subprocess.run(
            [node, '--experimental-strip-types', str(INTEGRITY_CLI)],
            input=payload,
            text=True,
            capture_output=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise HTTPException(status_code=503, detail='integrity canonicalizer is unavailable') from exc
    if result.returncode != 0:
        message = result.stderr.strip()[:256] or 'event failed integrity validation'
        raise HTTPException(status_code=422, detail=message)
    try:
        response = json.loads(result.stdout)
        canonical = base64.b64decode(response['canonicalEventBase64'], validate=True)
        digest = response['canonicalEventSha256']
        normalized = response['event']
    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=503, detail='integrity canonicalizer returned an invalid response') from exc
    if not SHA256_RE.fullmatch(digest) or hashlib.sha256(canonical).hexdigest() != digest:
        raise HTTPException(status_code=503, detail='integrity canonicalizer returned inconsistent output')
    return normalized, canonical, digest


def verified_stored_event(normalized_json: str, stored_digest: str, event_id: str) -> dict[str, Any]:
    try:
        event = json.loads(normalized_json)
    except (json.JSONDecodeError, TypeError, RecursionError) as exc:
        raise HTTPException(status_code=409, detail=f'stored normalized event is malformed for {event_id}; operation refused') from exc
    try:
        normalized, _canonical, digest = canonicalize_with_existing_module(event)
    except HTTPException as exc:
        if exc.status_code == 503:
            raise
        raise HTTPException(status_code=409, detail=f'stored normalized event is invalid for {event_id}; operation refused') from exc
    if digest != stored_digest or normalized != event or event.get('eventId') != event_id:
        raise HTTPException(status_code=409, detail=f'stored normalized event integrity mismatch for {event_id}; operation refused')
    return event


def integrity_sha256_file(path: Path) -> str:
    node = os.environ.get('CHAINPROOF_NODE', 'node')
    try:
        result = subprocess.run(
            [node, '--experimental-strip-types', str(INTEGRITY_CLI), '--sha256-file', str(path)],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise HTTPException(status_code=503, detail='integrity hasher is unavailable') from exc
    digest = result.stdout.strip()
    if result.returncode != 0 or not SHA256_RE.fullmatch(digest):
        raise HTTPException(status_code=503, detail='integrity hasher returned an invalid result')
    return digest


def integrity_merkle_batch(events: list[dict[str, Any]]) -> tuple[str, int, str]:
    try:
        payload = json.dumps(events, ensure_ascii=True, separators=(',', ':'), allow_nan=False)
    except (TypeError, ValueError, RecursionError) as exc:
        raise HTTPException(status_code=422, detail='events contain an unsupported JSON value') from exc
    node = os.environ.get('CHAINPROOF_NODE', 'node')
    try:
        result = subprocess.run(
            [node, '--experimental-strip-types', str(INTEGRITY_CLI), '--merkle-batch'],
            input=payload,
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise HTTPException(status_code=503, detail='integrity Merkle builder is unavailable') from exc
    if result.returncode != 0:
        message = result.stderr.strip()[:256] or 'events failed Merkle validation'
        raise HTTPException(status_code=422, detail=message)
    try:
        response = json.loads(result.stdout)
        root = response['rootHash']
        leaf_count = response['leafCount']
        tree_version = response['treeVersion']
        normalized_events = response['events']
    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=503, detail='integrity Merkle builder returned an invalid response') from exc
    if (not isinstance(root, str) or not SHA256_RE.fullmatch(root) or not isinstance(leaf_count, int)
            or isinstance(leaf_count, bool) or leaf_count != len(events) or tree_version != 'cpx-merkle-v1'
            or not isinstance(normalized_events, list) or len(normalized_events) != len(events)):
        raise HTTPException(status_code=503, detail='integrity Merkle builder returned inconsistent output')
    return root, leaf_count, tree_version


def integrity_operation(operation: str, payload: Any) -> dict[str, Any]:
    if operation not in {'--merkle-context', '--verify-proof', '--verify-signature', '--validate-key'}:
        raise ValueError('unsupported integrity operation')
    try:
        encoded = json.dumps(payload, ensure_ascii=True, separators=(',', ':'), allow_nan=False)
    except (TypeError, ValueError, RecursionError) as exc:
        raise HTTPException(status_code=422, detail='verification input is not valid JSON data') from exc
    try:
        result = subprocess.run(
            [os.environ.get('CHAINPROOF_NODE', 'node'), '--experimental-strip-types', str(INTEGRITY_CLI), operation],
            input=encoded, text=True, capture_output=True, timeout=10, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise HTTPException(status_code=503, detail='integrity verifier is unavailable') from exc
    if result.returncode != 0:
        raise HTTPException(status_code=422, detail=(result.stderr.strip()[:256] or 'integrity verification input was rejected'))
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=503, detail='integrity verifier returned malformed output') from exc
    if not isinstance(value, dict):
        raise HTTPException(status_code=503, detail='integrity verifier returned malformed output')
    return value


def configured_chain_client() -> EvidenceRegistryRpc:
    deployment_path = Path(os.environ.get('CHAINPROOF_DEPLOYMENT_FILE', PROJECT_ROOT / 'data' / 'hardhat-deployment.json'))
    deployment: dict[str, Any] = {}
    if deployment_path.exists():
        try:
            loaded = json.loads(deployment_path.read_text(encoding='utf-8'))
        except (OSError, json.JSONDecodeError) as exc:
            raise ChainUnavailable('Hardhat deployment metadata is unreadable.') from exc
        if not isinstance(loaded, dict):
            raise ChainUnavailable('Hardhat deployment metadata is malformed.')
        deployment = loaded
    address = os.environ.get('CHAINPROOF_CONTRACT_ADDRESS') or deployment.get('contract_address')
    raw_chain_id = os.environ.get('CHAINPROOF_CHAIN_ID') or deployment.get('chain_id')
    if address is None or raw_chain_id is None:
        raise ChainUnavailable('Deploy EvidenceRegistry locally and configure its deployment metadata first.')
    try:
        chain_id = int(raw_chain_id)
    except (TypeError, ValueError) as exc:
        raise ChainUnavailable('Configured Hardhat chain ID is invalid.') from exc
    return EvidenceRegistryRpc(
        rpc_url=os.environ.get('CHAINPROOF_RPC_URL', 'http://127.0.0.1:8545'),
        expected_chain_id=chain_id,
        contract_address=address,
        sender_address=os.environ.get('CHAINPROOF_ANCHOR_ACCOUNT'),
    )


def _connect(database_path: Path) -> sqlite3.Connection:
    database_path.parent.mkdir(parents=True, exist_ok=True)
    if os.name == 'posix':
        # Create a new evidence database with owner-only permissions from its
        # first byte. Tighten the mode of an existing database on startup too.
        try:
            fd = os.open(database_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            os.chmod(database_path, 0o600)
        else:
            os.close(fd)
    connection = sqlite3.connect(database_path, timeout=10, isolation_level='DEFERRED')
    connection.row_factory = sqlite3.Row
    connection.execute('PRAGMA foreign_keys = ON')
    connection.execute('PRAGMA busy_timeout = 10000')
    return connection


@contextmanager
def _db(database_path: Path) -> Iterator[sqlite3.Connection]:
    connection = _connect(database_path)
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize_database(database_path: Path) -> None:
    database_path.parent.mkdir(parents=True, exist_ok=True)
    connection = _connect(database_path)
    try:
        connection.executescript(SCHEMA_PATH.read_text(encoding='utf-8'))
        signature_columns = {row['name'] for row in connection.execute('PRAGMA table_info(signature_checks)')}
        for name, definition in (
            ('tree_version', "TEXT NOT NULL DEFAULT 'cpx-merkle-v1'"),
            ('leaf_count', 'INTEGER NOT NULL DEFAULT 1'),
            ('root_hash', "TEXT NOT NULL DEFAULT ''"),
        ):
            if name not in signature_columns:
                connection.execute(f'ALTER TABLE signature_checks ADD COLUMN {name} {definition}')
    finally:
        connection.close()


def _safe_filename(filename: str | None) -> str:
    # Never use an uploaded filename as a path. Retain only a bounded display value.
    raw = (filename or 'evidence.bin').replace('\\', '/')
    name = PurePosixPath(raw).name
    name = ''.join(char for char in name if ord(char) >= 32 and not 0x7F <= ord(char) <= 0x9F)
    name = name.strip()[:255]
    return name or 'evidence.bin'


def _media_type(value: str | None) -> str:
    result = (value or 'application/octet-stream').split(';', 1)[0].strip().lower()
    if len(result) > 127 or not MEDIA_TYPE_RE.fullmatch(result):
        return 'application/octet-stream'
    return result


class IngestBodyLimitMiddleware:
    """Bound multipart request bytes before Starlette spools uploaded files."""

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        proof_request = scope.get('path', '').endswith('/verification/proof')
        if (scope['type'] != 'http' or scope.get('method') != 'POST'
                or not (proof_request or scope.get('path', '').endswith('/evidence')
                        or scope.get('path', '').endswith('/verify-candidate'))):
            await self.app(scope, receive, send)
            return
        request_limit = MAX_PROOF_REQUEST_BYTES if proof_request else self.max_bytes
        limit_detail = 'proof request exceeds the request limit' if proof_request else 'evidence request exceeds the upload limit'

        headers = {key.lower(): value for key, value in scope.get('headers', [])}
        declared = headers.get(b'content-length')
        if declared is not None:
            try:
                declared_size = int(declared)
            except ValueError:
                await self._send_error(send, 400, 'invalid Content-Length')
                return
            if declared_size < 0 or declared_size > request_limit:
                await self._send_error(send, 413, limit_detail)
                return

        consumed = 0
        over_limit = False
        response_started = False

        async def bounded_receive() -> Message:
            nonlocal consumed, over_limit
            message = await receive()
            if message['type'] == 'http.request':
                consumed += len(message.get('body', b''))
                if consumed > request_limit:
                    over_limit = True
                    return {'type': 'http.request', 'body': b'', 'more_body': False}
            return message

        async def bounded_send(message: Message) -> None:
            nonlocal response_started
            if not over_limit:
                if message['type'] == 'http.response.start':
                    response_started = True
                await send(message)
                return
            if message['type'] == 'http.response.start':
                response_started = True
                body = json.dumps({'detail': limit_detail}, separators=(',', ':')).encode()
                await send({
                    'type': 'http.response.start', 'status': 413,
                    'headers': [(b'content-type', b'application/json'), (b'content-length', str(len(body)).encode())],
                })
            elif message['type'] == 'http.response.body':
                body = json.dumps({'detail': limit_detail}, separators=(',', ':')).encode() if not message.get('more_body', False) else b''
                await send({'type': 'http.response.body', 'body': body, 'more_body': message.get('more_body', False)})

        await self.app(scope, bounded_receive, bounded_send)
        if over_limit and not response_started:
            await self._send_error(send, 413, limit_detail)

    @staticmethod
    async def _send_error(send: Send, status: int, detail: str) -> None:
        body = json.dumps({'detail': detail}, separators=(',', ':')).encode()
        await send({
            'type': 'http.response.start', 'status': status,
            'headers': [(b'content-type', b'application/json'), (b'content-length', str(len(body)).encode())],
        })
        await send({'type': 'http.response.body', 'body': body, 'more_body': False})


class LocalBrowserOriginMiddleware:
    """Reject browser state-changing requests initiated by non-local origins.

    This is defense-in-depth alongside bearer-token authorization; it is not
    an authentication or authorization mechanism by itself.
    """

    _STATE_CHANGING = {'POST', 'PUT', 'PATCH', 'DELETE'}
    _LOCAL_PORTS = {5173, 8000}

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope['type'] == 'http' and scope.get('method') in self._STATE_CHANGING:
            origins = [value for key, value in scope.get('headers', []) if key.lower() == b'origin']
            if origins and (len(origins) != 1 or not self._is_allowed_origin(origins[0])):
                await IngestBodyLimitMiddleware._send_error(send, 403, 'state-changing browser requests require a local ChainProof X origin')
                return
        await self.app(scope, receive, send)

    @classmethod
    def _is_allowed_origin(cls, value: bytes) -> bool:
        try:
            origin = value.decode('ascii')
            parsed = urllib.parse.urlsplit(origin)
            hostname = parsed.hostname
            port = parsed.port
            ip = ipaddress.ip_address(hostname) if hostname else None
            loopback = hostname == 'localhost' or ip is not None and ip.is_loopback
            configured_ports = {
                int(candidate) for candidate in (
                    os.environ.get('CPX_FRONTEND_PORT', ''),
                    os.environ.get('CPX_API_PORT', ''),
                ) if candidate.isdigit()
            }
            return (parsed.scheme == 'http' and loopback and port in cls._LOCAL_PORTS | configured_ports
                    and not parsed.username and not parsed.password and not parsed.path
                    and not parsed.query and not parsed.fragment)
        except (UnicodeDecodeError, ValueError):
            return False


class APIAuthenticationMiddleware:
    """Require a bearer token for data routes; viewers read, analysts write."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        path = scope.get('path', '')
        if scope.get('type') != 'http' or not (path == '/api/v1' or path.startswith('/api/v1/')):
            await self.app(scope, receive, send)
            return
        status, role = _authenticate_api_request(scope)
        if status != 200:
            detail = {
                401: 'valid ChainProof bearer token required',
                403: 'analyst role required for state-changing requests',
                503: 'API authentication is not configured; set distinct viewer and analyst tokens',
            }[status]
            await IngestBodyLimitMiddleware._send_error(send, status, detail)
            return
        scope.setdefault('state', {})['cpx_role'] = role
        await self.app(scope, receive, send)


def _expected_storage_key(digest: str) -> str:
    if not SHA256_RE.fullmatch(digest):
        raise ValueError('invalid stored digest')
    return f'{digest[:2]}/{digest}.bin'


def _hash_evidence_blob(storage_root: Path, storage_key: str) -> tuple[str | None, int | None, str | None]:
    """Hash an evidence object without following a replaceable symlink."""
    expected = _expected_storage_key(Path(storage_key).name.removesuffix('.bin'))
    if storage_key != expected:
        return None, None, 'stored_object_path_invalid'
    root_flags = os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_NOFOLLOW', 0)
    leaf_flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    root_fd = prefix_fd = blob_fd = None
    try:
        root_fd = os.open(storage_root, root_flags)
        prefix_name = storage_key.split('/', 1)[0]
        try:
            os.mkdir(prefix_name, mode=0o700, dir_fd=root_fd)
        except FileExistsError:
            pass
        prefix_fd = os.open(prefix_name, root_flags, dir_fd=root_fd)
        blob_fd = os.open(Path(storage_key).name, leaf_flags, dir_fd=prefix_fd)
        if not stat.S_ISREG(os.fstat(blob_fd).st_mode):
            return None, None, 'stored_object_path_invalid'
        digest = hashlib.sha256()
        total = 0
        with os.fdopen(blob_fd, 'rb', closefd=False) as source:
            for chunk in iter(lambda: source.read(UPLOAD_CHUNK_BYTES), b''):
                total += len(chunk)
                if total > MAX_UPLOAD_BYTES:
                    return None, total, 'stored_object_exceeds_limit'
                digest.update(chunk)
        return digest.hexdigest(), total, None
    except FileNotFoundError:
        return None, None, 'stored_object_missing'
    except OSError:
        return None, None, 'stored_object_path_invalid'
    finally:
        for descriptor in (blob_fd, prefix_fd, root_fd):
            if descriptor is not None:
                os.close(descriptor)


def _install_blob(temp_path: Path, storage_root: Path, digest: str) -> tuple[str, bool]:
    storage_key = _expected_storage_key(digest)
    # Do not follow a pre-planted symlink at the content-addressed prefix.
    # Resolve the parent after creation and require it to remain directly under
    # the configured object root before touching the destination.
    if storage_root.is_symlink():
        raise HTTPException(status_code=500, detail='evidence object storage path is invalid')
    storage_root = storage_root.resolve(strict=True)
    destination = storage_root / storage_key
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if destination.parent.is_symlink() or destination.parent.resolve(strict=True).parent != storage_root:
        raise HTTPException(status_code=500, detail='evidence object storage path is invalid')
    if destination.is_symlink():
        raise HTTPException(status_code=500, detail='evidence object storage path is invalid')
    if os.name == 'posix':
        flags = os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_NOFOLLOW', 0)
        root_fd = None
        prefix_fd = None
        try:
            root_fd = os.open(storage_root, flags)
            try:
                os.mkdir(destination.parent.name, mode=0o700, dir_fd=root_fd)
            except FileExistsError:
                pass
            prefix_fd = os.open(destination.parent.name, flags, dir_fd=root_fd)
        except OSError as exc:
            if prefix_fd is not None:
                os.close(prefix_fd)
            if root_fd is not None:
                os.close(root_fd)
            raise HTTPException(status_code=500, detail='evidence object storage path is invalid') from exc
        try:
            if not stat.S_ISDIR(os.fstat(prefix_fd).st_mode):
                raise HTTPException(status_code=500, detail='evidence object storage path is invalid')
            os.fchmod(prefix_fd, 0o700)
            try:
                # Pin the checked directory across the atomic hard link. O_NOFOLLOW
                # prevents a last-moment symlink swap from escaping the object root.
                os.link(temp_path, destination.name, dst_dir_fd=prefix_fd)
                installed_fd = os.open(destination.name, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0), dir_fd=prefix_fd)
                try:
                    os.fchmod(installed_fd, 0o600)
                finally:
                    os.close(installed_fd)
                return storage_key, True
            except FileExistsError:
                try:
                    existing_fd = os.open(destination.name, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0), dir_fd=prefix_fd)
                except OSError as exc:
                    raise HTTPException(status_code=500, detail='content-addressed evidence object is inconsistent') from exc
                try:
                    info = os.fstat(existing_fd)
                    existing_digest = hashlib.sha256()
                    with os.fdopen(existing_fd, 'rb', closefd=False) as existing:
                        for chunk in iter(lambda: existing.read(UPLOAD_CHUNK_BYTES), b''):
                            existing_digest.update(chunk)
                    if existing_digest.hexdigest() != digest or info.st_size != temp_path.stat().st_size or not stat.S_ISREG(info.st_mode):
                        raise HTTPException(status_code=500, detail='content-addressed evidence object is inconsistent')
                    os.fchmod(existing_fd, 0o600)
                finally:
                    os.close(existing_fd)
                return storage_key, False
            except OSError as exc:
                raise HTTPException(status_code=500, detail='evidence object could not be stored') from exc
        finally:
            if prefix_fd is not None:
                os.close(prefix_fd)
            if root_fd is not None:
                os.close(root_fd)
    try:
        # Hard-link installation is atomic and never overwrites an existing object.
        os.link(temp_path, destination)
        if os.name == 'posix':
            os.chmod(destination, 0o600)
        return storage_key, True
    except FileExistsError:
        existing_digest = hashlib.sha256()
        with destination.open('rb') as existing:
            for chunk in iter(lambda: existing.read(UPLOAD_CHUNK_BYTES), b''):
                existing_digest.update(chunk)
        if existing_digest.hexdigest() != digest or destination.stat().st_size != temp_path.stat().st_size:
            raise HTTPException(status_code=500, detail='content-addressed evidence object is inconsistent')
        if os.name == 'posix':
            os.chmod(destination, 0o600)
        return storage_key, False
    except OSError as exc:
        raise HTTPException(status_code=500, detail='evidence object could not be stored') from exc


def create_app(
    database_path: str | Path | None = None,
    evidence_root: str | Path | None = None,
) -> FastAPI:
    db_path = Path(database_path or os.environ.get('CHAINPROOF_DB', PROJECT_ROOT / 'data' / 'chainproof.sqlite3')).resolve()
    configured_object_root = Path(evidence_root or os.environ.get('CHAINPROOF_EVIDENCE_DIR', PROJECT_ROOT / 'data' / 'evidence')).absolute()
    if configured_object_root.is_symlink():
        raise ValueError('evidence storage root must not be a symlink')
    object_root = configured_object_root.resolve()
    object_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name == 'posix':
        os.chmod(object_root, 0o700)
    initialize_database(db_path)

    app = FastAPI(title='ChainProof X API', version='0.1.0')
    app.add_middleware(LocalBrowserOriginMiddleware)
    app.add_middleware(APIAuthenticationMiddleware)
    app.add_middleware(IngestBodyLimitMiddleware, max_bytes=MAX_INGEST_REQUEST_BYTES)
    app.state.database_path = db_path
    app.state.evidence_root = object_root


    @app.get('/health')
    def health() -> dict[str, str]:
        return {'status': 'ok', 'workspace_mode': os.environ.get('CPX_WORKSPACE_MODE', 'local')}

    @app.get('/api/v1/session')
    def api_session(request: Request) -> dict[str, str]:
        return {'role': request.state.cpx_role}

    @app.post('/api/v1/cases', status_code=201)
    def create_case(body: CaseCreate) -> dict[str, str]:
        case_id = str(uuid.uuid4())
        created_at = utc_now()
        with _db(db_path) as connection:
            connection.execute('INSERT INTO cases(id, name, created_at) VALUES (?, ?, ?)', (case_id, body.name, created_at))
        return {'id': case_id, 'name': body.name, 'created_at': created_at}

    @app.get('/api/v1/cases')
    def list_cases() -> list[dict[str, Any]]:
        with _db(db_path) as connection:
            rows = connection.execute(
                '''SELECT c.id, c.name, c.created_at,
                          (SELECT count(*) FROM evidence_objects e WHERE e.case_id = c.id) AS evidence_count,
                          (SELECT count(*) FROM event_records r WHERE r.case_id = c.id) AS event_count
                   FROM cases c ORDER BY c.created_at DESC, c.id ASC'''
            ).fetchall()
        return [dict(row) for row in rows]

    @app.get('/api/v1/cases/{case_id}/evidence')
    def list_case_evidence(
        case_id: str,
        limit: int = Query(default=50, ge=1, le=100),
        offset: int = Query(default=0, ge=0),
    ) -> dict[str, Any]:
        try:
            canonical_uuid = str(uuid.UUID(case_id))
        except ValueError as exc:
            raise HTTPException(status_code=404, detail='case not found') from exc
        with _db(db_path) as connection:
            if connection.execute('SELECT 1 FROM cases WHERE id = ?', (canonical_uuid,)).fetchone() is None:
                raise HTTPException(status_code=404, detail='case not found')
            rows = connection.execute(
                '''SELECT e.id AS evidence_id, e.original_filename AS filename, e.media_type,
                          e.byte_length, e.sha256, e.ingested_at,
                          r.event_id, r.source_id, r.occurred_at, r.event_type,
                          r.normalized_json, r.canonical_sha256 AS canonical_event_sha256
                   FROM evidence_objects e
                   JOIN event_records r ON r.evidence_id = e.id AND r.case_id = e.case_id
                   WHERE e.case_id = ? ORDER BY e.ingested_at DESC, e.id ASC LIMIT ? OFFSET ?''',
                (canonical_uuid, limit, offset),
            ).fetchall()
            total = connection.execute(
                'SELECT count(*) FROM evidence_objects WHERE case_id = ?', (canonical_uuid,)
            ).fetchone()[0]
        items = []
        for row in rows:
            item = dict(row)
            item['event'] = verified_stored_event(item.pop('normalized_json'), item['canonical_event_sha256'], item['event_id'])
            items.append(item)
        return {'items': items, 'total': total, 'limit': limit, 'offset': offset}

    @app.post('/api/v1/cases/{case_id}/organizations', status_code=201)
    def assign_case_organization(case_id: str, body: OrganizationCreate) -> dict[str, Any]:
        try:
            canonical_uuid = str(uuid.UUID(case_id))
        except ValueError as exc:
            raise HTTPException(status_code=404, detail='case not found') from exc
        organization_id = str(uuid.uuid4())
        assigned_at = utc_now()
        with _db(db_path) as connection:
            if connection.execute('SELECT 1 FROM cases WHERE id = ?', (canonical_uuid,)).fetchone() is None:
                raise HTTPException(status_code=404, detail='case not found')
            existing = connection.execute(
                'SELECT organization_id FROM case_organizations WHERE case_id = ?', (canonical_uuid,)
            ).fetchone()
            if existing is not None:
                raise HTTPException(status_code=409, detail='case already has an organization association')
            organization = connection.execute(
                'SELECT id, name, created_at FROM organizations WHERE name = ? COLLATE NOCASE', (body.name,)
            ).fetchone()
            if organization is None:
                connection.execute(
                    'INSERT INTO organizations(id, name, created_at) VALUES (?, ?, ?)',
                    (organization_id, body.name, assigned_at),
                )
                organization = {'id': organization_id, 'name': body.name, 'created_at': assigned_at}
            connection.execute(
                'INSERT INTO case_organizations(case_id, organization_id, assigned_at) VALUES (?, ?, ?)',
                (canonical_uuid, organization['id'], assigned_at),
            )
        return {**dict(organization), 'case_id': canonical_uuid, 'assigned_at': assigned_at,
                'relationship_basis': 'explicit_case_metadata'}

    @app.post('/api/v1/cases/{case_id}/correlations/recompute')
    def recompute_case_correlations(case_id: str) -> dict[str, Any]:
        try:
            canonical_uuid = str(uuid.UUID(case_id))
        except ValueError as exc:
            raise HTTPException(status_code=404, detail='case not found') from exc
        with _db(db_path) as connection:
            if connection.execute('SELECT 1 FROM cases WHERE id = ?', (canonical_uuid,)).fetchone() is None:
                raise HTTPException(status_code=404, detail='case not found')
            rows = connection.execute(
                '''SELECT r.id, r.event_id, r.source_id, r.occurred_at, r.event_type,
                          r.normalized_json, r.canonical_sha256, e.id AS evidence_id
                   FROM event_records r JOIN evidence_objects e ON e.id = r.evidence_id
                   WHERE r.case_id = ? ORDER BY r.occurred_at COLLATE BINARY, r.event_id COLLATE BINARY''',
                (canonical_uuid,),
            ).fetchall()
            if len(rows) > MAX_CORRELATION_EVENTS:
                raise HTTPException(status_code=413, detail=f'correlation is limited to {MAX_CORRELATION_EVENTS} events per case')
            for row in rows:
                verified_stored_event(row['normalized_json'], row['canonical_sha256'], row['event_id'])
            try:
                results = correlate_events(canonical_uuid, [dict(row) for row in rows],
                                           {row['event_id']: row['evidence_id'] for row in rows})
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                raise HTTPException(status_code=422, detail=f'correlation input is invalid: {exc}') from exc

            generated_ids = {result['id'] for result in results}
            linked_ids = {row['correlation_id'] for row in connection.execute(
                '''SELECT ic.correlation_id FROM investigation_correlations ic
                   JOIN investigations i ON i.id=ic.investigation_id WHERE i.case_id=?''', (canonical_uuid,))}
            removed_links = linked_ids - generated_ids
            if removed_links:
                raise HTTPException(status_code=409, detail='recomputation would remove a correlation linked to an investigation; preserve it and review investigation references first')
            existing_ids = {row['id'] for row in connection.execute('SELECT id FROM correlations WHERE case_id=?', (canonical_uuid,))}
            for stale_id in existing_ids - generated_ids:
                connection.execute('DELETE FROM correlations WHERE id=?', (stale_id,))
            created_at = utc_now()
            for result in results:
                connection.execute(
                    '''INSERT INTO correlations
                       (id, case_id, rule_id, rule_version, window_seconds, matched_entities_json,
                        explanation, start_at, end_at, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT(id) DO UPDATE SET
                         rule_id=excluded.rule_id, rule_version=excluded.rule_version,
                         window_seconds=excluded.window_seconds, matched_entities_json=excluded.matched_entities_json,
                         explanation=excluded.explanation, start_at=excluded.start_at, end_at=excluded.end_at,
                         created_at=excluded.created_at''',
                    (result['id'], canonical_uuid, result['rule_id'], result['rule_version'],
                     result['window_seconds'], json.dumps(result['matched_entities'], separators=(',', ':')),
                     result['explanation'], result['start_at'], result['end_at'], created_at),
                )
                connection.execute('DELETE FROM correlation_events WHERE correlation_id=?', (result['id'],))
                connection.executemany(
                    'INSERT INTO correlation_events(correlation_id, ordinal, event_record_id) VALUES (?, ?, ?)',
                    [(result['id'], index, record_id) for index, record_id in enumerate(result['event_record_ids'])],
                )
        response_results = [{key: value for key, value in result.items() if key != 'event_record_ids'} for result in results]
        return {
            'case_id': canonical_uuid,
            'rule_id': RULE_ID,
            'rule_version': RULE_VERSION,
            'window_seconds': WINDOW_SECONDS,
            'event_count': len(rows),
            'correlation_count': len(results),
            'correlations': response_results,
        }

    @app.get('/api/v1/cases/{case_id}/correlations')
    def list_case_correlations(case_id: str) -> list[dict[str, Any]]:
        try:
            canonical_uuid = str(uuid.UUID(case_id))
        except ValueError as exc:
            raise HTTPException(status_code=404, detail='case not found') from exc
        with _db(db_path) as connection:
            if connection.execute('SELECT 1 FROM cases WHERE id = ?', (canonical_uuid,)).fetchone() is None:
                raise HTTPException(status_code=404, detail='case not found')
            correlation_rows = connection.execute(
                'SELECT * FROM correlations WHERE case_id = ? ORDER BY start_at COLLATE BINARY, id',
                (canonical_uuid,),
            ).fetchall()
            investigation_rows = connection.execute(
                'SELECT * FROM investigations WHERE case_id=? ORDER BY updated_at DESC, id', (canonical_uuid,)
            ).fetchall()
            investigation_evidence_refs = {
                row['id']: connection.execute(
                    '''SELECT e.id, e.original_filename FROM investigation_evidence ie
                       JOIN evidence_objects e ON e.id=ie.evidence_id WHERE ie.investigation_id=? ORDER BY e.id''',
                    (row['id'],),
                ).fetchall() for row in investigation_rows
            }
            investigation_correlation_refs = {
                row['id']: connection.execute(
                    '''SELECT c.id, c.rule_id, c.explanation, ce.event_record_id, e.id AS evidence_id
                       FROM investigation_correlations ic JOIN correlations c ON c.id=ic.correlation_id
                       JOIN correlation_events ce ON ce.correlation_id=c.id
                       JOIN event_records r ON r.id=ce.event_record_id JOIN evidence_objects e ON e.id=r.evidence_id
                       WHERE ic.investigation_id=? ORDER BY c.id, ce.ordinal''', (row['id'],)
                ).fetchall() for row in investigation_rows
            }
            results = []
            for correlation in correlation_rows:
                refs = connection.execute(
                    '''SELECT r.event_id, r.source_id, r.occurred_at, r.event_type,
                              r.canonical_sha256, e.id AS evidence_id
                       FROM correlation_events ce JOIN event_records r ON r.id = ce.event_record_id
                       JOIN evidence_objects e ON e.id = r.evidence_id
                       WHERE ce.correlation_id = ? ORDER BY ce.ordinal''',
                    (correlation['id'],),
                ).fetchall()
                results.append({**dict(correlation),
                                'matched_entities': json.loads(correlation['matched_entities_json']),
                                'events': [dict(ref) for ref in refs]})
                results[-1].pop('matched_entities_json')
        return results

    def investigation_response(connection: sqlite3.Connection, row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
        item = dict(row)
        item['evidence_ids'] = [ref['evidence_id'] for ref in connection.execute(
            '''SELECT ie.evidence_id FROM investigation_evidence ie JOIN evidence_objects e ON e.id=ie.evidence_id
               WHERE ie.investigation_id=? ORDER BY e.ingested_at, ie.evidence_id''', (item['id'],))]
        item['correlation_ids'] = [ref['correlation_id'] for ref in connection.execute(
            '''SELECT ic.correlation_id FROM investigation_correlations ic JOIN correlations c ON c.id=ic.correlation_id
               WHERE ic.investigation_id=? ORDER BY c.start_at, ic.correlation_id''', (item['id'],))]
        return item

    @app.get('/api/v1/cases/{case_id}/investigations')
    def list_case_investigations(case_id: str) -> list[dict[str, Any]]:
        try:
            canonical_uuid = str(uuid.UUID(case_id))
        except ValueError as exc:
            raise HTTPException(status_code=404, detail='case not found') from exc
        with _db(db_path) as connection:
            if connection.execute('SELECT 1 FROM cases WHERE id=?', (canonical_uuid,)).fetchone() is None:
                raise HTTPException(status_code=404, detail='case not found')
            rows = connection.execute('SELECT * FROM investigations WHERE case_id=? ORDER BY updated_at DESC, id', (canonical_uuid,)).fetchall()
            return [investigation_response(connection, row) for row in rows]

    @app.post('/api/v1/cases/{case_id}/investigations', status_code=201)
    def create_case_investigation(case_id: str, body: InvestigationCreate) -> dict[str, Any]:
        try:
            canonical_uuid = str(uuid.UUID(case_id))
        except ValueError as exc:
            raise HTTPException(status_code=404, detail='case not found') from exc
        investigation_id = str(uuid.uuid4())
        timestamp = utc_now()
        with _db(db_path) as connection:
            if connection.execute('SELECT 1 FROM cases WHERE id=?', (canonical_uuid,)).fetchone() is None:
                raise HTTPException(status_code=404, detail='case not found')
            evidence_count = connection.execute(
                f"SELECT count(*) FROM evidence_objects WHERE case_id=? AND id IN ({','.join('?' for _ in body.evidence_ids)})" if body.evidence_ids else 'SELECT 0',
                (canonical_uuid, *body.evidence_ids) if body.evidence_ids else (),
            ).fetchone()[0]
            if evidence_count != len(body.evidence_ids):
                raise HTTPException(status_code=422, detail='every evidence reference must belong to this case')
            correlation_count = connection.execute(
                f"SELECT count(*) FROM correlations WHERE case_id=? AND id IN ({','.join('?' for _ in body.correlation_ids)})" if body.correlation_ids else 'SELECT 0',
                (canonical_uuid, *body.correlation_ids) if body.correlation_ids else (),
            ).fetchone()[0]
            if correlation_count != len(body.correlation_ids):
                raise HTTPException(status_code=422, detail='every correlation reference must belong to this case')
            connection.execute('INSERT INTO investigations(id, case_id, title, summary, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
                               (investigation_id, canonical_uuid, body.title, body.summary, 'open', timestamp, timestamp))
            connection.executemany('INSERT INTO investigation_evidence(investigation_id, evidence_id) VALUES (?, ?)',
                                   [(investigation_id, item) for item in body.evidence_ids])
            connection.executemany('INSERT INTO investigation_correlations(investigation_id, correlation_id) VALUES (?, ?)',
                                   [(investigation_id, item) for item in body.correlation_ids])
            result = investigation_response(connection, connection.execute('SELECT * FROM investigations WHERE id=?', (investigation_id,)).fetchone())
        return result

    @app.post('/api/v1/investigations/{investigation_id}/status')
    def update_investigation_status(investigation_id: str, body: InvestigationStatusBody) -> dict[str, Any]:
        try:
            canonical_id = str(uuid.UUID(investigation_id))
        except ValueError as exc:
            raise HTTPException(status_code=404, detail='investigation not found') from exc
        updated_at = utc_now()
        with _db(db_path) as connection:
            connection.execute('UPDATE investigations SET status=?, updated_at=? WHERE id=?', (body.status, updated_at, canonical_id))
            row = connection.execute('SELECT * FROM investigations WHERE id=?', (canonical_id,)).fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail='investigation not found')
            result = investigation_response(connection, row)
        return result

    @app.get('/api/v1/cases/{case_id}/trust-graph')
    def get_case_trust_graph(case_id: str) -> dict[str, Any]:
        try:
            canonical_uuid = str(uuid.UUID(case_id))
        except ValueError as exc:
            raise HTTPException(status_code=404, detail='case not found') from exc
        with _db(db_path) as connection:
            case = connection.execute('SELECT id, name FROM cases WHERE id = ?', (canonical_uuid,)).fetchone()
            if case is None:
                raise HTTPException(status_code=404, detail='case not found')
            rows = connection.execute(
                '''SELECT r.id AS record_id, r.event_id, r.source_id, r.occurred_at, r.event_type,
                          r.normalized_json, r.canonical_sha256, e.id AS evidence_id,
                          e.original_filename, e.sha256 AS evidence_sha256, e.byte_length, e.ingested_at
                   FROM event_records r JOIN evidence_objects e ON e.id = r.evidence_id
                   WHERE r.case_id = ? ORDER BY r.occurred_at COLLATE BINARY, r.event_id COLLATE BINARY''',
                (canonical_uuid,),
            ).fetchall()
            if len(rows) > MAX_CORRELATION_EVENTS:
                raise HTTPException(status_code=413, detail=f'trust graph is limited to {MAX_CORRELATION_EVENTS} events per case')
            organization = connection.execute(
                '''SELECT o.id, o.name, co.assigned_at FROM case_organizations co
                   JOIN organizations o ON o.id = co.organization_id WHERE co.case_id = ?''',
                (canonical_uuid,),
            ).fetchone()
            correlation_rows = connection.execute(
                'SELECT * FROM correlations WHERE case_id = ? ORDER BY start_at COLLATE BINARY, id',
                (canonical_uuid,),
            ).fetchall()
            investigation_rows = connection.execute(
                'SELECT * FROM investigations WHERE case_id=? ORDER BY updated_at DESC, id', (canonical_uuid,)
            ).fetchall()
            investigation_evidence_refs = {
                row['id']: connection.execute(
                    '''SELECT e.id, e.original_filename FROM investigation_evidence ie
                       JOIN evidence_objects e ON e.id=ie.evidence_id WHERE ie.investigation_id=? ORDER BY e.id''',
                    (row['id'],),
                ).fetchall() for row in investigation_rows
            }
            investigation_correlation_refs = {
                row['id']: connection.execute(
                    '''SELECT c.id, c.rule_id, c.explanation, ce.event_record_id, e.id AS evidence_id
                       FROM investigation_correlations ic JOIN correlations c ON c.id=ic.correlation_id
                       JOIN correlation_events ce ON ce.correlation_id=c.id
                       JOIN event_records r ON r.id=ce.event_record_id JOIN evidence_objects e ON e.id=r.evidence_id
                       WHERE ic.investigation_id=? ORDER BY c.id, ce.ordinal''', (row['id'],)
                ).fetchall() for row in investigation_rows
            }
            correlation_refs = {
                row['id']: connection.execute(
                    '''SELECT r.id AS record_id, r.event_id, r.source_id, e.id AS evidence_id
                       FROM correlation_events ce JOIN event_records r ON r.id = ce.event_record_id
                       JOIN evidence_objects e ON e.id = r.evidence_id
                       WHERE ce.correlation_id = ? ORDER BY ce.ordinal''', (row['id'],)
                ).fetchall()
                for row in correlation_rows
            }

        nodes: list[dict[str, Any]] = []
        edges: list[dict[str, Any]] = []
        if not rows and organization is None and not investigation_rows:
            return {'case_id': canonical_uuid, 'nodes': [], 'edges': [], 'correlation_count': 0}

        case_node_id = f'case:{canonical_uuid}'
        nodes.append({'id': case_node_id, 'type': 'case', 'label': case['name'],
                      'details': 'Current case scope; organization association is explicit metadata.'})
        if organization is not None:
            organization_node_id = f"organization:{organization['id']}"
            nodes.append({'id': organization_node_id, 'type': 'organization', 'label': organization['name'],
                          'details': 'Explicit case metadata association; not inferred from evidence.'})
            edges.append({'id': f'{case_node_id}->{organization_node_id}', 'source': case_node_id,
                          'target': organization_node_id, 'relationship': 'associated_with',
                          'rule_id': None, 'explanation': 'Organization was explicitly associated with this case.',
                          'evidence_ids': []})

        for row in rows:
            event = verified_stored_event(row['normalized_json'], row['canonical_sha256'], row['event_id'])
            event_node_id = f"event:{row['record_id']}"
            evidence_node_id = f"evidence:{row['evidence_id']}"
            nodes.append({'id': evidence_node_id, 'type': 'evidence', 'label': row['original_filename'],
                          'details': f"SHA-256 {row['evidence_sha256']} · {row['byte_length']} bytes",
                          'evidence_id': row['evidence_id'], 'sha256': row['evidence_sha256']})
            nodes.append({'id': event_node_id, 'type': 'event', 'label': row['event_id'],
                          'details': f"{row['event_type']} · {row['source_id']} · {row['occurred_at']}",
                          'event': event, 'evidence_id': row['evidence_id'], 'canonical_sha256': row['canonical_sha256']})
            edges.append({'id': f'{event_node_id}->{evidence_node_id}', 'source': event_node_id,
                          'target': evidence_node_id, 'relationship': 'derived_from', 'rule_id': None,
                          'explanation': 'This normalized event record references the separately preserved original evidence object.',
                          'evidence_ids': [row['evidence_id']]})
            for entity_type, key, label in entity_keys(event):
                entity_digest = hashlib.sha256(f'{entity_type}\0{key}'.encode('utf-8')).hexdigest()
                entity_node_id = f'entity:{entity_type}:{entity_digest}'
                if not any(node['id'] == entity_node_id for node in nodes):
                    nodes.append({'id': entity_node_id, 'type': 'entity', 'label': f'{entity_type}: {label}',
                                  'details': f'Normalized {entity_type} match key: {key}',
                                  'entity_type': entity_type, 'entity_key': key})
                source_kind = event['eventType'].split('.', 1)[0]
                field = 'actor' if ((source_kind in {'windows', 'linux_audit'} and entity_type == 'user')
                                    or (source_kind == 'network' and entity_type == 'host')) else 'target'
                edges.append({'id': f'{event_node_id}->{entity_node_id}', 'source': event_node_id,
                              'target': entity_node_id, 'relationship': 'references',
                              'rule_id': 'entity-normalization-v1',
                              'explanation': f"Entity key derived from the canonical event {field} field using the {event['eventType'].split('.', 1)[0]} adapter.",
                              'evidence_ids': [row['evidence_id']]})

        by_record = {row['record_id']: row for row in rows}
        for correlation in correlation_rows:
            refs = correlation_refs[correlation['id']]
            if len(refs) != 2:
                continue
            incident_node_id = f"incident:{correlation['id']}"
            matched_entities = json.loads(correlation['matched_entities_json'])
            nodes.append({'id': incident_node_id, 'type': 'incident',
                          'label': f"Correlation · {', '.join(matched_entities)}",
                          'details': correlation['explanation'], 'rule_id': correlation['rule_id'],
                          'rule_version': correlation['rule_version'], 'matched_entities': matched_entities,
                          'window_seconds': correlation['window_seconds']})
            evidence_ids = sorted({ref['evidence_id'] for ref in refs})
            for ref in refs:
                event_node_id = f"event:{ref['record_id']}"
                if ref['record_id'] not in by_record:
                    continue
                edges.append({'id': f'{event_node_id}->{incident_node_id}', 'source': event_node_id,
                              'target': incident_node_id, 'relationship': 'correlated_by',
                              'rule_id': correlation['rule_id'], 'explanation': correlation['explanation'],
                              'evidence_ids': evidence_ids})
        for investigation in investigation_rows:
            investigation_node_id = f"investigation:{investigation['id']}"
            nodes.append({'id': investigation_node_id, 'type': 'investigation', 'label': investigation['title'],
                          'details': f"{investigation['status'].title()} · {investigation['summary'] or 'No analyst summary supplied.'}",
                          'status': investigation['status']})
            edges.append({'id': f'{case_node_id}->{investigation_node_id}', 'source': case_node_id,
                          'target': investigation_node_id, 'relationship': 'contains_investigation',
                          'rule_id': None, 'explanation': 'Analyst-authored investigation record scoped to this case.',
                          'evidence_ids': []})
            evidence_refs = investigation_evidence_refs[investigation['id']]
            correlation_refs = investigation_correlation_refs[investigation['id']]
            for evidence in evidence_refs:
                evidence_node_id = f"evidence:{evidence['id']}"
                if any(node['id'] == evidence_node_id for node in nodes):
                    edges.append({'id': f'{investigation_node_id}->{evidence_node_id}', 'source': investigation_node_id,
                                  'target': evidence_node_id, 'relationship': 'references_evidence', 'rule_id': None,
                                  'explanation': 'Evidence was explicitly selected by an analyst for this investigation.',
                                  'evidence_ids': [evidence['id']]})
            linked_evidence_ids = sorted({row['evidence_id'] for row in correlation_refs})
            for correlation_ref in correlation_refs:
                event_node_id = f"event:{correlation_ref['event_record_id']}"
                edges.append({'id': f"{investigation_node_id}->{correlation_ref['event_record_id']}:{correlation_ref['id']}",
                              'source': investigation_node_id, 'target': event_node_id,
                              'relationship': 'reviews_correlation_candidate', 'rule_id': correlation_ref['rule_id'],
                              'explanation': correlation_ref['explanation'], 'evidence_ids': linked_evidence_ids})
        return {'case_id': canonical_uuid, 'nodes': nodes, 'edges': edges,
                'correlation_count': len(correlation_rows)}

    @app.post('/api/v1/cases/{case_id}/anchors', status_code=201)
    def anchor_case_events(case_id: str, body: AnchorCreate) -> dict[str, Any]:
        try:
            canonical_uuid = str(uuid.UUID(case_id))
        except ValueError as exc:
            raise HTTPException(status_code=404, detail='case not found') from exc
        with _db(db_path) as connection:
            if connection.execute('SELECT 1 FROM cases WHERE id = ?', (canonical_uuid,)).fetchone() is None:
                raise HTTPException(status_code=404, detail='case not found')
            if connection.execute('SELECT 1 FROM blockchain_anchors WHERE batch_id = ?', (body.batch_id,)).fetchone() is not None:
                raise HTTPException(status_code=409, detail='batch ID already recorded')
            event_rows = connection.execute(
                'SELECT event_id, normalized_json, canonical_sha256 FROM event_records WHERE case_id = ? ORDER BY event_id COLLATE BINARY ASC',
                (canonical_uuid,),
            ).fetchall()
        if not event_rows:
            raise HTTPException(status_code=409, detail='case has no normalized events to anchor')
        events = [verified_stored_event(row['normalized_json'], row['canonical_sha256'], row['event_id']) for row in event_rows]
        root_hex, leaf_count, tree_version = integrity_merkle_batch(events)
        merkle_root = '0x' + root_hex
        try:
            receipt = configured_chain_client().anchor_root(body.batch_id, merkle_root)
        except BatchAlreadyAnchored as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except ChainUnavailable as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except ChainVerificationFailed as exc:
            raise HTTPException(status_code=502, detail=f'Anchor transaction failed independent verification: {exc}') from exc

        created_at = utc_now()
        try:
            with _db(db_path) as connection:
                connection.execute(
                    '''INSERT INTO blockchain_anchors
                       (batch_id, case_id, merkle_root, leaf_count, tree_version, chain_id,
                        contract_address, sender_address, tx_hash, block_number, block_hash,
                        anchored_at, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (receipt.batch_id, canonical_uuid, receipt.merkle_root, leaf_count, tree_version,
                     receipt.chain_id, receipt.contract_address, receipt.sender_address, receipt.tx_hash,
                     receipt.block_number, receipt.block_hash, receipt.anchored_at, created_at),
                )
        except sqlite3.IntegrityError as exc:
            raise HTTPException(status_code=409, detail='batch ID or transaction has already been recorded') from exc
        return {**receipt.as_dict(), 'case_id': canonical_uuid, 'leaf_count': leaf_count,
                'tree_version': tree_version, 'verification_status': 'verified', 'created_at': created_at}

    @app.get('/api/v1/cases/{case_id}/anchors')
    def list_case_anchors(case_id: str) -> list[dict[str, Any]]:
        try:
            canonical_uuid = str(uuid.UUID(case_id))
        except ValueError as exc:
            raise HTTPException(status_code=404, detail='case not found') from exc
        with _db(db_path) as connection:
            if connection.execute('SELECT 1 FROM cases WHERE id = ?', (canonical_uuid,)).fetchone() is None:
                raise HTTPException(status_code=404, detail='case not found')
            rows = connection.execute(
                '''SELECT batch_id, case_id, merkle_root, leaf_count, tree_version, chain_id,
                          contract_address, sender_address, tx_hash, block_number, block_hash,
                          anchored_at, created_at
                   FROM blockchain_anchors WHERE case_id = ? ORDER BY created_at DESC, batch_id ASC''',
                (canonical_uuid,),
            ).fetchall()
        return [{**dict(row), 'verification_status': 'recorded'} for row in rows]

    @app.get('/api/v1/anchors/{batch_id}')
    def get_anchor(batch_id: str) -> dict[str, Any]:
        with _db(db_path) as connection:
            row = connection.execute(
                '''SELECT batch_id, case_id, merkle_root, leaf_count, tree_version, chain_id,
                          contract_address, sender_address, tx_hash, block_number, block_hash,
                          anchored_at, created_at
                   FROM blockchain_anchors WHERE batch_id = ?''',
                (batch_id,),
            ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail='anchor not found')
        return {**dict(row), 'verification_status': 'recorded'}

    @app.get('/api/v1/anchors/{batch_id}/verify')
    def verify_anchor(batch_id: str) -> dict[str, Any]:
        with _db(db_path) as connection:
            row = connection.execute(
                '''SELECT batch_id, merkle_root, chain_id, contract_address, tx_hash, sender_address
                   FROM blockchain_anchors WHERE batch_id = ?''',
                (batch_id,),
            ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail='anchor not found')
        try:
            client = configured_chain_client()
            if client.contract_address != row['contract_address'].lower():
                raise ChainVerificationFailed('Configured EvidenceRegistry address differs from the recorded anchor.')
            receipt = client.verify_receipt(
                row['tx_hash'], row['batch_id'], row['merkle_root'],
                expected_sender=row['sender_address'], expected_chain_id=row['chain_id'],
            )
        except ChainUnavailable as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except ChainVerificationFailed as exc:
            raise HTTPException(status_code=409, detail=f'Anchor verification failed: {exc}') from exc
        return {**receipt.as_dict(), 'verification_status': 'verified'}

    @app.post('/api/v1/cases/{case_id}/evidence', status_code=201)
    def ingest_evidence(
        case_id: str,
        file: UploadFile = File(...),
        event: str = Form(...),
    ) -> dict[str, Any]:
        try:
            canonical_uuid = str(uuid.UUID(case_id))
        except ValueError as exc:
            raise HTTPException(status_code=404, detail='case not found') from exc
        with _db(db_path) as connection:
            if connection.execute('SELECT 1 FROM cases WHERE id = ?', (canonical_uuid,)).fetchone() is None:
                raise HTTPException(status_code=404, detail='case not found')

        raw_event = parse_event_json(event)
        try:
            source_event = normalize_source_event(raw_event)
        except NormalizationError as exc:
            raise HTTPException(status_code=422, detail=f'source event normalization failed: {exc}') from exc
        normalized, canonical_event, canonical_digest = canonicalize_with_existing_module(source_event.event)
        evidence_id = str(uuid.uuid4())
        event_record_id = str(uuid.uuid4())
        ingested_at = utc_now()
        temp_path: Path | None = None
        raw_hash = hashlib.sha256()
        byte_length = 0

        try:
            with tempfile.NamedTemporaryFile(prefix='ingest-', suffix='.part', dir=object_root, delete=False) as temporary:
                temp_path = Path(temporary.name)
                while True:
                    chunk = file.file.read(UPLOAD_CHUNK_BYTES)
                    if not chunk:
                        break
                    byte_length += len(chunk)
                    if byte_length > MAX_UPLOAD_BYTES:
                        raise HTTPException(status_code=413, detail='evidence file exceeds the upload limit')
                    raw_hash.update(chunk)
                    temporary.write(chunk)
                temporary.flush()
                os.fsync(temporary.fileno())

            streamed_digest = raw_hash.hexdigest()
            evidence_digest = integrity_sha256_file(temp_path)
            if streamed_digest != evidence_digest:
                raise HTTPException(status_code=503, detail='integrity hash implementations disagree')
            with _db(db_path) as connection:
                # Serialize uniqueness checking, blob installation, and metadata commit.
                # This prevents a concurrent failed insert from deleting a blob another
                # request is about to reference.
                connection.execute('BEGIN IMMEDIATE')
                if connection.execute(
                    'SELECT 1 FROM event_records WHERE case_id = ? AND event_id = ?',
                    (canonical_uuid, normalized['eventId']),
                ).fetchone() is not None:
                    raise HTTPException(status_code=409, detail='eventId already exists in this case')
                storage_key, _ = _install_blob(temp_path, object_root, evidence_digest)
                try:
                    connection.execute(
                        '''INSERT INTO evidence_objects
                           (id, case_id, original_filename, media_type, byte_length, sha256, storage_key, ingested_at)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                        (evidence_id, canonical_uuid, _safe_filename(file.filename), _media_type(file.content_type),
                         byte_length, evidence_digest, storage_key, ingested_at),
                    )
                    connection.execute(
                        '''INSERT INTO event_records
                           (id, case_id, evidence_id, event_id, source_id, occurred_at, event_type,
                            normalized_json, canonical_sha256)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                        (event_record_id, canonical_uuid, evidence_id, normalized['eventId'], normalized['sourceId'],
                         normalized['occurredAt'], normalized['eventType'], canonical_event.decode('utf-8'), canonical_digest),
                    )
                except sqlite3.IntegrityError as exc:
                    message = str(exc)
                    if 'event_records.case_id, event_records.event_id' in message:
                        raise HTTPException(status_code=409, detail='eventId already exists in this case') from exc
                    raise HTTPException(status_code=409, detail='duplicate evidence or event record') from exc
            return {
                'evidence_id': evidence_id,
                'event_record_id': event_record_id,
                'case_id': canonical_uuid,
                'filename': _safe_filename(file.filename),
                'byte_length': byte_length,
                'sha256': evidence_digest,
                'canonical_event_sha256': canonical_digest,
                'event': normalized,
                'ingested_at': ingested_at,
            }
        except Exception:
            # If SQLite fails after blob installation, an orphaned immutable
            # content-addressed object is safer than path-based cleanup that
            # could race with a replaced directory symlink.
            raise
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)
            file.file.close()

    @app.get('/api/v1/evidence/{evidence_id}/verify')
    def verify_evidence(evidence_id: str) -> dict[str, Any]:
        try:
            canonical_id = str(uuid.UUID(evidence_id))
        except ValueError as exc:
            raise HTTPException(status_code=404, detail='evidence not found') from exc
        with _db(db_path) as connection:
            row = connection.execute(
                'SELECT id, sha256, byte_length, storage_key FROM evidence_objects WHERE id = ?',
                (canonical_id,),
            ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail='evidence not found')

        digest = row['sha256']
        try:
            expected_key = _expected_storage_key(digest)
        except ValueError as exc:
            raise HTTPException(status_code=500, detail='stored evidence metadata is invalid') from exc
        if row['storage_key'] != expected_key:
            raise HTTPException(status_code=500, detail='stored evidence path is invalid')
        actual_digest, total, storage_reason = _hash_evidence_blob(object_root, expected_key)
        valid = storage_reason is None and actual_digest == digest and total == row['byte_length']
        checked_at = utc_now()
        return {
            'evidence_id': canonical_id,
            'valid': valid,
            'expected_sha256': digest,
            'actual_sha256': actual_digest,
            'expected_byte_length': row['byte_length'],
            'actual_byte_length': total,
            'reason': storage_reason or (None if valid else 'digest_or_length_mismatch'),
            'checked_at': checked_at,
        }

    @app.post('/api/v1/evidence/{evidence_id}/verify-candidate')
    def verify_evidence_candidate(evidence_id: str, file: UploadFile = File(...)) -> dict[str, Any]:
        """Compare a user-selected byte copy with recorded ingestion metadata without storing it."""
        try:
            canonical_id = str(uuid.UUID(evidence_id))
        except ValueError as exc:
            raise HTTPException(status_code=404, detail='evidence not found') from exc
        with _db(db_path) as connection:
            row = connection.execute('SELECT id, sha256, byte_length FROM evidence_objects WHERE id = ?', (canonical_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail='evidence not found')
        digest = hashlib.sha256()
        total = 0
        try:
            while True:
                chunk = file.file.read(UPLOAD_CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_UPLOAD_BYTES:
                    raise HTTPException(status_code=413, detail='candidate evidence exceeds the upload limit')
                digest.update(chunk)
        finally:
            file.file.close()
        actual = digest.hexdigest()
        valid = actual == row['sha256'] and total == row['byte_length']
        return {'evidence_id': canonical_id, 'valid': valid, 'expected_sha256': row['sha256'],
                'actual_sha256': actual, 'expected_byte_length': row['byte_length'], 'actual_byte_length': total,
                'failed_check': None if valid else 'candidate_original_sha256',
                'reason': 'candidate_matches_recorded_original' if valid else 'candidate_digest_or_length_mismatch',
                'checked_at': utc_now(), 'candidate_stored': False}

    def case_integrity_context(connection: sqlite3.Connection, case_id: str) -> tuple[list[sqlite3.Row], dict[str, Any]]:
        rows = connection.execute(
            '''SELECT event_id, normalized_json, canonical_sha256 FROM event_records
               WHERE case_id = ? ORDER BY event_id COLLATE BINARY''', (case_id,)
        ).fetchall()
        if not rows:
            raise HTTPException(status_code=409, detail='case has no normalized events to verify')
        if len(rows) > 4096:
            raise HTTPException(status_code=413, detail='verification batch exceeds the 4096-event limit')
        events = []
        for row in rows:
            events.append(verified_stored_event(row['normalized_json'], row['canonical_sha256'], row['event_id']))
        context = integrity_operation('--merkle-context', events)
        return rows, context

    @app.post('/api/v1/signing-keys', status_code=201)
    def register_signing_key(body: PublicKeyCreate) -> dict[str, Any]:
        try:
            der = base64.b64decode(body.public_key_der_base64, validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise HTTPException(status_code=422, detail='public_key_der_base64 must be valid base64') from exc
        if len(der) > 128:
            raise HTTPException(status_code=422, detail='public key DER is too large')
        key = integrity_operation('--validate-key', {'publicKeyDerBase64': body.public_key_der_base64})
        key_id = key.get('keyId')
        if not isinstance(key_id, str) or not SHA256_RE.fullmatch(key_id):
            raise HTTPException(status_code=503, detail='key validator returned invalid key metadata')
        registered_at = utc_now()
        with _db(db_path) as connection:
            existing = connection.execute('SELECT public_key_der FROM signing_keys WHERE key_id = ?', (key_id,)).fetchone()
            if existing is not None:
                if bytes(existing['public_key_der']) != der:
                    raise HTTPException(status_code=409, detail='key ID is already registered to different key bytes')
                raise HTTPException(status_code=409, detail='signing key is already registered')
            connection.execute('INSERT INTO signing_keys(key_id, public_key_der, status, registered_at) VALUES (?, ?, ?, ?)',
                               (key_id, der, 'active', registered_at))
        return {'key_id': key_id, 'status': 'active', 'registered_at': registered_at}

    @app.post('/api/v1/cases/{case_id}/verification/signature')
    def check_case_signature(case_id: str, body: SignatureCheckBody) -> dict[str, Any]:
        try:
            canonical_uuid = str(uuid.UUID(case_id))
        except ValueError as exc:
            raise HTTPException(status_code=404, detail='case not found') from exc
        with _db(db_path) as connection:
            if connection.execute('SELECT 1 FROM cases WHERE id = ?', (canonical_uuid,)).fetchone() is None:
                raise HTTPException(status_code=404, detail='case not found')
            rows, context = case_integrity_context(connection, canonical_uuid)
            registration_row = connection.execute('SELECT key_id, public_key_der, status FROM signing_keys WHERE key_id = ?', (body.key_id,)).fetchone()
            registration = None if registration_row is None else {
                'keyId': registration_row['key_id'],
                'publicKeyDerBase64': base64.b64encode(bytes(registration_row['public_key_der'])).decode('ascii'),
                'status': registration_row['status'],
            }
            signed_batch = {'version': 'cpx-signed-batch-v1', 'batchId': body.batch_id, 'keyId': body.key_id,
                            'treeVersion': context['treeVersion'], 'leafCount': context['leafCount'], 'rootHash': context['rootHash']}
            checked = integrity_operation('--verify-signature', {
                'batch': signed_batch, 'signatureHex': body.signature_hex,
                'registration': registration,
            })
            result = checked.get('result')
            if result not in {'valid', 'unknown_key', 'revoked_key', 'invalid_signature'}:
                raise HTTPException(status_code=503, detail='signature verifier returned an invalid result')
            reasons = {'valid': 'signature_valid', 'unknown_key': 'key_not_registered',
                       'revoked_key': 'signing_key_revoked', 'invalid_signature': 'signature_invalid_or_key_mismatch'}
            checked_at = utc_now()
            connection.execute(
                '''INSERT INTO signature_checks(id, case_id, batch_id, key_id, tree_version, leaf_count, root_hash, result, reason, checked_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (str(uuid.uuid4()), canonical_uuid, body.batch_id, body.key_id, context['treeVersion'], context['leafCount'],
                 context['rootHash'], result, reasons[result], checked_at),
            )
        return {'case_id': canonical_uuid, 'batch_id': body.batch_id, 'key_id': body.key_id,
                'root_hash': context['rootHash'], 'leaf_count': context['leafCount'], 'valid': result == 'valid',
                'result': result, 'failed_check': None if result == 'valid' else 'ed25519_signature',
                'reason': reasons[result], 'checked_at': checked_at}

    @app.get('/api/v1/cases/{case_id}/verification/context')
    def get_verification_context(case_id: str) -> dict[str, Any]:
        try:
            canonical_uuid = str(uuid.UUID(case_id))
        except ValueError as exc:
            raise HTTPException(status_code=404, detail='case not found') from exc
        with _db(db_path) as connection:
            case = connection.execute('SELECT id FROM cases WHERE id = ?', (canonical_uuid,)).fetchone()
            if case is None:
                raise HTTPException(status_code=404, detail='case not found')
            rows, context = case_integrity_context(connection, canonical_uuid)
        by_id = {event['eventId']: index for index, event in enumerate(context['events'])}
        proof_records = []
        for event_id, index in by_id.items():
            proof_records.append({'event_id': event_id, 'canonical_event_base64': context['canonicalEventBase64'][index],
                                  'canonical_sha256': hashlib.sha256(base64.b64decode(context['canonicalEventBase64'][index])).hexdigest(),
                                  'proof': context['proofs'][index]})
        return {'case_id': canonical_uuid, 'tree_version': context['treeVersion'], 'leaf_count': context['leafCount'],
                'root_hash': context['rootHash'], 'proofs': proof_records,
                'signature_payload_template': {'version': 'cpx-signed-batch-v1', 'batchId': '<batch-id>', 'keyId': '<registered-key-id>',
                                                'treeVersion': context['treeVersion'], 'leafCount': context['leafCount'], 'rootHash': context['rootHash']}}

    @app.post('/api/v1/cases/{case_id}/verification/proof')
    def check_case_proof(case_id: str, body: ProofCheckBody) -> dict[str, Any]:
        try:
            canonical_uuid = str(uuid.UUID(case_id))
        except ValueError as exc:
            raise HTTPException(status_code=404, detail='case not found') from exc
        with _db(db_path) as connection:
            if connection.execute('SELECT 1 FROM cases WHERE id = ?', (canonical_uuid,)).fetchone() is None:
                raise HTTPException(status_code=404, detail='case not found')
            rows, context = case_integrity_context(connection, canonical_uuid)
            event_index = next((index for index, event in enumerate(context['events']) if event.get('eventId') == body.event_id), None)
            if event_index is None:
                raise HTTPException(status_code=404, detail='normalized event not found in case')
            canonical_b64 = context['canonicalEventBase64'][event_index]
            proof_data = body.proof.model_dump(exclude_none=True)
            checked = integrity_operation('--verify-proof', {'canonicalEventBase64': canonical_b64,
                                                              'proof': proof_data, 'expectedRoot': body.expected_root})
            valid = checked.get('valid') is True
            reason = 'proof_valid' if valid else 'proof_malformed_or_root_mismatch'
            checked_at = utc_now()
            connection.execute(
                'INSERT INTO proof_checks(id, case_id, event_id, expected_root, valid, reason, proof_json, checked_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                (str(uuid.uuid4()), canonical_uuid, body.event_id, body.expected_root, int(valid), reason,
                 json.dumps(proof_data, ensure_ascii=True, separators=(',', ':'), sort_keys=True), checked_at),
            )
        return {'case_id': canonical_uuid, 'event_id': body.event_id, 'expected_root': body.expected_root,
                'valid': valid, 'failed_check': None if valid else 'merkle_inclusion_proof', 'reason': reason, 'checked_at': checked_at}

    @app.put('/api/v1/cases/{case_id}/expected-events')
    def set_expected_events(case_id: str, body: ManifestBody) -> dict[str, Any]:
        try:
            canonical_uuid = str(uuid.UUID(case_id))
        except ValueError as exc:
            raise HTTPException(status_code=404, detail='case not found') from exc
        manifest_id = str(uuid.uuid4())
        updated_at = utc_now()
        ids = sorted(body.expected_event_ids, key=lambda item: item.encode('utf-8'))
        with _db(db_path) as connection:
            if connection.execute('SELECT 1 FROM cases WHERE id = ?', (canonical_uuid,)).fetchone() is None:
                raise HTTPException(status_code=404, detail='case not found')
            connection.execute('''INSERT INTO expected_event_manifests(case_id, expected_event_ids_json, manifest_id, updated_at)
                                  VALUES (?, ?, ?, ?) ON CONFLICT(case_id) DO UPDATE SET expected_event_ids_json=excluded.expected_event_ids_json,
                                  manifest_id=excluded.manifest_id, updated_at=excluded.updated_at''',
                               (canonical_uuid, json.dumps(ids, ensure_ascii=False, separators=(',', ':')), manifest_id, updated_at))
        return {'case_id': canonical_uuid, 'manifest_id': manifest_id, 'expected_event_ids': ids, 'updated_at': updated_at}

    @app.get('/api/v1/cases/{case_id}/completeness')
    def case_completeness(case_id: str) -> dict[str, Any]:
        try:
            canonical_uuid = str(uuid.UUID(case_id))
        except ValueError as exc:
            raise HTTPException(status_code=404, detail='case not found') from exc
        with _db(db_path) as connection:
            if connection.execute('SELECT 1 FROM cases WHERE id = ?', (canonical_uuid,)).fetchone() is None:
                raise HTTPException(status_code=404, detail='case not found')
            manifest = connection.execute('SELECT manifest_id, expected_event_ids_json, updated_at FROM expected_event_manifests WHERE case_id = ?', (canonical_uuid,)).fetchone()
            observed = [row[0] for row in connection.execute('SELECT event_id FROM event_records WHERE case_id = ? ORDER BY event_id COLLATE BINARY', (canonical_uuid,))]
        if manifest is None:
            return {'case_id': canonical_uuid, 'manifest_present': False, 'complete': None, 'missing_event_ids': [],
                    'unexpected_event_ids': [], 'reason': 'expected_event_manifest_not_configured'}
        expected = json.loads(manifest['expected_event_ids_json'])
        missing = sorted(set(expected) - set(observed), key=lambda item: item.encode('utf-8'))
        unexpected = sorted(set(observed) - set(expected), key=lambda item: item.encode('utf-8'))
        return {'case_id': canonical_uuid, 'manifest_present': True, 'manifest_id': manifest['manifest_id'],
                'manifest_updated_at': manifest['updated_at'], 'expected_count': len(expected), 'observed_count': len(observed),
                'complete': not missing, 'missing_event_ids': missing, 'unexpected_event_ids': unexpected,
                'reason': None if not missing else 'expected_events_missing'}

    def build_forensic_report(case_id: str) -> dict[str, Any]:
        try:
            canonical_uuid = str(uuid.UUID(case_id))
        except ValueError as exc:
            raise HTTPException(status_code=404, detail='case not found') from exc
        with _db(db_path) as connection:
            case = connection.execute('SELECT * FROM cases WHERE id = ?', (canonical_uuid,)).fetchone()
            if case is None:
                raise HTTPException(status_code=404, detail='case not found')
            evidence_rows = connection.execute(
                '''SELECT e.*, r.event_id, r.source_id, r.occurred_at, r.event_type, r.normalized_json, r.canonical_sha256
                   FROM evidence_objects e JOIN event_records r ON r.evidence_id=e.id AND r.case_id=e.case_id
                   WHERE e.case_id=? ORDER BY e.id COLLATE BINARY''', (canonical_uuid,)
            ).fetchall()
            anchors = [dict(row) for row in connection.execute('SELECT * FROM blockchain_anchors WHERE case_id=? ORDER BY created_at, batch_id', (canonical_uuid,))]
            correlations = [dict(row) for row in connection.execute('SELECT * FROM correlations WHERE case_id=? ORDER BY start_at, id', (canonical_uuid,))]
            correlation_refs = [dict(row) for row in connection.execute(
                '''SELECT ce.correlation_id, ce.ordinal, r.event_id, e.id AS evidence_id, r.canonical_sha256
                   FROM correlation_events ce JOIN correlations c ON c.id=ce.correlation_id
                   JOIN event_records r ON r.id=ce.event_record_id JOIN evidence_objects e ON e.id=r.evidence_id
                   WHERE c.case_id=? ORDER BY ce.correlation_id, ce.ordinal''', (canonical_uuid,))]
            signatures = [dict(row) for row in connection.execute('SELECT batch_id, key_id, tree_version, leaf_count, root_hash, result, reason, checked_at FROM signature_checks WHERE case_id=? ORDER BY checked_at, id', (canonical_uuid,))]
            proofs = [dict(row) for row in connection.execute('SELECT event_id, expected_root, valid, reason, proof_json, checked_at FROM proof_checks WHERE case_id=? ORDER BY checked_at, id', (canonical_uuid,))]
            investigations = [investigation_response(connection, row) for row in connection.execute(
                'SELECT * FROM investigations WHERE case_id=? ORDER BY created_at, id', (canonical_uuid,))]
            manifest = connection.execute('SELECT manifest_id, expected_event_ids_json, updated_at FROM expected_event_manifests WHERE case_id=?', (canonical_uuid,)).fetchone()
        evidence_records = []
        integrity_events = []
        for row in evidence_rows:
            item = dict(row)
            try:
                expected_key = _expected_storage_key(item['sha256'])
            except (TypeError, ValueError):
                expected_key = None
            if expected_key is None or item['storage_key'] != expected_key:
                byte_integrity = {'valid': False, 'actual_sha256': None, 'actual_byte_length': None,
                                  'reason': 'stored_object_path_invalid'}
            else:
                actual_digest, length, storage_reason = _hash_evidence_blob(object_root, expected_key)
                valid = storage_reason is None and actual_digest == item['sha256'] and length == item['byte_length']
                byte_integrity = {'valid': valid, 'actual_sha256': actual_digest, 'actual_byte_length': length,
                                  'reason': storage_reason or (None if valid else 'digest_or_length_mismatch')}
            event = verified_stored_event(item['normalized_json'], item['canonical_sha256'], item['event_id'])
            canonical_digest = item['canonical_sha256']
            integrity_events.append(event)
            evidence_records.append({'evidence_id': item['id'], 'filename': item['original_filename'], 'media_type': item['media_type'],
                'byte_length': item['byte_length'], 'sha256': item['sha256'], 'byte_integrity_check': byte_integrity,
                'ingested_at': item['ingested_at'], 'event_id': item['event_id'], 'event': event,
                'canonical_event_sha256': canonical_digest})
        event_records = integrity_events
        merkle = integrity_operation('--merkle-context', event_records) if event_records else None
        if manifest:
            expected = json.loads(manifest['expected_event_ids_json'])
            observed_ids = {item['event_id'] for item in evidence_records}
            missing = sorted(set(expected) - observed_ids)
            completeness = {'manifest_id': manifest['manifest_id'], 'manifest_updated_at': manifest['updated_at'],
                'expected_count': len(expected), 'observed_count': len(observed_ids), 'complete': not missing,
                'missing_event_ids': missing, 'unexpected_event_ids': sorted(observed_ids - set(expected)),
                'reason': None if not missing else 'expected_events_missing'}
        else:
            completeness = {'manifest_present': False, 'complete': None, 'missing_event_ids': [],
                            'reason': 'expected_event_manifest_not_configured'}
        signature_summary = [{'batch_id': item['batch_id'], 'key_id': item['key_id'], 'tree_version': item['tree_version'],
                              'leaf_count': item['leaf_count'], 'root_hash': item['root_hash'], 'result': item['result'],
                              'reason': item['reason'], 'checked_at': item['checked_at']} for item in signatures]
        proof_summary = []
        for item in proofs:
            proof_json = json.loads(item['proof_json'])
            proof_summary.append({'event_id': item['event_id'], 'expected_root': item['expected_root'], 'valid': bool(item['valid']),
                                  'reason': item['reason'], 'proof': proof_json, 'checked_at': item['checked_at']})
        refs_by_correlation: dict[str, list[dict[str, Any]]] = {}
        for ref in correlation_refs:
            refs_by_correlation.setdefault(ref['correlation_id'], []).append({
                'ordinal': ref['ordinal'], 'event_id': ref['event_id'], 'evidence_id': ref['evidence_id'],
                'canonical_event_sha256': ref['canonical_sha256'],
            })
        correlation_summary = [{'id': item['id'], 'rule_id': item['rule_id'], 'rule_version': item['rule_version'],
                                'window_seconds': item['window_seconds'], 'matched_entities': json.loads(item['matched_entities_json']),
                                'explanation': item['explanation'], 'start_at': item['start_at'], 'end_at': item['end_at'],
                                'source_event_references': refs_by_correlation.get(item['id'], []),
                                'created_at': item['created_at']} for item in correlations]
        return {'report_version': 'chainproof-forensic-report-v1', 'generated_at': utc_now(),
            'case': {'id': case['id'], 'name': case['name'], 'created_at': case['created_at']},
            'evidence': evidence_records,
            'merkle': None if merkle is None else {'tree_version': merkle['treeVersion'], 'leaf_count': merkle['leafCount'],
                'root_hash': merkle['rootHash'], 'inclusion_proofs': [{'event_id': merkle['events'][i]['eventId'],
                'canonical_event_base64': merkle['canonicalEventBase64'][i], 'proof': merkle['proofs'][i]} for i in range(len(merkle['events']))]},
            'signature_checks': signature_summary, 'proof_checks': proof_summary,
            'blockchain_transaction_references': anchors, 'correlation_rules': correlation_summary,
            'investigations': investigations, 'completeness': completeness,
            'verification_limitations': ['Byte-integrity checks compare currently stored original bytes with the recorded ingestion digest; a passing result does not prove source-log truth.',
                'Normalized event records are derived representations and do not establish that the source emitted truthful or complete logs.',
                'Merkle inclusion proofs establish membership under the computed root only; roots are not represented as blockchain-anchored unless a transaction reference is recorded.',
                'Blockchain entries in this report are stored transaction metadata; this export does not independently re-query the chain.',
                'Investigations are analyst-authored organization records; referenced correlations are candidate relationships and do not establish causation.',
                'Completeness is assessable only against an explicitly supplied expected-event manifest; a missing manifest means completeness is unknown.']}

    @app.get('/api/v1/cases/{case_id}/reports/forensic.json')
    def forensic_json_report(case_id: str) -> Any:
        from fastapi.responses import JSONResponse
        report = build_forensic_report(case_id)
        return JSONResponse(report, headers={'Content-Disposition': f'attachment; filename="chainproof-{report["case"]["id"]}-forensic.json"'})

    @app.get('/api/v1/cases/{case_id}/reports/forensic.html')
    def forensic_html_report(case_id: str) -> Any:
        from fastapi.responses import HTMLResponse
        from html import escape
        report = build_forensic_report(case_id)
        serialized = json.dumps(report, ensure_ascii=False, indent=2)
        safe = escape(serialized)
        title = escape(str(report['case']['name']))
        document = f'<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Forensic report — {title}</title><style>body{{font:15px/1.55 system-ui,sans-serif;background:#111820;color:#e7edf2;margin:0;padding:32px}}main{{max-width:1100px;margin:auto}}h1{{font-size:24px}}p{{color:#aebcc8}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#18232d;border:1px solid #344653;border-radius:6px;padding:20px}}@media print{{body{{background:#fff;color:#111}}pre{{border:1px solid #777;background:#fff}}}}</style><main><h1>ChainProof X forensic report</h1><p>Case: {title} · Generated {escape(report["generated_at"])}</p><p>Structured report data follows. Verification limitations are included in the report.</p><pre>{safe}</pre></main></html>'
        return HTMLResponse(document, headers={'Content-Disposition': f'attachment; filename="chainproof-{report["case"]["id"]}-forensic.html"'})

    return app


app = create_app()
