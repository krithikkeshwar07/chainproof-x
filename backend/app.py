from __future__ import annotations

import hashlib
import base64
import json
import os
import re
import sqlite3
import subprocess
import tempfile
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterator

from fastapi import FastAPI, File, Form, HTTPException, Query, UploadFile
from pydantic import BaseModel, ConfigDict, Field, field_validator
from starlette.types import ASGIApp, Message, Receive, Scope, Send


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = PROJECT_ROOT / 'backend' / 'schema.sql'
INTEGRITY_CLI = PROJECT_ROOT / 'src' / 'integrity_cli.ts'
MAX_UPLOAD_BYTES = 16 * 1024 * 1024
MAX_INGEST_REQUEST_BYTES = MAX_UPLOAD_BYTES + 128 * 1024
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


def _connect(database_path: Path) -> sqlite3.Connection:
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
        if (scope['type'] != 'http' or scope.get('method') != 'POST'
                or not scope.get('path', '').endswith('/evidence')):
            await self.app(scope, receive, send)
            return

        headers = {key.lower(): value for key, value in scope.get('headers', [])}
        declared = headers.get(b'content-length')
        if declared is not None:
            try:
                declared_size = int(declared)
            except ValueError:
                await self._send_error(send, 400, 'invalid Content-Length')
                return
            if declared_size < 0 or declared_size > self.max_bytes:
                await self._send_error(send, 413, 'evidence request exceeds the upload limit')
                return

        consumed = 0
        over_limit = False
        response_started = False

        async def bounded_receive() -> Message:
            nonlocal consumed, over_limit
            message = await receive()
            if message['type'] == 'http.request':
                consumed += len(message.get('body', b''))
                if consumed > self.max_bytes:
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
                body = b'{"detail":"evidence request exceeds the upload limit"}'
                await send({
                    'type': 'http.response.start', 'status': 413,
                    'headers': [(b'content-type', b'application/json'), (b'content-length', str(len(body)).encode())],
                })
            elif message['type'] == 'http.response.body':
                body = b'{"detail":"evidence request exceeds the upload limit"}' if not message.get('more_body', False) else b''
                await send({'type': 'http.response.body', 'body': body, 'more_body': message.get('more_body', False)})

        await self.app(scope, bounded_receive, bounded_send)
        if over_limit and not response_started:
            await self._send_error(send, 413, 'evidence request exceeds the upload limit')

    @staticmethod
    async def _send_error(send: Send, status: int, detail: str) -> None:
        body = json.dumps({'detail': detail}, separators=(',', ':')).encode()
        await send({
            'type': 'http.response.start', 'status': status,
            'headers': [(b'content-type', b'application/json'), (b'content-length', str(len(body)).encode())],
        })
        await send({'type': 'http.response.body', 'body': body, 'more_body': False})


def _expected_storage_key(digest: str) -> str:
    if not SHA256_RE.fullmatch(digest):
        raise ValueError('invalid stored digest')
    return f'{digest[:2]}/{digest}.bin'


def _install_blob(temp_path: Path, storage_root: Path, digest: str) -> tuple[str, bool]:
    storage_key = _expected_storage_key(digest)
    destination = storage_root / storage_key
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        # Hard-link installation is atomic and never overwrites an existing object.
        os.link(temp_path, destination)
        return storage_key, True
    except FileExistsError:
        existing_digest = hashlib.sha256()
        with destination.open('rb') as existing:
            for chunk in iter(lambda: existing.read(UPLOAD_CHUNK_BYTES), b''):
                existing_digest.update(chunk)
        if existing_digest.hexdigest() != digest or destination.stat().st_size != temp_path.stat().st_size:
            raise HTTPException(status_code=500, detail='content-addressed evidence object is inconsistent')
        return storage_key, False
    except OSError as exc:
        raise HTTPException(status_code=500, detail='evidence object could not be stored') from exc


def create_app(
    database_path: str | Path | None = None,
    evidence_root: str | Path | None = None,
) -> FastAPI:
    db_path = Path(database_path or os.environ.get('CHAINPROOF_DB', PROJECT_ROOT / 'data' / 'chainproof.sqlite3')).resolve()
    object_root = Path(evidence_root or os.environ.get('CHAINPROOF_EVIDENCE_DIR', PROJECT_ROOT / 'data' / 'evidence')).resolve()
    object_root.mkdir(parents=True, exist_ok=True)
    initialize_database(db_path)

    app = FastAPI(title='ChainProof X API', version='0.1.0')
    app.add_middleware(IngestBodyLimitMiddleware, max_bytes=MAX_INGEST_REQUEST_BYTES)
    app.state.database_path = db_path
    app.state.evidence_root = object_root


    @app.get('/health')
    def health() -> dict[str, str]:
        return {'status': 'ok'}

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
            item['event'] = json.loads(item.pop('normalized_json'))
            items.append(item)
        return {'items': items, 'total': total, 'limit': limit, 'offset': offset}

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
        normalized, canonical_event, canonical_digest = canonicalize_with_existing_module(raw_event)
        evidence_id = str(uuid.uuid4())
        event_record_id = str(uuid.uuid4())
        ingested_at = utc_now()
        temp_path: Path | None = None
        installed_path: Path | None = None
        newly_installed = False
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
                storage_key, newly_installed = _install_blob(temp_path, object_root, evidence_digest)
                installed_path = object_root / storage_key
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
            if newly_installed and installed_path is not None:
                try:
                    installed_path.unlink(missing_ok=True)
                except OSError:
                    pass
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
        path = object_root / expected_key
        total = 0
        try:
            with path.open('rb') as source:
                for chunk in iter(lambda: source.read(UPLOAD_CHUNK_BYTES), b''):
                    total += len(chunk)
                    if total > MAX_UPLOAD_BYTES:
                        return {'evidence_id': canonical_id, 'valid': False, 'reason': 'stored_object_exceeds_limit'}
        except FileNotFoundError:
            return {'evidence_id': canonical_id, 'valid': False, 'reason': 'stored_object_missing'}
        actual_digest = integrity_sha256_file(path)
        valid = actual_digest == digest and total == row['byte_length']
        return {
            'evidence_id': canonical_id,
            'valid': valid,
            'expected_sha256': digest,
            'actual_sha256': actual_digest,
            'expected_byte_length': row['byte_length'],
            'actual_byte_length': total,
            'reason': None if valid else 'digest_or_length_mismatch',
        }

    return app


app = create_app()
