# ChainProof X backend slice

## Run locally

Install Python dependencies with `python -m pip install -r requirements.txt`, install Node.js 22.6 or newer, then start the local API:

```sh
uvicorn backend.app:app --host 127.0.0.1 --port 8000
```

The API creates `data/chainproof.sqlite3` and content-addressed originals under `data/evidence/` by default. Override these locations with `CHAINPROOF_DB` and `CHAINPROOF_EVIDENCE_DIR`. Set `CHAINPROOF_NODE` if the Node executable is not on `PATH`.

## Endpoints

- `POST /api/v1/cases` — JSON body `{"name":"..."}`; returns the generated case ID.
- `POST /api/v1/cases/{case_id}/evidence` — multipart fields `file` (original bytes) and `event` (a JSON event object); stores the exact original file separately from its normalized event.
- `GET /api/v1/evidence/{evidence_id}/verify` — recomputes the original file SHA-256 and byte length from storage and compares them with SQLite metadata.
- `GET /health` — liveness response.

The event form field is canonicalized by the existing TypeScript integrity module via a small Node bridge. The original evidence is never parsed or rewritten. SQLite stores only its digest, size, metadata, and content-addressed storage key; normalized event JSON is stored in the distinct `event_records` table.

Run API tests with `python -m pytest -q`. Run integrity-module tests with `npm test`.

This slice does not implement authentication, authorization, audit history, manifests, reports, UI, or blockchain anchoring. Bind only to loopback unless access controls are added.
