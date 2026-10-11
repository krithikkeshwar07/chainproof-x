# ChainProof X backend slice

## Run locally

Install Python dependencies with `python -m pip install -r requirements.txt`, install Node.js 22.6 or newer, then start the local API:

```sh
set -a
. ./.env
set +a
uvicorn backend.app:app --host 127.0.0.1 --port 8000
```

Run this from the project root after creating the ignored `.env` as described in the main README. Both distinct API tokens are required; without them the API fails closed with HTTP 503 on data routes. The API creates `data/chainproof.sqlite3` and content-addressed originals under `data/evidence/` by default. Override these locations with `CHAINPROOF_DB` and `CHAINPROOF_EVIDENCE_DIR`. Set `CHAINPROOF_NODE` if the Node executable is not on `PATH`.

## Endpoints

- `POST /api/v1/cases` — JSON body `{"name":"..."}`; returns the generated case ID.
- `POST /api/v1/cases/{case_id}/evidence` — multipart fields `file` (original bytes) and `event` (a JSON event object); stores the exact original file separately from its normalized event.
- `GET /api/v1/evidence/{evidence_id}/verify` — recomputes the original file SHA-256 and byte length from storage and compares them with SQLite metadata.
- `POST /api/v1/evidence/{evidence_id}/verify-candidate` — hashes a user-selected candidate copy in memory and compares it with recorded metadata without storing or replacing either file.
- `POST /api/v1/signing-keys` — registers an Ed25519 public SPKI DER key (base64); returns its content-derived key ID. Private signing keys are never accepted.
- `GET /api/v1/cases/{case_id}/verification/context` — computes the current normalized-event Merkle root, canonical event bytes, and inclusion proofs.
- `POST /api/v1/cases/{case_id}/verification/signature` — verifies a supplied signature over the exact `cpx-signed-batch-v1` payload using a registered key and this case's currently computed root/count.
- `POST /api/v1/cases/{case_id}/verification/proof` — verifies a caller-supplied proof against the stored canonical event and supplied expected root; malformed or wrong-root proofs return an explicit failed check and reason.
- `PUT /api/v1/cases/{case_id}/expected-events` — stores the expected event ID manifest; duplicate or malformed IDs are rejected.
- `GET /api/v1/cases/{case_id}/completeness` — compares the manifest with observed normalized event IDs. Without a manifest, completeness is unknown.
- `GET /api/v1/cases/{case_id}/reports/forensic.json` and `/reports/forensic.html` — download a point-in-time case report with fresh evidence byte checks, event hashes, Merkle proofs, recorded signature/proof results, stored transaction references, rule correlations, completeness, timestamps, and limitations.
- `POST /api/v1/cases/{case_id}/anchors` — JSON body `{"batch_id":"0x<64 lowercase hex characters>"}`; builds a Merkle tree from that case's current normalized events, submits its root to the local contract, independently verifies the receipt and contract state, then stores the verified transaction metadata.
- `GET /api/v1/cases/{case_id}/anchors` — lists verified anchors recorded for a case.
- `GET /api/v1/anchors/{batch_id}` — retrieves recorded transaction metadata.
- `GET /api/v1/anchors/{batch_id}/verify` — independently rechecks the recorded chain ID, receipt, contract address, event and committed root against the local node.
- `POST /api/v1/cases/{case_id}/organizations` — explicitly associates one organization metadata record with a case; organizations are not inferred from evidence.
- `POST /api/v1/cases/{case_id}/correlations/recompute` — recomputes the versioned deterministic cross-source relationship candidates over ingested normalized source events.
- `GET /api/v1/cases/{case_id}/correlations` — returns stored candidates, rule explanations, source-event references, and evidence IDs.
- `GET /api/v1/cases/{case_id}/trust-graph` — returns actual case, organization, entity, evidence, event, and correlation-incident nodes with relationship explanations.
- `GET /health` — liveness response.
- `GET /api/v1/session` — validates the supplied bearer token and returns its `viewer` or `analyst` role.

The event form field is canonicalized by the existing TypeScript integrity module via a small Node bridge. The original evidence is never parsed or rewritten. SQLite stores only its digest, size, metadata, and content-addressed storage key; normalized event JSON is stored in the distinct `event_records` table. Anchor roots are computed by that same integrity module using its documented deterministic ordering and domain-separated SHA-256 Merkle format.

The strict synthetic Windows, Linux audit, and network adapters, correlation rule/window, failure limits, and graph semantics are documented in [`docs/correlation-rules.md`](../docs/correlation-rules.md). Correlations are candidate relationships and do not attest to log truth, completeness, causation, or a common actor.

## Verification and report scope

The verification endpoints call the shared TypeScript integrity implementation. Public keys are validated as Ed25519 SPKI DER; a key ID is SHA-256 of its raw 32-byte public key. A batch signature covers `ChainProofX-SignedBatch-v1\0` followed by compact UTF-8 JSON in the fixed field order `version`, `batchId`, `keyId`, `treeVersion`, `leafCount`, `rootHash`. The private key must sign outside this service. Public-key registration is not identity proof or a trust-authority assertion.

Proof records and signature-check outcomes are retained as audit records. The root and count are recomputed from current event records on each request, so later ingestion changes the signing payload. The HTML report escapes all interpolated data and includes structured report JSON for review. JSON/HTML exports list blockchain transaction metadata already stored in SQLite; they do not independently re-query the chain. A successful digest, signature, proof, or anchor check establishes only its stated cryptographic relationship. It cannot establish that original source logs are true. Completeness is measurable only against an explicit manifest; even a complete match cannot establish that the manifest itself is complete.

## Local Hardhat anchoring

Start the local chain and deploy the registry in separate terminals:

```sh
npm run chain:node
npm run chain:deploy
```

Deployment metadata is written under `data/hardhat-deployment.json` and is intentionally ignored by Git. The deployment command uses exclusive file creation and refuses to overwrite existing metadata before submitting a deployment. The combined local launcher checks that the chain, API, and frontend ports and authentication configuration are valid before starting; it refuses existing deployment metadata or a database with stored anchors before starting a new ephemeral chain. Choose fresh isolated data paths for a new chain; the database cannot recover prior Hardhat history. The backend uses `CHAINPROOF_RPC_URL` (default `http://127.0.0.1:8545`), `CHAINPROOF_CHAIN_ID` and `CHAINPROOF_CONTRACT_ADDRESS` when set, or the chain ID and address from `CHAINPROOF_DEPLOYMENT_FILE` (default `data/hardhat-deployment.json`). `CHAINPROOF_ANCHOR_ACCOUNT` may select an unlocked Hardhat account; otherwise the first account returned by `eth_accounts` is used. No private key is read or stored. Anchoring is restricted to loopback RPC endpoints and is only intended for local development.

All `/api/v1` endpoints require `Authorization: Bearer <token>`. `CPX_API_VIEWER_TOKEN` may only read; `CPX_API_ANALYST_TOKEN` may read and write. Both must be independently generated high-entropy strings of at least 32 random bytes, are kept outside the database, and are compared using SHA-256 digests and constant-time comparison. `/health` is intentionally public and exposes only liveness and workspace mode. This shared-token model does not provide per-user identity, SSO, session expiry, or tenant isolation; use an identity-aware gateway and a reviewed authorization design before network exposure.

Each request anchors all normalized events currently recorded for its case. The caller supplies a unique lowercase bytes32 batch ID. The API computes the root itself; it does not accept a caller-supplied root. A database row is recorded only after the RPC receipt, successful status, transaction target/calldata, chain ID, emitted event and contract storage at the receipt block all agree. This proves the configured local chain recorded that root; it does not prove that source logs are truthful or complete.

Run API tests with `python -m pytest -q`. Run integrity-module tests with `npm test`.

This slice does not implement user identity, SSO, an external identity-backed signing-key trust authority, signing-key revocation, or a public blockchain trust anchor. The local Hardhat chain is ephemeral. Bind only to loopback; bearer tokens do not make a public deployment production-secure.
