# ChainProof X

ChainProof X is a local digital-forensics evidence integrity workspace. It preserves original evidence bytes, records normalized events separately, and exposes cryptographic verification and investigation workflows. A passing integrity check establishes consistency with recorded bytes and cryptographic commitments; it does **not** establish that source logs are truthful or complete.

## Requirements

- Node.js 22.6 or newer
- Python 3.10 or newer (Python 3.12 recommended)
- npm

## One-command local setup

From the project directory:

```sh
npm ci
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
cp .env.example .env
python3 -c 'import secrets; print("CPX_API_VIEWER_TOKEN=" + secrets.token_urlsafe(32))'
python3 -c 'import secrets; print("CPX_API_ANALYST_TOKEN=" + secrets.token_urlsafe(32))'
# Paste both outputs into .env before starting the stack.
npm run dev:stack
```

On Windows PowerShell, create the environment with `py -3 -m venv .venv`, install using `.venv\Scripts\python.exe -m pip install -r requirements.txt`, and copy configuration with `Copy-Item .env.example .env`. The stack launcher detects the Windows environment interpreter automatically.

`npm run dev:stack` starts the normal local Hardhat JSON-RPC node, deploys the actual `EvidenceRegistry` contract to that node, starts FastAPI, and starts Vite after checking each service is ready. It prints clear startup errors and stops child processes if a required service exits. Press Ctrl+C once to stop the stack. For the separate synthetic presentation environment, use the isolated competition-demo workflow below instead.

- Dashboard: <http://127.0.0.1:5173>
- API documentation: <http://127.0.0.1:8000/docs>
- Local Hardhat JSON-RPC: <http://127.0.0.1:8545>

Keep these development services bound to loopback. Every `/api/v1` route requires a configured bearer token: viewer tokens can read; analyst tokens can change case state. `/health` remains public and reveals only liveness/workspace mode. The browser holds the token in memory only; reload or sign-out clears it. The local chain is ephemeral and resets when restarted. The launcher checks ports and auth configuration before starting services, refuses existing deployment metadata, and refuses a database containing anchor references; it will not overwrite them or label old transactions as present on a fresh chain. Select new isolated database, evidence, and deployment paths when rehearsing against a new chain.

## Configuration and data

`.env.example` documents local settings. The launcher and seed commands load `.env` without overriding variables already set in the shell. Generate two independent tokens using Python's `secrets.token_urlsafe(32)`, store them as `CPX_API_VIEWER_TOKEN` and `CPX_API_ANALYST_TOKEN`, and do not commit `.env`. The server stores only SHA-256 token digests in process memory and compares them in constant time; credentials are not stored in SQLite or logged. `CHAINPROOF_DB` and `CHAINPROOF_EVIDENCE_DIR` default to ignored `data/` paths. `CHAINPROOF_RPC_URL` and `CHAINPROOF_CHAIN_ID` describe the local chain; the bundled launcher starts Hardhat on port 8545 and expects chain ID 31337. Vite proxies API calls to FastAPI, so leave `VITE_API_BASE_URL` empty for local development. Set `PYTHON` only if you need a non-default Python interpreter.

If an earlier local run left deployment metadata or stored anchor references, `npm run dev:stack` deliberately refuses to create a fresh chain on top of them. Use new isolated paths supplied through `CHAINPROOF_DB`, `CHAINPROOF_EVIDENCE_DIR`, and `CHAINPROOF_DEPLOYMENT_FILE`; do not remove or rename the existing files to bypass the guard.

The UI fetches its cases, evidence, correlations, and ledger from the API. If a service is unavailable, it displays loading/error/unavailable states and retry actions; it does not substitute fabricated metrics or transaction details. Blockchain records appear only after a real local contract transaction and verification.

## Isolated competition demo

The competition demo has a separate SQLite database, evidence directory, deployment metadata, and Hardhat node. It runs on frontend port 5174, API port 8100, and chain port 8546. Its database is `data/demo/chainproof.sqlite3`; it cannot seed into the normal workspace. The **Competition demo** navigation entry only appears in this mode.

For a repeatable fresh scenario, make sure no demo stack is running, then run:

```sh
npm run demo:reset
npm run demo:stack
```

In a second terminal:

```sh
npm run demo:seed
```

Open <http://127.0.0.1:5174>, select **DEMO · ChainProof X synthetic investigation**, and choose **Competition demo**. Follow its evidence ingestion/review, Verification Lab, local anchor and receipt check, Trust Graph, and JSON/HTML export actions. The seed uses stable synthetic event IDs and timestamps. It makes real API ingestion and correlation requests, but does not pre-create signature results or a blockchain transaction. Perform verification and anchoring from the UI to create those real results; the walkthrough reports only checks and transactions returned by the API. Report download actions are not persisted as a completion flag.

`npm run demo:reset` removes only `data/demo/` and refuses to run while its API is listening on port 8100. It checks for symbolic links before deleting. It never removes `data/` or the normal workspace database/evidence objects. Restart the stack after reset so its in-memory local chain is fresh. Demo data remains generated local state under ignored `data/` and is not committed.

Do not run the demo seeder against `npm run dev:stack`. The seeder checks the API's `competition-demo` health mode and rejects other endpoints. The reset command is scoped to the fixed ignored `data/demo/` directory and refuses to operate if the demo API port is active.

## Isolated competition rehearsal

Use this rehearsal when existing local or `data/demo/` records and anchors must remain untouched. Its scripts have separate data paths and ports; they refuse occupied services and never call `demo:reset`, `demo:seed`, `demo:stack`, or the combined `dev:stack` launcher. Its default persistent data root is a per-user directory outside the project workspace; it contains its own `chainproof.sqlite3`, `evidence/`, and `hardhat-deployment.json`.

Start these commands from the project directory in separate terminals, in order:

```sh
# Terminal 1: start the new, loopback-only rehearsal chain and leave it running.
npm run rehearsal:chain

# Terminal 2: deploy exactly once to that chain; refuses if this rehearsal already has data/metadata.
npm run rehearsal:deploy

# Terminal 3: start FastAPI and Vite against the rehearsal paths and the already-running chain.
npm run rehearsal:app

# Terminal 4: run once, after the rehearsal API is ready and the database is empty.
npm run rehearsal:seed
```

Open <http://127.0.0.1:5184>, select **DEMO · ChainProof X competition rehearsal**, and use Verification Lab and the Blockchain Ledger. On the Ledger, choose **Anchor current events**, then **Verify receipt**. The API returns a transaction hash only after a real transaction has been mined and independently checked against chain ID 31337, deployed contract code, its receipt, the emitted anchor event, and committed Merkle root. The existing anchor in `data/demo/` is not copied into this database; the existing Ledger continues to show its old metadata as `recorded` while its original RPC is unavailable.

`rehearsal:seed` is guarded: it accepts only the loopback API on 8110 reporting workspace mode `competition-rehearsal`, and refuses to seed if the case list is nonempty. It never deletes or resets records. If it fails partway through, preserve the partial case and inspect it; do not reset or rerun seeding. The rehearsal startup does not seed or deploy. Restarting the application uses the same external data paths and does not repeat either operation.

To select a different fresh rehearsal after the original chain has been stopped, set `CPX_REHEARSAL_ROOT` to a **new, unused single directory** under the per-user rehearsal parent in every rehearsal terminal. This example derives that parent from the project configuration and selects a new run directory:

```sh
export CPX_REHEARSAL_ROOT="$(node -p 'require("./scripts/rehearsal-config.cjs").rehearsalParent + "/competition-run2"')"
```

Then repeat the four startup commands in order. The deployment command refuses to overwrite existing deployment metadata or a rehearsal database/evidence directory. Never point a new chain at an old rehearsal directory.

### Verify, stop, restart, and recover

The Ledger's **Verify receipt** action or `GET /api/v1/anchors/{batch_id}/verify` on port 8110 performs live verification. Without that successful response, SQLite metadata is only `recorded`. The old anchor remains unverified/unavailable against a fresh chain, even if the fresh chain uses ID 31337 and the same default Hardhat accounts.

Press Ctrl+C in the `rehearsal:app` terminal to stop FastAPI and Vite; this does not stop the Hardhat process in Terminal 1. Restart only `npm run rehearsal:app` to reuse the existing database, evidence, deployment metadata, and still-running chain. Do not run the one-time seed or deployment command during this restart.

Press Ctrl+C in Terminal 1 only when ending the chain session. Hardhat keeps its local history in process memory: stopping that process loses contract deployments and anchor transactions. The SQLite database and deployment JSON preserve references, not the chain history, and cannot restore it. After a chain stop, the app guard refuses to start against the old deployment if its contract code is absent. Preserve that old rehearsal folder, select a new `CPX_REHEARSAL_ROOT`, then deploy and seed a new session to make a fresh verifiable anchor.

If you have a verified source/data backup stored outside the project, set `CHAINPROOF_BACKUP_ARCHIVE` to its archive path and verify the archive and its checksum before recovery. The commands below assume a `.sha256` checksum sidecar next to the archive:

```sh
backup_archive="${CHAINPROOF_BACKUP_ARCHIVE:?Set CHAINPROOF_BACKUP_ARCHIVE to the verified archive path}"
shasum -a 256 -c "${backup_archive}.sha256"
tar -tzf "$backup_archive" | head
```

If a restore is needed, extract only into a new empty recovery directory outside the live project, never over the workspace:

```sh
restore_dir="${CHAINPROOF_RECOVERY_DIR:?Set CHAINPROOF_RECOVERY_DIR to a new recovery directory outside the live project}"
test ! -e "$restore_dir" || { echo "Refusing to overwrite existing recovery directory: $restore_dir"; exit 1; }
mkdir -p "$restore_dir"
tar -xzf "$backup_archive" -C "$restore_dir"
```

The archive verifies project files and SQLite snapshots. It does not contain a persistent Hardhat chain snapshot and therefore cannot restore local chain history.

## Checks

```sh
npm test
npm run test:frontend
.venv/bin/python -m pytest -q
npm run test:contract
npm run build
```

On Windows, use `.venv\Scripts\python.exe -m pytest -q`. The Python suite may use loopback sockets for local Hardhat integration tests.

## Security review and known limitations

This release is a **local development and evaluation build, not production-ready**.

- **API access:** every data API route requires a high-entropy viewer or analyst bearer token. Viewer can read; analyst can also write. The launcher fails before starting if the two distinct tokens are absent or weak. This is a shared service-token boundary, not per-user identity, SSO, tenant isolation, delegated roles, session expiry, or a production identity system. Tokens are held in browser memory for the current tab, but remain bearer secrets and require secure delivery. Bind only to loopback. Do not expose FastAPI or Hardhat on a network interface or through a reverse proxy until an identity provider, TLS, per-user authorization, audit identity, rate limits, and deployment review are in place.
- **Key trust:** only Ed25519 public keys are registered; signing private keys must stay with an external signer and are never placed in SQLite, browser storage, or Solidity. Public-key registration is self-asserted and does not establish identity or organizational trust. Key revocation and an identity-backed registration authority are not implemented.
- **Evidence storage:** exact uploaded bytes are stored separately from normalized event JSON. On POSIX systems, the database and object files use owner-only file permissions, with owner-only evidence directories. Storage remains local SQLite plus the filesystem; it is not a write-once archive, remote backup, or independently protected audit vault. A privileged local actor able to alter both the database and evidence store can undermine local records. Set protected backups and retention before operational use. Windows access is governed by the user's filesystem ACLs.
- **Blockchain:** anchoring submits and verifies a real transaction against the local Hardhat registry. The local chain is ephemeral; restarting it loses its ledger state. Hardhat prints publicly known test-account private keys in the terminal; never use or fund those keys on a live network. The exported report lists stored anchor metadata and does not re-query the chain. No public chain or production key custody is configured.
- **Analyst investigations:** investigations are additive analyst-authored case records linked to same-case evidence and deterministic correlation IDs. They can be opened or closed; deletion, reassignment/editing of references, permissions, and multi-analyst audit identity are not implemented. A linked correlation that a later recompute would remove is preserved and causes recomputation to stop with a conflict for analyst review.
- **Interpretation:** byte hashes and signatures show consistency with recorded bytes and a registered public key. Merkle proofs show inclusion under a root. None of these establishes source-log truth. Correlations are deterministic candidates, not causation. Completeness is unknown without an independently prepared expected-event manifest, and a matching manifest cannot prove that its expectations are complete.
- **Reports:** exports are point-in-time snapshots with generation timestamps and current byte checks, so timestamped output files are not byte-for-byte identical across exports. Their evidence and verification limitations are included in each report.
- **Dependencies:** a fresh 2026-10-11 `npm audit` found 0 production advisories; all 42 remaining findings are in the development dependency tree (12 high, 17 moderate, 13 low; 0 critical). Targeted overrides pin transitive `lodash` to 4.18.1 and `tmp` to 0.2.7; the dependency override regression test and full suites pass. The remaining high findings are in the Hardhat/tooling tree: `@fastify/busboy`, `adm-zip`, `braces`, `chokidar`, `fast-glob`, `globby`, Hardhat 2.x, `micromatch`, `mocha`, `serialize-javascript`, `solidity-coverage`, and `undici`. npm's remaining suggested remediation upgrades Hardhat to 3.19.0 or Hardhat Toolbox to 7.0.0, a major toolchain migration, so it was not applied. Re-run `npm audit` before releases. `pip check` found no broken Python requirements; `pip-audit` is not installed, so Python advisory scanning remains outstanding.

## Exact local workflows

From the project directory, install dependencies and start the normal integrated stack:

```sh
npm ci
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
cp .env.example .env
npm run dev:stack
```

Use `.venv\Scripts\python.exe` for Python commands on Windows. The startup command starts Hardhat on `127.0.0.1:8545`, deploys `EvidenceRegistry`, waits for FastAPI at `127.0.0.1:8000`, and waits for Vite at `127.0.0.1:5173`. Keep the terminal open; press Ctrl+C to stop the stack. Synthetic data belongs in the separately documented competition demo stack.

For a clean competition walkthrough, use the separate ports and data paths shown above: stop any previous demo run, execute `npm run demo:reset`, run `npm run demo:stack`, then in a second terminal run `npm run demo:seed`. Visit <http://127.0.0.1:5174>. This stack uses its own ephemeral Hardhat node at 8546 and is isolated from the normal database at `data/chainproof.sqlite3`.

Run all automated suites and the production build with:

```sh
npm test
npm run test:frontend
PYTHONPATH=. .venv/bin/python -m pytest -q
npm run test:contract
npm run build
```

On Windows PowerShell, use `.venv\Scripts\python.exe -m pytest -q` and set `$env:PYTHONPATH='.'` first.

The current security limitations remain material: bearer tokens are shared environment credentials rather than per-user identity; local filesystem and SQLite are not write-once storage; public-key registration is self-asserted with no identity authority or revocation; the local chain is ephemeral and its Hardhat accounts are public test accounts; and integrity/correlation/completeness checks cannot establish source truth or log completeness. The latest dependency audit must be rerun against the registry before release. This project remains an evaluation build, not production-ready.

## Existing service details

The FastAPI routes and evidence, signing-key, completeness, correlation, graph, report, and anchor semantics are documented in [backend/README.md](backend/README.md). The cross-source deterministic rule is documented in [docs/correlation-rules.md](docs/correlation-rules.md). Reports include verification timestamps and limitations. An expected-event manifest is an externally supplied expectation: a complete match cannot prove the manifest itself covers every event that should have existed.
