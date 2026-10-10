# ChainProof X integrity format, version 1

This document defines the deterministic formats used by the first integrity slice. A format change requires a new version. The fixture and assertions in `test/integrity.test.ts` are executable test vectors.

## Evidence and normalized records

The bytes collected from a source are the original evidence object. Store and hash those exact bytes as an immutable object, separate from parsed/normalized event records. This slice demonstrates that boundary with `fixtures/synthetic-evidence.json`: the original fixture bytes are read and hashed without rewriting them, while parsing and canonicalization create a separate byte sequence. Parsing never replaces, normalizes in place, or re-encodes the original evidence. Preserve parse errors and source offsets alongside the original in a later ingestion service.

SHA-256 of the exact fixture file bytes (including indentation and final newline): `9db5f93ea9347e9dd490ccd7dcf263992bb11819c627194a0fc118c1ed7b0050`.

## Canonical event JSON (`cpx-event-v1`)

An event is a JSON object with exactly these six string fields, serialized in this order, with no whitespace:

1. `eventId`
2. `sourceId`
3. `occurredAt`
4. `eventType`
5. `actor`
6. `target`

Encode as UTF-8 without a byte-order mark. JSON strings use standard JSON escaping for quotes, reverse solidus, and required control escapes. Unicode scalar values are normalized to NFC before serialization; unpaired UTF-16 surrogates are rejected. Identifiers (`eventId`) must match `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`. Other string values must be nonempty after trimming, contain no C0/C1 controls, and are preserved otherwise after NFC normalization. Do not trim or case-fold field contents.

`occurredAt` must be a valid UTC timestamp in exactly `YYYY-MM-DDTHH:mm:ss.sssZ` form. Offsets other than `Z`, missing fractions, precision other than exactly three fractional digits, leap-second notation, invalid calendar dates, and timestamps that cannot round-trip through that exact form are rejected. No local timezone inference is allowed.

Reject missing or extra fields, `null`, booleans, numbers, arrays, nested objects, empty/whitespace-only strings, invalid UTF-16, and timestamps with ambiguous precision or timezone. Input object key order does not affect output. Duplicate `eventId` values in a batch are a hard batch error; do not silently choose one or merge records.

Inputs must be plain objects with own enumerable data properties only; accessors, symbols, inherited fields, and custom prototypes are rejected. Resource limits are 4 KiB UTF-8 per field, 24 KiB per canonical event, 4,096 events per batch, and 4 MiB total canonical batch bytes.

Synthetic fixture canonical event bytes:

```text
{"eventId":"evt-001","sourceId":"synthetic-host","occurredAt":"2026-10-10T12:34:56.789Z","eventType":"login.success","actor":"josé@example.test","target":"srv-01"}
```

SHA-256 of those canonical bytes:

```text
6b595ed728900869b67d096786b31bd9175bbcde0664fd1abc858e196af1f543
```

## Merkle tree (`cpx-merkle-v1`)

All hashes are SHA-256, represented in lowercase hexadecimal when serialized.

- Leaf: `SHA256(0x00 || canonical_event_utf8)`.
- Internal node: `SHA256(0x01 || left_child_32_bytes || right_child_32_bytes)`.
- Empty batches are invalid. A one-leaf root is that leaf hash.
- Sort events by `eventId` in ascending bytewise UTF-8 order before assigning leaf indexes. Event IDs are ASCII by schema, making this ordering unambiguous. Reject duplicate IDs before tree creation.
- At each level, pair adjacent nodes. An unpaired final node is promoted unchanged to the next level; it is not duplicated or hashed with itself. Repeat until one root remains.

Proof JSON has `{ "version": "cpx-merkle-v1", "leafIndex": integer, "leafCount": positive_integer, "steps": [...] }`. Steps are in leaf-to-root order. `{"side":"left","hash":"<64 lowercase hex>"}` means combine `hash || current`; `{"side":"right","hash":"..."}` means combine `current || hash`; `{"side":"promote"}` means carry the current hash unchanged for an unpaired node. A verifier derives the required side/promotion from `leafIndex` and `leafCount`, rejects missing/extra steps or irrelevant hashes, recomputes the root, and compares it with the expected root. The proof is not trusted merely because it came from this service.

The verifier also parses supplied event bytes as strict UTF-8 JSON, canonicalizes the event again, and requires byte-for-byte equality before hashing; malformed or noncanonical bytes fail verification. It enforces the same event and batch-count limits.

One-leaf test vector for the canonical event above:

```text
leaf = root = 5a5031e0ab12a0ee07ef376948ea00e84abb20a39929f1e572ddd56cc64b91b2
proof = {"version":"cpx-merkle-v1","leafIndex":0,"leafCount":1,"steps":[]}
```

The 3-leaf test uses IDs `evt-01`, `evt-02`, `evt-03`. Proof for index 2 is one `promote` step followed by a `left` step whose sibling is `830e42d06cb283d47de7728d2f6add39caab96e076d4095f5658fd92c3081924`.

## Ed25519 signed batch (`cpx-signed-batch-v1`)

The signed bytes are exactly:

```text
UTF8("ChainProofX-SignedBatch-v1") || 0x00 || UTF8(compact canonical JSON)
```

The JSON field order is `version`, `batchId`, `keyId`, `treeVersion`, `leafCount`, `rootHash`, with no whitespace:

```json
{"version":"cpx-signed-batch-v1","batchId":"batch-001","keyId":"56475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708c","treeVersion":"cpx-merkle-v1","leafCount":1,"rootHash":"5a5031e0ab12a0ee07ef376948ea00e84abb20a39929f1e572ddd56cc64b91b2"}
```

Sign these bytes with Ed25519 (no external digest/prehash). The signature is the standard 64-byte Ed25519 signature; serialize as lowercase hex or base64 only at an API boundary with an explicit encoding field. The verifier reconstructs bytes from parsed fields and the version rules, checks key type and signature length, verifies the signature, and checks that `keyId` matches the public key. Any failure is invalid; never downgrade to “unverified but accepted.”

### Public-key registration and custody

`keyId` is `SHA256(raw_32_byte_Ed25519_public_key)` as lowercase hex. A registration record contains key ID, raw public key (or its canonical DER/SPKI representation), owner/role, registration time, and lifecycle status. Registration IDs are unique and immutable; rotations create a new ID and record, revocations append a status event rather than rewriting signed history. `verifyRegisteredBatchSignature` requires the caller to supply a registration from its trusted registry and distinguishes unknown, revoked, and cryptographically invalid outcomes. This slice does not implement durable registration storage or an identity authority, and does not prove when a signature was made.

Private keys are generated and kept in a dedicated OS keychain, HSM, or external key manager. They are never persisted in SQLite, sent to the browser/frontend, or placed in a smart contract. Test-only fixed seeds exist solely to make deterministic vectors and must never be used for production signing. SQLite may hold public registration data and signatures.

Batch signature test vector uses test-only seed `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`; public key ID is `56475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708c`, and the signature is:

```text
1938903d440b08601fa4b009dff2562d3be95dea6fc5b2a2cc72122b35af4ebc4a87f77f9e792ad2b5bd5b12c6df8ae898953f2a9d6fee7429fdc6e7a0d59600
```

## Failure semantics

- Duplicate record or batch IDs: reject the operation; never overwrite an earlier object. Duplicate `eventId` in one batch rejects the whole batch.
- Invalid, malformed, unknown-key, revoked-key, or mismatching signature: return a failed verification result with a specific reason; do not mark the batch verified or anchored.
- Malformed event: retain original evidence bytes, reject that event's normalized record, and record a parse/validation error with its source reference. Do not guess or silently coerce values.
- Missing expected event: a manifest comparison records an explicit missing expectation and marks the completeness check incomplete. It must not synthesize an event or label the input evidence corrupt solely because the expectation was unmet.

Integrity results concern the bytes received and the later transformations recorded here. They do not establish that source logs were truthful, complete, correctly timed, or uncompromised before collection. This slice contains no SQLite, UI, manifest processor, or blockchain implementation; in particular it makes no claim of blockchain anchoring.
