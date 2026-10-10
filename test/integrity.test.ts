import assert from 'node:assert/strict';
import { createPublicKey, generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import {
  buildMerkleBatch,
  canonicalizeEvent,
  MAX_BATCH_BYTES,
  MAX_BATCH_EVENTS,
  MAX_EVENT_FIELD_BYTES,
  publicKeyId,
  sha256,
  signBatch,
  testOnlyPrivateKeyFromSeed,
  verifyBatchSignature,
  verifyRegisteredBatchSignature,
  verifyInclusionProof,
  type EventRecord,
  type SignedBatch,
} from '../src/integrity.ts';

const event: EventRecord = {
  eventId: 'evt-001',
  sourceId: 'synthetic-host',
  occurredAt: '2026-10-10T12:34:56.789Z',
  eventType: 'login.success',
  actor: 'josé@example.test',
  target: 'srv-01',
};
const seed = Buffer.from('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', 'hex');

test('canonical event has stable field ordering and NFC Unicode', () => {
  const shuffled = { target: 'srv-01', actor: 'jose\u0301@example.test', eventType: 'login.success', occurredAt: event.occurredAt, sourceId: event.sourceId, eventId: event.eventId };
  const { event: normalized, bytes } = canonicalizeEvent(shuffled);
  assert.equal(normalized.actor, 'josé@example.test');
  assert.equal(bytes.toString('utf8'), '{"eventId":"evt-001","sourceId":"synthetic-host","occurredAt":"2026-10-10T12:34:56.789Z","eventType":"login.success","actor":"josé@example.test","target":"srv-01"}');
  assert.equal(sha256(bytes).toString('hex'), '6b595ed728900869b67d096786b31bd9175bbcde0664fd1abc858e196af1f543');
});

test('canonicalizer rejects missing, unknown, ambiguous, and malformed values', () => {
  const { event: normalized } = canonicalizeEvent(event);
  assert.throws(() => canonicalizeEvent({ ...normalized, extra: 'x' }), /exactly the six defined fields/);
  const missing = { ...normalized } as Record<string, unknown>;
  delete missing.actor;
  assert.throws(() => canonicalizeEvent(missing), /exactly the six defined fields/);
  assert.throws(() => canonicalizeEvent({ ...normalized, actor: null }), /must be a string/);
  assert.throws(() => canonicalizeEvent({ ...normalized, actor: '  ' }), /must not be empty/);
  assert.throws(() => canonicalizeEvent({ ...normalized, actor: 'bad\u0000value' }), /control character/);
  assert.throws(() => canonicalizeEvent({ ...normalized, actor: '\ud800' }), /unpaired Unicode surrogate/);
  assert.throws(() => canonicalizeEvent({ ...normalized, occurredAt: '2026-10-10T12:34:56Z' }), /exactly millisecond precision/);
  assert.throws(() => canonicalizeEvent({ ...normalized, occurredAt: '2026-02-30T12:34:56.000Z' }), /not a valid timestamp/);
  assert.throws(() => canonicalizeEvent(Object.assign(Object.create({ inherited: 'x' }), normalized)), /plain data object/);
  assert.throws(() => canonicalizeEvent({ ...normalized, [Symbol('extra')]: 'x' }), /plain data object|exactly the six defined fields/);
  const accessor = { ...normalized };
  Object.defineProperty(accessor, 'actor', { enumerable: true, get() { throw new Error('must not execute'); } });
  assert.throws(() => canonicalizeEvent(accessor), /plain data object/);
  assert.throws(() => canonicalizeEvent({ ...normalized, actor: 'é'.repeat(MAX_EVENT_FIELD_BYTES) }), /byte limit/);
});

test('original evidence bytes remain distinct from normalized event bytes', () => {
  const original = readFileSync(new URL('../fixtures/synthetic-evidence.json', import.meta.url));
  const originalBefore = Buffer.from(original);
  const digest = sha256(original).toString('hex');
  const parsed = JSON.parse(original.toString('utf8')) as unknown;
  const canonical = canonicalizeEvent(parsed).bytes;
  assert.deepEqual(original, originalBefore);
  assert.notDeepEqual(original, canonical);
  assert.equal(digest, '9db5f93ea9347e9dd490ccd7dcf263992bb11819c627194a0fc118c1ed7b0050');
  assert.equal(canonical.toString('utf8'), canonicalizeEvent(event).bytes.toString('utf8'));
});

test('one-leaf Merkle root and inclusion proof verify; tampering fails', () => {
  const batch = buildMerkleBatch([event]);
  assert.equal(batch.rootHash.toString('hex'), '5a5031e0ab12a0ee07ef376948ea00e84abb20a39929f1e572ddd56cc64b91b2');
  assert.deepEqual(batch.proofs[0], { version: 'cpx-merkle-v1', leafIndex: 0, leafCount: 1, steps: [] });
  assert.equal(verifyInclusionProof(batch.canonicalEvents[0]!, batch.proofs[0]!, batch.rootHash.toString('hex')), true);
  assert.equal(verifyInclusionProof(Buffer.from('tampered'), batch.proofs[0]!, batch.rootHash.toString('hex')), false);
});

test('deterministic ordering, odd-node promotion, duplicate IDs, and invalid proofs', () => {
  const events = ['evt-03', 'evt-01', 'evt-02'].map((eventId) => ({ ...event, eventId }));
  const batch = buildMerkleBatch(events);
  assert.deepEqual(batch.events.map((item) => item.eventId), ['evt-01', 'evt-02', 'evt-03']);
  assert.deepEqual(batch.proofs[2]!.steps, [{ side: 'promote' }, { side: 'left', hash: '830e42d06cb283d47de7728d2f6add39caab96e076d4095f5658fd92c3081924' }]);
  assert.equal(verifyInclusionProof(batch.canonicalEvents[2]!, batch.proofs[2]!, batch.rootHash.toString('hex')), true);
  const altered = { ...batch.proofs[2]!, steps: [{ side: 'right' as const, hash: '0'.repeat(64) }, { side: 'left' as const, hash: '0'.repeat(64) }] };
  assert.equal(verifyInclusionProof(batch.canonicalEvents[2]!, altered, batch.rootHash.toString('hex')), false);
  assert.throws(() => buildMerkleBatch([event, { ...event }]), /duplicate eventId/);
  assert.throws(() => buildMerkleBatch([]), /at least one event/);
});

test('Merkle proofs verify at power-of-two and irregular sizes; malformed proofs are rejected', () => {
  for (const count of [1, 2, 3, 4, 5, 7, 8, 9]) {
    const events = Array.from({ length: count }, (_, index) => ({ ...event, eventId: `evt-${String(index).padStart(2, '0')}` }));
    const batch = buildMerkleBatch(events);
    for (let index = 0; index < count; index += 1) {
      assert.equal(verifyInclusionProof(batch.canonicalEvents[index]!, batch.proofs[index]!, batch.rootHash.toString('hex')), true, `count=${count} index=${index}`);
    }
    const proof = batch.proofs[count - 1]!;
    assert.equal(verifyInclusionProof(batch.canonicalEvents[count - 1]!, { ...proof, leafCount: Number.MAX_SAFE_INTEGER }, batch.rootHash.toString('hex')), false);
    if (proof.steps.length > 0) {
      const first = proof.steps[0]!;
      assert.equal(verifyInclusionProof(batch.canonicalEvents[count - 1]!, {
        ...proof,
        steps: [{ ...first, unexpected: true } as typeof first, ...proof.steps.slice(1)],
      }, batch.rootHash.toString('hex')), false);
    }
  }
});

test('proof verifier rejects noncanonical, malformed UTF-8, and malformed event bytes', () => {
  const batch = buildMerkleBatch([event]);
  const proof = batch.proofs[0]!;
  const root = batch.rootHash.toString('hex');
  assert.equal(verifyInclusionProof(Buffer.from(` ${batch.canonicalEvents[0]!.toString('utf8')}`), proof, root), false);
  assert.equal(verifyInclusionProof(Buffer.from('{"eventId":"evt-001","extra":"no"}'), proof, root), false);
  assert.equal(verifyInclusionProof(Buffer.from([0xff, 0xfe]), proof, root), false);
});

test('Merkle batch size and missing-entry limits are enforced', () => {
  assert.throws(() => buildMerkleBatch(new Array(MAX_BATCH_EVENTS + 1)), /event limit/);
  const sparse = new Array(1);
  assert.throws(() => buildMerkleBatch(sparse), /missing event/);
  const largeEvent = (eventId: string) => ({ ...event, eventId, actor: 'x'.repeat(1100) });
  const byteLimited = Array.from({ length: MAX_BATCH_EVENTS }, (_, index) => largeEvent(`evt-${String(index).padStart(4, '0')}`));
  assert.throws(() => buildMerkleBatch(byteLimited), new RegExp(`${MAX_BATCH_BYTES}-byte limit`));
});

test('Ed25519 signs exact domain-separated batch bytes; changed fields and invalid keys fail', () => {
  const privateKey = testOnlyPrivateKeyFromSeed(seed);
  const publicKey = createPublicKey(privateKey);
  const tree = buildMerkleBatch([event]);
  const batch: SignedBatch = {
    version: 'cpx-signed-batch-v1', batchId: 'batch-001', keyId: publicKeyId(publicKey),
    treeVersion: 'cpx-merkle-v1', leafCount: 1, rootHash: tree.rootHash.toString('hex'),
  };
  const signature = signBatch(batch, privateKey);
  const publicDer = publicKey.export({ format: 'der', type: 'spki' });
  assert.equal(signature.toString('hex'), '1938903d440b08601fa4b009dff2562d3be95dea6fc5b2a2cc72122b35af4ebc4a87f77f9e792ad2b5bd5b12c6df8ae898953f2a9d6fee7429fdc6e7a0d59600');
  assert.equal(verifyBatchSignature(batch, signature, publicDer), true);
  assert.equal(verifyBatchSignature({ ...batch, batchId: 'batch-002' }, signature, publicDer), false);
  assert.equal(verifyBatchSignature(batch, Buffer.alloc(64), publicDer), false);
  const registration = { keyId: batch.keyId, publicKeyDer: publicDer, status: 'active' as const };
  assert.equal(verifyRegisteredBatchSignature(batch, signature, registration), 'valid');
  assert.equal(verifyRegisteredBatchSignature(batch, signature, undefined), 'unknown_key');
  assert.equal(verifyRegisteredBatchSignature(batch, signature, { ...registration, status: 'revoked' as const }), 'revoked_key');
  assert.equal(verifyRegisteredBatchSignature(batch, Buffer.alloc(64), registration), 'invalid_signature');
  assert.throws(() => signBatch({ ...batch, keyId: '0'.repeat(64) }, privateKey), /does not match registered keyId/);
  assert.equal(verifyBatchSignature(batch, signature, Buffer.from('invalid')), false);
});

test('signing and verification reject non-Ed25519 key types and noncanonical public-key DER', () => {
  const edPrivate = testOnlyPrivateKeyFromSeed(seed);
  const edPublic = createPublicKey(edPrivate);
  const tree = buildMerkleBatch([event]);
  const batch: SignedBatch = {
    version: 'cpx-signed-batch-v1', batchId: 'batch-001', keyId: publicKeyId(edPublic),
    treeVersion: 'cpx-merkle-v1', leafCount: 1, rootHash: tree.rootHash.toString('hex'),
  };
  const signature = signBatch(batch, edPrivate);
  const { privateKey: rsaPrivate, publicKey: rsaPublic } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  assert.throws(() => signBatch(batch, rsaPrivate), /must be an Ed25519 private key/);
  assert.equal(verifyBatchSignature(batch, signature, rsaPublic.export({ format: 'der', type: 'spki' })), false);
  assert.equal(verifyBatchSignature(batch, signature, Buffer.concat([edPublic.export({ format: 'der', type: 'spki' }), Buffer.from([0])])), false);
  assert.throws(() => publicKeyId(rsaPublic), /must be an Ed25519 public key/);
});
