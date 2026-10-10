import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as cryptoSign,
  verify as cryptoVerify,
  type KeyObject,
} from 'node:crypto';

export const TREE_VERSION = 'cpx-merkle-v1';
export const SIGNED_PAYLOAD_VERSION = 'cpx-signed-batch-v1';
export const SIGNED_PAYLOAD_DOMAIN = Buffer.from('ChainProofX-SignedBatch-v1\0', 'utf8');
export const MAX_EVENT_FIELD_BYTES = 4 * 1024;
export const MAX_EVENT_BYTES = 24 * 1024;
export const MAX_BATCH_EVENTS = 4096;
export const MAX_BATCH_BYTES = 4 * 1024 * 1024;

export interface EventRecord {
  eventId: string;
  sourceId: string;
  occurredAt: string;
  eventType: string;
  actor: string;
  target: string;
}

export interface MerkleProofStep {
  side: 'left' | 'right' | 'promote';
  hash?: string;
}

export interface InclusionProof {
  version: typeof TREE_VERSION;
  leafIndex: number;
  leafCount: number;
  steps: MerkleProofStep[];
}

export interface SignedBatch {
  version: typeof SIGNED_PAYLOAD_VERSION;
  batchId: string;
  keyId: string;
  treeVersion: typeof TREE_VERSION;
  leafCount: number;
  rootHash: string;
}

export interface PublicKeyRegistration {
  keyId: string;
  publicKeyDer: Uint8Array;
  status: 'active' | 'revoked';
}

export type RegisteredSignatureResult = 'valid' | 'unknown_key' | 'revoked_key' | 'invalid_signature';

export function sha256(bytes: Uint8Array): Buffer {
  return createHash('sha256').update(bytes).digest();
}

function fail(message: string): never {
  throw new TypeError(message);
}

function ownDataRecord(input: unknown): Record<string, unknown> | undefined {
  if (input === null || typeof input !== 'object' || Array.isArray(input)) return undefined;
  const prototype = Object.getPrototypeOf(input);
  if (prototype !== Object.prototype && prototype !== null) return undefined;
  const keys = Reflect.ownKeys(input);
  if (keys.some((key) => typeof key !== 'string')) return undefined;
  for (const key of keys as string[]) {
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    if (!descriptor || !descriptor.enumerable || !('value' in descriptor)) return undefined;
  }
  return input as Record<string, unknown>;
}

function hasUnpairedSurrogate(value: string): boolean {
  for (let i = 0; i < value.length; i += 1) {
    const unit = value.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
      i += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function canonicalText(value: unknown, field: string): string {
  if (typeof value !== 'string') fail(`${field} must be a string`);
  if (value.length === 0 || value.trim().length === 0) fail(`${field} must not be empty`);
  if (hasUnpairedSurrogate(value)) fail(`${field} contains an unpaired Unicode surrogate`);
  const normalized = value.normalize('NFC');
  if (/[\u0000-\u001f\u007f-\u009f]/u.test(normalized)) fail(`${field} contains a control character`);
  if (Buffer.byteLength(normalized, 'utf8') > MAX_EVENT_FIELD_BYTES) fail(`${field} exceeds the ${MAX_EVENT_FIELD_BYTES}-byte limit`);
  return normalized;
}

function canonicalTimestamp(value: unknown): string {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)) {
    fail('occurredAt must be UTC RFC 3339 with exactly millisecond precision and Z suffix');
  }
  const epoch = Date.parse(value);
  if (!Number.isFinite(epoch) || new Date(epoch).toISOString() !== value) fail('occurredAt is not a valid timestamp');
  return value;
}

const EVENT_KEYS = ['eventId', 'sourceId', 'occurredAt', 'eventType', 'actor', 'target'] as const;

export function canonicalizeEvent(input: unknown): { event: EventRecord; bytes: Buffer } {
  const value = ownDataRecord(input);
  if (!value) fail('event must be a plain data object');
  const keys = Reflect.ownKeys(value) as string[];
  if (keys.length !== EVENT_KEYS.length || keys.some((key) => !EVENT_KEYS.includes(key as (typeof EVENT_KEYS)[number]))) {
    fail('event must contain exactly the six defined fields; extra and missing fields are rejected');
  }

  const eventId = canonicalText(value.eventId, 'eventId');
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(eventId)) fail('eventId must use the documented ASCII identifier syntax');

  const event: EventRecord = {
    eventId,
    sourceId: canonicalText(value.sourceId, 'sourceId'),
    occurredAt: canonicalTimestamp(value.occurredAt),
    eventType: canonicalText(value.eventType, 'eventType'),
    actor: canonicalText(value.actor, 'actor'),
    target: canonicalText(value.target, 'target'),
  };
  // Fixed field order, compact JSON, and UTF-8 without BOM. JSON.stringify escapes
  // quotes, backslashes, and required JSON control characters deterministically.
  const bytes = Buffer.from(JSON.stringify(event), 'utf8');
  if (bytes.byteLength > MAX_EVENT_BYTES) fail(`canonical event exceeds the ${MAX_EVENT_BYTES}-byte limit`);
  return { event, bytes };
}

function eventLeaf(canonicalEvent: Uint8Array): Buffer {
  return sha256(Buffer.concat([Buffer.from([0x00]), Buffer.from(canonicalEvent)]));
}

function parentHash(left: Buffer, right: Buffer): Buffer {
  return sha256(Buffer.concat([Buffer.from([0x01]), left, right]));
}

function compareUtf8(a: string, b: string): number {
  return Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
}

export function buildMerkleBatch(inputs: unknown[]): {
  events: EventRecord[];
  canonicalEvents: Buffer[];
  leaves: Buffer[];
  rootHash: Buffer;
  proofs: InclusionProof[];
} {
  if (!Array.isArray(inputs)) fail('batch events must be an array');
  if (inputs.length === 0) fail('a Merkle batch must contain at least one event');
  if (inputs.length > MAX_BATCH_EVENTS) fail(`batch exceeds the ${MAX_BATCH_EVENTS}-event limit`);
  const canonical: Array<{ event: EventRecord; bytes: Buffer }> = [];
  let totalBytes = 0;
  for (let index = 0; index < inputs.length; index += 1) {
    if (!Object.hasOwn(inputs, index)) fail(`batch contains a missing event at index ${index}`);
    const item = canonicalizeEvent(inputs[index]);
    totalBytes += item.bytes.byteLength;
    if (totalBytes > MAX_BATCH_BYTES) fail(`batch exceeds the ${MAX_BATCH_BYTES}-byte limit`);
    canonical.push(item);
  }
  canonical.sort((a, b) => compareUtf8(a.event.eventId, b.event.eventId));
  for (let index = 1; index < canonical.length; index += 1) {
    if (canonical[index - 1]!.event.eventId === canonical[index]!.event.eventId) {
      fail(`duplicate eventId: ${canonical[index]!.event.eventId}`);
    }
  }
  const leaves = canonical.map(({ bytes }) => eventLeaf(bytes));
  const levels: Buffer[][] = [leaves];
  while (levels.at(-1)!.length > 1) {
    const current = levels.at(-1)!;
    const next: Buffer[] = [];
    for (let index = 0; index < current.length; index += 2) {
      next.push(index + 1 < current.length ? parentHash(current[index]!, current[index + 1]!) : current[index]!);
    }
    levels.push(next);
  }

  const proofs = leaves.map((_leaf, originalIndex): InclusionProof => {
    let index = originalIndex;
    const steps: MerkleProofStep[] = [];
    for (let level = 0; level < levels.length - 1; level += 1) {
      const row = levels[level]!;
      if (index % 2 === 1) steps.push({ side: 'left', hash: row[index - 1]!.toString('hex') });
      else if (index + 1 < row.length) steps.push({ side: 'right', hash: row[index + 1]!.toString('hex') });
      else steps.push({ side: 'promote' });
      index = Math.floor(index / 2);
    }
    return { version: TREE_VERSION, leafIndex: originalIndex, leafCount: leaves.length, steps };
  });

  return {
    events: canonical.map(({ event }) => event),
    canonicalEvents: canonical.map(({ bytes }) => bytes),
    leaves,
    rootHash: levels.at(-1)![0]!,
    proofs,
  };
}

function isLowerHex(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{64}$/u.test(value);
}

function canonicalBytesFromProofInput(input: unknown): Buffer | undefined {
  if (input instanceof Uint8Array) {
    if (input.byteLength > MAX_EVENT_BYTES) return undefined;
    let parsed: unknown;
    try {
      parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(input));
    } catch {
      return undefined;
    }
    const canonical = canonicalizeEvent(parsed).bytes;
    return Buffer.from(input).equals(canonical) ? canonical : undefined;
  }
  return canonicalizeEvent(input).bytes;
}

export function verifyInclusionProof(canonicalEvent: Uint8Array, proof: InclusionProof, expectedRootHex: string): boolean {
  try {
    const proofRecord = ownDataRecord(proof);
    if (!proofRecord || Reflect.ownKeys(proofRecord).length !== 4
      || Object.keys(proofRecord).some((key) => !['version', 'leafIndex', 'leafCount', 'steps'].includes(key))) return false;
    if (!isLowerHex(expectedRootHex) || proof.version !== TREE_VERSION || !Number.isSafeInteger(proof.leafCount)
      || proof.leafCount < 1 || proof.leafCount > MAX_BATCH_EVENTS || !Number.isSafeInteger(proof.leafIndex)
      || proof.leafIndex < 0 || proof.leafIndex >= proof.leafCount || !Array.isArray(proof.steps)) return false;
    const canonicalEventBytes = canonicalBytesFromProofInput(canonicalEvent);
    if (!canonicalEventBytes) return false;
    let hash = eventLeaf(canonicalEventBytes);
    let index = proof.leafIndex;
    let width = proof.leafCount;
    let stepIndex = 0;
    while (width > 1) {
      const step = proof.steps[stepIndex++];
      if (!step) return false;
      const stepRecord = ownDataRecord(step);
      if (!stepRecord) return false;
      const isOdd = index % 2 === 1;
      const hasRight = !isOdd && index + 1 < width;
      if (isOdd) {
        if (Reflect.ownKeys(stepRecord).length !== 2 || Object.keys(stepRecord).some((key) => !['side', 'hash'].includes(key))
          || step.side !== 'left' || !isLowerHex(step.hash)) return false;
        hash = parentHash(Buffer.from(step.hash, 'hex'), hash);
      } else if (hasRight) {
        if (Reflect.ownKeys(stepRecord).length !== 2 || Object.keys(stepRecord).some((key) => !['side', 'hash'].includes(key))
          || step.side !== 'right' || !isLowerHex(step.hash)) return false;
        hash = parentHash(hash, Buffer.from(step.hash, 'hex'));
      } else if (Reflect.ownKeys(stepRecord).length !== 1 || step.side !== 'promote') return false;
      index = Math.floor(index / 2);
      width = Math.ceil(width / 2);
    }
    return stepIndex === proof.steps.length && hash.toString('hex') === expectedRootHex;
  } catch {
    return false;
  }
}

function canonicalSignedBatch(batch: SignedBatch): Buffer {
  const record = ownDataRecord(batch);
  const keys = ['version', 'batchId', 'keyId', 'treeVersion', 'leafCount', 'rootHash'];
  if (!record || Reflect.ownKeys(record).length !== keys.length || Object.keys(record).some((key) => !keys.includes(key))) {
    fail('signed batch must be a plain data object with exactly six fields');
  }
  if (batch.version !== SIGNED_PAYLOAD_VERSION || batch.treeVersion !== TREE_VERSION) fail('unsupported signed batch version');
  if (typeof batch.batchId !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(batch.batchId)) fail('invalid batchId');
  if (!isLowerHex(batch.keyId) || !isLowerHex(batch.rootHash)) fail('keyId and rootHash must be lowercase SHA-256 hex');
  if (!Number.isSafeInteger(batch.leafCount) || batch.leafCount < 1) fail('leafCount must be a positive safe integer');
  const json = JSON.stringify({
    version: batch.version,
    batchId: batch.batchId,
    keyId: batch.keyId,
    treeVersion: batch.treeVersion,
    leafCount: batch.leafCount,
    rootHash: batch.rootHash,
  });
  return Buffer.concat([SIGNED_PAYLOAD_DOMAIN, Buffer.from(json, 'utf8')]);
}

export function rawEd25519PublicKey(publicKey: KeyObject): Buffer {
  if (publicKey.type !== 'public' || publicKey.asymmetricKeyType !== 'ed25519') fail('key must be an Ed25519 public key');
  const der = publicKey.export({ format: 'der', type: 'spki' }) as Buffer;
  const prefix = Buffer.from('302a300506032b6570032100', 'hex');
  if (der.length !== prefix.length + 32 || !der.subarray(0, prefix.length).equals(prefix)) fail('invalid Ed25519 public key encoding');
  return der.subarray(prefix.length);
}

export function publicKeyId(publicKey: KeyObject): string {
  return sha256(rawEd25519PublicKey(publicKey)).toString('hex');
}

export function signBatch(batch: SignedBatch, privateKey: KeyObject): Buffer {
  if (privateKey.type !== 'private' || privateKey.asymmetricKeyType !== 'ed25519') fail('key must be an Ed25519 private key');
  const publicKey = createPublicKey(privateKey);
  if (publicKeyId(publicKey) !== batch.keyId) fail('signing key does not match registered keyId');
  return cryptoSign(null, canonicalSignedBatch(batch), privateKey);
}

export function verifyBatchSignature(batch: SignedBatch, signature: Uint8Array, registeredPublicKeyDer: Uint8Array): boolean {
  try {
    if (signature.byteLength !== 64) return false;
    const publicKey = createPublicKey({ key: Buffer.from(registeredPublicKeyDer), format: 'der', type: 'spki' });
    if (publicKey.asymmetricKeyType !== 'ed25519' || publicKeyId(publicKey) !== batch.keyId) return false;
    const canonicalDer = publicKey.export({ format: 'der', type: 'spki' }) as Buffer;
    if (!canonicalDer.equals(Buffer.from(registeredPublicKeyDer))) return false;
    return cryptoVerify(null, canonicalSignedBatch(batch), publicKey, Buffer.from(signature));
  } catch {
    return false;
  }
}

/** Verify against a registration supplied by the caller's trusted key registry. */
export function verifyRegisteredBatchSignature(
  batch: SignedBatch,
  signature: Uint8Array,
  registration: PublicKeyRegistration | undefined,
): RegisteredSignatureResult {
  if (!registration) return 'unknown_key';
  const record = ownDataRecord(registration);
  if (!record || Reflect.ownKeys(record).length !== 3
    || Object.keys(record).some((key) => !['keyId', 'publicKeyDer', 'status'].includes(key))
    || !isLowerHex(registration.keyId) || !(registration.publicKeyDer instanceof Uint8Array)
    || !['active', 'revoked'].includes(registration.status)) return 'invalid_signature';
  if (registration.keyId !== batch.keyId) return 'invalid_signature';
  if (registration.status === 'revoked') return 'revoked_key';
  return verifyBatchSignature(batch, signature, registration.publicKeyDer) ? 'valid' : 'invalid_signature';
}

// Deterministic seed, explicitly test-only. Production private keys must be generated
// and protected by an external key manager; this value must never be used in production.
export function testOnlyPrivateKeyFromSeed(seed: Uint8Array): KeyObject {
  if (seed.byteLength !== 32) fail('Ed25519 seed must be 32 bytes');
  const pkcs8Prefix = Buffer.from('302e020100300506032b657004220420', 'hex');
  return createPrivateKey({ key: Buffer.concat([pkcs8Prefix, Buffer.from(seed)]), format: 'der', type: 'pkcs8' });
}
