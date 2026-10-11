import { readFileSync } from 'node:fs';
import { createPublicKey } from 'node:crypto';
import { buildMerkleBatch, canonicalizeEvent, publicKeyId, rawEd25519PublicKey, sha256, TREE_VERSION, verifyInclusionProof, verifyRegisteredBatchSignature, type SignedBatch } from './integrity.ts';

async function main(): Promise<void> {
  const input = await new Promise<string>((resolve, reject) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (part: string) => { data += part; });
    process.stdin.on('end', () => resolve(data));
    process.stdin.on('error', reject);
  });
  try {
    const parsed: unknown = JSON.parse(input);
    const result = canonicalizeEvent(parsed);
    process.stdout.write(JSON.stringify({
      event: result.event,
      canonicalEventBase64: result.bytes.toString('base64'),
      canonicalEventSha256: sha256(result.bytes).toString('hex'),
    }));
  } catch (error) {
    process.stderr.write(error instanceof Error ? error.message : 'Invalid event');
    process.exitCode = 2;
  }
}

  if (process.argv[2] === '--sha256-file') {
  try {
    if (!process.argv[3] || process.argv.length !== 4) throw new Error('expected one evidence file path');
    process.stdout.write(sha256(readFileSync(process.argv[3])).toString('hex'));
  } catch (error) {
    process.stderr.write(error instanceof Error ? error.message : 'Unable to hash evidence');
    process.exitCode = 2;
  }
} else if (process.argv[2] === '--merkle-batch' || process.argv[2] === '--merkle-context' || process.argv[2] === '--verify-proof' || process.argv[2] === '--verify-signature' || process.argv[2] === '--validate-key') {
  const input = await new Promise<string>((resolve, reject) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (part: string) => { data += part; });
    process.stdin.on('end', () => resolve(data));
    process.stdin.on('error', reject);
  });
  try {
    const parsed: unknown = JSON.parse(input);
    if (process.argv[2] === '--validate-key') {
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed) || typeof (parsed as { publicKeyDerBase64?: unknown }).publicKeyDerBase64 !== 'string') throw new TypeError('key request is incomplete');
      const der = Buffer.from((parsed as { publicKeyDerBase64: string }).publicKeyDerBase64, 'base64');
      const key = createPublicKey({ key: der, format: 'der', type: 'spki' });
      if (!(key.export({ format: 'der', type: 'spki' }) as Buffer).equals(der)) throw new TypeError('public key DER must use its canonical SPKI encoding');
      process.stdout.write(JSON.stringify({ keyId: publicKeyId(key), rawKeyHex: rawEd25519PublicKey(key).toString('hex') }));
    } else if (process.argv[2] === '--verify-proof') {
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new TypeError('proof request must be an object');
      const request = parsed as { canonicalEventBase64?: string; proof?: unknown; expectedRoot?: string };
      if (typeof request.canonicalEventBase64 !== 'string' || typeof request.expectedRoot !== 'string') throw new TypeError('proof request is incomplete');
      const bytes = Buffer.from(request.canonicalEventBase64, 'base64');
      process.stdout.write(JSON.stringify({ valid: verifyInclusionProof(bytes, request.proof as never, request.expectedRoot) }));
    } else if (process.argv[2] === '--verify-signature') {
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new TypeError('signature request must be an object');
      const request = parsed as { batch?: SignedBatch; signatureHex?: string; registration?: { keyId: string; publicKeyDerBase64: string; status: 'active' | 'revoked' } };
      if (!request.batch || typeof request.signatureHex !== 'string') throw new TypeError('signature request is incomplete');
      const registration = request.registration ? {
        keyId: request.registration.keyId,
        publicKeyDer: Buffer.from(request.registration.publicKeyDerBase64, 'base64'),
        status: request.registration.status,
      } : undefined;
      const result = verifyRegisteredBatchSignature(request.batch, Buffer.from(request.signatureHex, 'hex'), registration);
      process.stdout.write(JSON.stringify({ result }));
    } else {
      if (!Array.isArray(parsed)) throw new TypeError('batch input must be an array of events');
      const batch = buildMerkleBatch(parsed);
      const context = {
        treeVersion: TREE_VERSION,
        leafCount: batch.events.length,
        rootHash: batch.rootHash.toString('hex'),
        events: batch.events,
      };
      process.stdout.write(JSON.stringify(process.argv[2] === '--merkle-context' ? {
        ...context,
        leaves: batch.leaves.map((leaf) => leaf.toString('hex')),
        canonicalEventBase64: batch.canonicalEvents.map((value) => value.toString('base64')),
        proofs: batch.proofs,
      } : context));
    }
  } catch (error) {
    process.stderr.write(error instanceof Error ? error.message : 'Invalid Merkle batch');
    process.exitCode = 2;
  }
} else {
  await main();
}
