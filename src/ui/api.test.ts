import { afterEach, describe, expect, it, vi } from 'vitest';
import { createCase, listCases, listEvidence, verifyEvidence } from './api.ts';

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });
}

const caseValue = { id: 'case-01', name: 'Example', created_at: '2026-10-10T12:00:00Z', evidence_count: 1, event_count: 1 };
const eventValue = { eventId: 'evt-01', sourceId: 'source', occurredAt: '2026-10-10T11:00:00.000Z', eventType: 'login.success', actor: 'user', target: 'system' };
const evidenceValue = {
  evidence_id: 'ev-01', filename: 'auth.log', media_type: 'text/plain', byte_length: 5, sha256: 'a'.repeat(64),
  ingested_at: '2026-10-10T12:00:00Z', event_id: 'evt-01', source_id: 'source', occurred_at: eventValue.occurredAt,
  event_type: eventValue.eventType, canonical_event_sha256: 'b'.repeat(64), event: eventValue,
};

afterEach(() => vi.unstubAllGlobals());

describe('frontend API error handling', () => {
  it('reports the backend unavailable without hiding the failure', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('offline')));
    await expect(listCases()).rejects.toThrow('Unable to reach the ChainProof API');
  });

  it('rejects malformed JSON and structurally malformed successful responses', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(new Response('{broken', { status: 200 })));
    await expect(listCases()).rejects.toThrow('malformed JSON');

    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(json([{ ...caseValue, evidence_count: 'one' }])));
    await expect(listCases()).rejects.toThrow('malformed case list response');

    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(json({ items: [{ ...evidenceValue, sha256: 'not-a-hash' }], total: 1, limit: 50, offset: 0 })));
    await expect(listEvidence('case-01')).rejects.toThrow('malformed evidence list response');
  });

  it('rejects HTTP errors and verification responses that cannot establish a valid check', async () => {
    vi.stubGlobal('fetch', vi.fn()
      .mockResolvedValueOnce(json({ detail: 'case not found' }, 404))
      .mockResolvedValueOnce(json({ evidence_id: 'ev-01', valid: true, expected_sha256: 'a'.repeat(64), actual_sha256: '0'.repeat(64), expected_byte_length: 5, actual_byte_length: 5 }))
      .mockResolvedValueOnce(json({ evidence_id: 'ev-01', valid: 'true' })));
    await expect(listCases()).rejects.toThrow('case not found');
    await expect(verifyEvidence('ev-01')).rejects.toThrow('malformed verification response');
    await expect(verifyEvidence('ev-01')).rejects.toThrow('malformed verification response');
  });

  it('accepts the backend case-create contract, which omits list-only counts', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(json({
      id: 'case-new', name: 'New case', created_at: '2026-10-10T12:00:00Z',
    }, 201)));
    await expect(createCase('New case')).resolves.toEqual({
      id: 'case-new', name: 'New case', created_at: '2026-10-10T12:00:00Z', evidence_count: 0, event_count: 0,
    });
  });
});
