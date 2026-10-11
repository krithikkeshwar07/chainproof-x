import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { anchorCase, authenticateApi, clearApiToken, createCase, createInvestigation, downloadForensicReport, getInvestigations, getTrustGraph, listAnchors, listCases, listEvidence, recomputeCorrelations, updateInvestigationStatus, verifyAnchor, verifyEvidence, verifyEvidenceCandidate } from './api.ts';

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

const TEST_TOKEN = 'analyst-test-token-' + 'a'.repeat(50);

beforeEach(async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json({ role: 'analyst' })));
  await authenticateApi(TEST_TOKEN);
});
afterEach(() => { clearApiToken(); vi.unstubAllGlobals(); });

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

  it('submits candidate bytes to the real comparison endpoint and rejects malformed outcomes', async () => {
    const result = { evidence_id: 'ev-01', valid: false, expected_sha256: 'a'.repeat(64), actual_sha256: 'c'.repeat(64), expected_byte_length: 5, actual_byte_length: 4, failed_check: 'candidate_original_sha256', reason: 'candidate_digest_or_length_mismatch', checked_at: '2026-10-10T12:00:00Z', candidate_stored: false };
    const fetchMock = vi.fn().mockResolvedValueOnce(json(result)).mockResolvedValueOnce(json({ ...result, candidate_stored: true }));
    vi.stubGlobal('fetch', fetchMock);
    await expect(verifyEvidenceCandidate('ev-01', new File(['edit'], 'edited.log'))).resolves.toMatchObject({ valid: false, failed_check: 'candidate_original_sha256', candidate_stored: false });
    expect(fetchMock.mock.calls[0]?.[0]).toBe('/api/v1/evidence/ev-01/verify-candidate');
    await expect(verifyEvidenceCandidate('ev-01', new File(['edit'], 'edited.log'))).rejects.toThrow('malformed candidate verification response');
  });

  it('accepts the backend case-create contract, which omits list-only counts', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(json({
      id: 'case-new', name: 'New case', created_at: '2026-10-10T12:00:00Z',
    }, 201)));
    await expect(createCase('New case')).resolves.toEqual({
      id: 'case-new', name: 'New case', created_at: '2026-10-10T12:00:00Z', evidence_count: 0, event_count: 0,
    });
  });

  it('validates real anchor listings and rejects malformed blockchain metadata', async () => {
    const record = {
      batch_id: `0x${'1'.repeat(64)}`, case_id: 'case-01', merkle_root: `0x${'2'.repeat(64)}`,
      leaf_count: 1, tree_version: 'cpx-merkle-v1', chain_id: 31337,
      contract_address: `0x${'a'.repeat(40)}`, sender_address: `0x${'b'.repeat(40)}`,
      tx_hash: `0x${'3'.repeat(64)}`, block_number: 8, block_hash: `0x${'4'.repeat(64)}`,
      anchored_at: 1791633600, created_at: '2026-10-10T12:00:00Z', verification_status: 'recorded',
    };
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(json([record])).mockResolvedValueOnce(json([{ ...record, tx_hash: 'fake' }])).mockResolvedValueOnce(json([{ ...record, verification_status: 'verified' }])));
    await expect(listAnchors('case-01')).resolves.toEqual([record]);
    await expect(listAnchors('case-01')).rejects.toThrow('malformed blockchain ledger response');
    await expect(listAnchors('case-01')).rejects.toThrow('malformed blockchain ledger response');
  });

  it('sends a byte-sized batch ID and validates the independent verification response', async () => {
    const batchId = '1'.repeat(64);
    const result = {
      batch_id: `0x${batchId}`, merkle_root: `0x${'2'.repeat(64)}`, chain_id: 31337,
      contract_address: `0x${'a'.repeat(40)}`, sender_address: `0x${'b'.repeat(40)}`,
      tx_hash: `0x${'3'.repeat(64)}`, block_number: 8, block_hash: `0x${'4'.repeat(64)}`,
      anchored_at: 1791633600, verification_status: 'verified',
    };
    const fetchMock = vi.fn().mockResolvedValueOnce(json({ ...result, case_id: 'case-01', leaf_count: 1, tree_version: 'cpx-merkle-v1', created_at: '2026-10-10T12:00:00Z' })).mockResolvedValueOnce(json(result));
    vi.stubGlobal('fetch', fetchMock);
    await anchorCase('case-01', batchId);
    expect(fetchMock.mock.calls[0]?.[0]).toBe('/api/v1/cases/case-01/anchors');
    expect(JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body))).toEqual({ batch_id: `0x${batchId}` });
    await expect(verifyAnchor(`0x${batchId}`)).resolves.toEqual(result);
    expect(() => anchorCase('case-01', 'invalid')).toThrow('32 bytes');
  });

  it('reports offline and unsuccessful ledger verification responses as errors', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValueOnce(new TypeError('offline')).mockResolvedValueOnce(json({ detail: 'Hardhat node is unavailable' }, 503)));
    await expect(listAnchors('case-01')).rejects.toThrow('Unable to reach the ChainProof API');
    await expect(verifyAnchor(`0x${'1'.repeat(64)}`)).rejects.toThrow('Hardhat node is unavailable');
  });

  it('validates graph node and edge references and surfaces graph API failures', async () => {
    const graph = {
      case_id: 'case-01', correlation_count: 1,
      nodes: [{ id: 'event:e1', type: 'event', label: 'evt-1', details: 'source evidence' },
        { id: 'evidence:b1', type: 'evidence', label: 'auth.log', details: 'sha256 digest' }],
      edges: [{ id: 'event:e1->evidence:b1', source: 'event:e1', target: 'evidence:b1', relationship: 'derived_from', rule_id: null, explanation: 'Evidence reference', evidence_ids: ['b1'] }],
    };
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(json(graph)).mockResolvedValueOnce(json({ ...graph, edges: [{ ...graph.edges[0], target: 'missing' }] })).mockResolvedValueOnce(json({ detail: 'graph backend unavailable' }, 503)));
    await expect(getTrustGraph('case-01')).resolves.toEqual(graph);
    await expect(getTrustGraph('case-01')).rejects.toThrow('malformed trust graph response');
    await expect(getTrustGraph('case-01')).rejects.toThrow('graph backend unavailable');
  });

  it('submits deterministic correlation recomputation and rejects malformed rule responses', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(json({ case_id: 'case-01', rule_id: 'shared-entity-window-v1', rule_version: 1, window_seconds: 300, event_count: 3, correlation_count: 1, correlations: [] })).mockResolvedValueOnce(json({ case_id: 'case-01', rule_id: 'unknown-rule', rule_version: 99, window_seconds: 300, event_count: 3, correlation_count: 1 })));
    await expect(recomputeCorrelations('case-01')).resolves.toMatchObject({ rule_id: 'shared-entity-window-v1', correlation_count: 1 });
    await expect(recomputeCorrelations('case-01')).rejects.toThrow('malformed correlation result response');
  });

  it('validates investigation responses and reports unavailable services', async () => {
    const investigation = { id: 'inv-1', case_id: 'case-01', title: 'Review', summary: '', status: 'open', created_at: '2026-10-10T12:00:00Z', updated_at: '2026-10-10T12:00:00Z', evidence_ids: ['ev-01'], correlation_ids: ['c'.repeat(64)] };
    const fetchMock = vi.fn().mockResolvedValueOnce(json([investigation])).mockResolvedValueOnce(json({ ...investigation, evidence_ids: 'invalid' })).mockResolvedValueOnce(json(investigation, 201)).mockResolvedValueOnce(json({ ...investigation, status: 'closed' })).mockResolvedValueOnce(json({ detail: 'investigation backend unavailable' }, 503));
    vi.stubGlobal('fetch', fetchMock);
    await expect(getInvestigations('case-01')).resolves.toEqual([investigation]);
    await expect(getInvestigations('case-01')).rejects.toThrow('malformed investigation list response');
    await expect(createInvestigation('case-01', { title: 'Review', summary: '', evidence_ids: ['ev-01'], correlation_ids: ['c'.repeat(64)] })).resolves.toEqual(investigation);
    await expect(updateInvestigationStatus('inv-1', 'closed')).resolves.toMatchObject({ status: 'closed' });
    await expect(getInvestigations('case-01')).rejects.toThrow('investigation backend unavailable');
  });

  it('sends bearer credentials on requests and report downloads, and rejects denied exports', async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(json({ case_id: 'case-01' }, 200));
    vi.stubGlobal('fetch', fetchMock);
    await expect(downloadForensicReport('case-01', 'json')).resolves.toBeInstanceOf(Blob);
    expect(fetchMock.mock.calls[0]?.[1]?.headers).toBeInstanceOf(Headers);
    expect((fetchMock.mock.calls[0]?.[1]?.headers as Headers).get('Authorization')).toBe(`Bearer ${TEST_TOKEN}`);
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json({ detail: 'analyst role required' }, 403)));
    await expect(downloadForensicReport('case-01', 'html')).rejects.toThrow('analyst role required');
  });

  it('rejects an empty report body instead of presenting a blank file as success', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('', { status: 200 })));
    await expect(downloadForensicReport('case-01', 'html')).rejects.toThrow('empty report');
  });
});
