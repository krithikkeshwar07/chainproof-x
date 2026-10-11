import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import App from './App';
import { clearApiToken } from './api';

const TEST_TOKEN = 'analyst-test-token-' + 'a'.repeat(50);

const oneCase = {
  id: 'case-01', name: 'Access review', created_at: '2026-10-10T12:00:00Z', evidence_count: 1, event_count: 1,
};
const oneEvidence = {
  evidence_id: 'ev-01', filename: 'auth.log', media_type: 'text/plain', byte_length: 5,
  sha256: 'a'.repeat(64), ingested_at: '2026-10-10T12:01:00Z', event_id: 'evt-01',
  source_id: 'source-a', occurred_at: '2026-10-10T11:59:00Z', event_type: 'login.success',
  canonical_event_sha256: 'b'.repeat(64),
  event: { eventId: 'evt-01', sourceId: 'source-a', occurredAt: '2026-10-10T11:59:00Z', eventType: 'login.success', actor: 'user-1', target: 'system-1' },
};

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } });
}

function mockApi(options: { cases?: unknown; evidence?: unknown; fail?: boolean } = {}) {
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input);
    if (url.endsWith('/api/v1/session')) return json({ role: 'analyst' });
    if (options.fail && url.endsWith('/api/v1/cases')) throw new TypeError('offline');
    if (url.endsWith('/api/v1/evidence/ev-01/verify')) return json({ evidence_id: 'ev-01', valid: true, expected_sha256: 'a'.repeat(64), actual_sha256: 'a'.repeat(64), expected_byte_length: 5, actual_byte_length: 5 });
    if (url.includes('/anchors')) return json([]);
    if (url.includes('/trust-graph')) return json({ case_id: 'case-01', nodes: [], edges: [], correlation_count: 0 });
    if (url.includes('/investigations')) return json([]);
    if (url.includes('/correlations/recompute')) return json({ case_id: 'case-01', rule_id: 'shared-entity-window-v1', rule_version: 1, window_seconds: 300, event_count: 0, correlation_count: 0, correlations: [] });
    if (url.endsWith('/api/v1/cases')) return json(options.cases ?? [oneCase]);
    if (url.includes('/api/v1/cases/')) return json(options.evidence ?? { items: [oneEvidence], total: 1, limit: 100, offset: 0 });
    return json({ detail: 'Not found' }, 404);
  });
  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}

async function renderAuthenticatedApp() {
  const existingFetch = globalThis.fetch;
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => String(input).endsWith('/api/v1/session')
    ? json({ role: 'analyst' })
    : existingFetch(input, init)));
  render(<App />);
  fireEvent.change(screen.getByLabelText('API access token'), { target: { value: TEST_TOKEN } });
  fireEvent.click(screen.getByRole('button', { name: 'Connect securely' }));
  await screen.findByRole('button', { name: 'Sign out' });
  vi.stubGlobal('fetch', existingFetch);
}

describe('ChainProof X application shell', () => {
  beforeEach(() => { clearApiToken(); vi.unstubAllGlobals(); });
  afterEach(() => { cleanup(); clearApiToken(); vi.unstubAllGlobals(); });

  it('does not fetch case data until an API token is accepted', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => String(input).endsWith('/api/v1/session')
      ? json({ detail: 'valid ChainProof bearer token required' }, 401)
      : json([]));
    vi.stubGlobal('fetch', fetchMock);
    render(<App />);
    expect(fetchMock).not.toHaveBeenCalled();
    fireEvent.change(screen.getByLabelText('API access token'), { target: { value: TEST_TOKEN } });
    fireEvent.click(screen.getByRole('button', { name: 'Connect securely' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('valid ChainProof bearer token required');
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('renders API-backed case and evidence without prefilled verification', async () => {
    mockApi();
    await renderAuthenticatedApp();
    expect(await screen.findByRole('heading', { name: 'Overview' })).toBeInTheDocument();
    expect(await screen.findByText('auth.log')).toBeInTheDocument();
    expect(screen.getByText('Not run in session')).toBeInTheDocument();
    expect(screen.getByText('Checks run on request')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Competition demo' })).not.toBeInTheDocument();
  });

  it('shows an honest empty ledger state when no anchors are recorded', async () => {
    mockApi();
    const user = userEvent.setup();
    await renderAuthenticatedApp();
    await screen.findByText('auth.log');
    await user.click(screen.getAllByRole('button', { name: 'Blockchain ledger' })[0]!);
    expect(screen.getByText('No chain transactions recorded')).toBeInTheDocument();
    expect(screen.getByText(/running local Hardhat node and a deployed EvidenceRegistry/)).toBeInTheDocument();
  });

  it('creates an investigation linked to evidence and changes its actual API status', async () => {
    const investigation = { id: 'inv-01', case_id: oneCase.id, title: 'Review login', summary: 'Analyst notes', status: 'open', created_at: '2026-10-10T12:00:00Z', updated_at: '2026-10-10T12:00:00Z', evidence_ids: ['ev-01'], correlation_ids: [] };
    const fetchMock = mockApi();
    let created = false;
    fetchMock.mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith('/investigations') && init?.method === 'POST') { created = true; return json(investigation, 201); }
      if (url.includes('/investigations/inv-01/status')) return json({ ...investigation, status: 'closed', updated_at: '2026-10-10T12:05:00Z' });
      if (url.endsWith('/investigations')) return json(created ? [investigation] : []);
      if (url.endsWith('/trust-graph')) return json({ case_id: oneCase.id, nodes: [], edges: [], correlation_count: 0 });
      if (url.endsWith('/api/v1/cases')) return json([oneCase]);
      if (url.includes('/anchors')) return json([]);
      if (url.includes('/api/v1/cases/')) return json({ items: [oneEvidence], total: 1, limit: 100, offset: 0 });
      return json({ detail: 'Not found' }, 404);
    });
    const user = userEvent.setup();
    await renderAuthenticatedApp();
    await screen.findByText('auth.log');
    await user.click(screen.getAllByRole('button', { name: 'Investigations' })[0]!);
    await user.type(screen.getByLabelText('Title'), 'Review login');
    await user.type(screen.getByLabelText('Analyst summary'), 'Analyst notes');
    await user.click(screen.getByLabelText(/evt-01/));
    await user.click(screen.getByRole('button', { name: 'Create investigation' }));
    expect(await screen.findByText('Review login')).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/cases/case-01/investigations', expect.objectContaining({ method: 'POST' }));
    await user.click(screen.getByRole('button', { name: 'Close investigation' }));
    expect(await screen.findByText('CLOSED')).toBeInTheDocument();
  });

  it('shows investigation status update failures and retains the recorded status', async () => {
    const investigation = { id: 'inv-02', case_id: oneCase.id, title: 'Pending review', summary: '', status: 'open', created_at: '2026-10-10T12:00:00Z', updated_at: '2026-10-10T12:00:00Z', evidence_ids: [], correlation_ids: [] };
    const fetchMock = mockApi();
    fetchMock.mockImplementation(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes('/investigations/inv-02/status')) return json({ detail: 'investigation store unavailable' }, 503);
      if (url.endsWith('/investigations')) return json([investigation]);
      if (url.endsWith('/api/v1/cases')) return json([oneCase]);
      if (url.includes('/anchors')) return json([]);
      if (url.includes('/api/v1/cases/')) return json({ items: [oneEvidence], total: 1, limit: 100, offset: 0 });
      return json({ detail: 'Not found' }, 404);
    });
    const user = userEvent.setup();
    await renderAuthenticatedApp();
    await screen.findByText('auth.log');
    await user.click(screen.getAllByRole('button', { name: 'Investigations' })[0]!);
    await user.click(await screen.findByRole('button', { name: 'Close investigation' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('investigation store unavailable');
    expect(screen.getByRole('button', { name: 'Close investigation' })).toBeInTheDocument();
    expect(screen.getByText('OPEN')).toBeInTheDocument();
  });

  it('renders actual ledger records and only reports independent verification after the API confirms it', async () => {
    const batch = `0x${'1'.repeat(64)}`;
    const root = `0x${'2'.repeat(64)}`;
    const tx = `0x${'3'.repeat(64)}`;
    const block = `0x${'4'.repeat(64)}`;
    const address = `0x${'a'.repeat(40)}`;
    const anchor = { batch_id: batch, case_id: oneCase.id, merkle_root: root, leaf_count: 1, tree_version: 'cpx-merkle-v1', chain_id: 31337, contract_address: address, sender_address: address, tx_hash: tx, block_number: 7, block_hash: block, anchored_at: 1791633600, created_at: '2026-10-10T12:00:00Z', verification_status: 'recorded' };
    const fetchMock = mockApi();
    fetchMock.mockImplementation(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes('/anchors') && url.endsWith('/verify')) return json({ batch_id: batch, merkle_root: root, chain_id: 31337, contract_address: address, sender_address: address, tx_hash: tx, block_number: 7, block_hash: block, anchored_at: 1791633600, verification_status: 'verified' });
      if (url.includes('/anchors')) return json([anchor]);
      if (url.endsWith('/api/v1/cases')) return json([oneCase]);
      if (url.includes('/api/v1/cases/')) return json({ items: [oneEvidence], total: 1, limit: 100, offset: 0 });
      return json({ detail: 'Not found' }, 404);
    });
    const user = userEvent.setup();
    await renderAuthenticatedApp();
    await screen.findByText('auth.log');
    await user.click(screen.getAllByRole('button', { name: 'Blockchain ledger' })[0]!);
    expect(await screen.findByText(tx)).toBeInTheDocument();
    expect(screen.getByText(batch)).toBeInTheDocument();
    expect(screen.getByText(root)).toBeInTheDocument();
    expect(screen.getByText('Chain 31337')).toBeInTheDocument();
    expect(screen.getByText('Verification not run in this session')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Verify receipt' }));
    expect(await screen.findByText('Receipt independently verified')).toBeInTheDocument();
  });

  it('shows the chain offline error without displaying a fabricated transaction', async () => {
    const fetchMock = mockApi();
    fetchMock.mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.includes('/anchors') && init?.method === 'POST') return json({ detail: 'Hardhat node is offline' }, 503);
      if (url.includes('/anchors')) return json([]);
      if (url.endsWith('/api/v1/cases')) return json([oneCase]);
      if (url.includes('/api/v1/cases/')) return json({ items: [oneEvidence], total: 1, limit: 100, offset: 0 });
      return json({ detail: 'Not found' }, 404);
    });
    const user = userEvent.setup();
    await renderAuthenticatedApp();
    await screen.findByText('auth.log');
    await user.click(screen.getAllByRole('button', { name: 'Blockchain ledger' })[0]!);
    await user.click(screen.getByRole('button', { name: 'Anchor current events' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Hardhat node is offline');
    expect(screen.queryByText(/Transaction hash/)).not.toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/cases/case-01/anchors', expect.objectContaining({ method: 'POST' }));
  });

  it('shows a retryable error when graph data cannot be loaded', async () => {
    const fetchMock = mockApi();
    fetchMock.mockImplementation(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes('/trust-graph')) return json({ detail: 'graph service unavailable' }, 503);
      if (url.includes('/anchors')) return json([]);
      if (url.endsWith('/api/v1/cases')) return json([oneCase]);
      if (url.includes('/api/v1/cases/')) return json({ items: [oneEvidence], total: 1, limit: 100, offset: 0 });
      return json({ detail: 'Not found' }, 404);
    });
    const user = userEvent.setup();
    await renderAuthenticatedApp();
    await screen.findByText('auth.log');
    await user.click(screen.getAllByRole('button', { name: 'Trust graph' })[0]!);
    expect(await screen.findByRole('alert')).toHaveTextContent('graph service unavailable');
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/cases/case-01/trust-graph', expect.objectContaining({ headers: expect.any(Headers) }));
  });

  it('renders API-backed graph relationships and shows evidence and rule details on selection', async () => {
    const event = { eventId: 'evt-graph', sourceId: 'win-source', occurredAt: '2026-10-10T12:00:00.000Z', eventType: 'windows.logon', actor: 'ACME\\analyst', target: 'ws-01' };
    const graph = {
      case_id: oneCase.id, correlation_count: 1,
      nodes: [
        { id: 'event:r1', type: 'event', label: 'evt-graph', details: 'windows.logon', event, evidence_id: 'evidence-1', canonical_sha256: 'a'.repeat(64) },
        { id: 'evidence:evidence-1', type: 'evidence', label: 'auth.json', details: 'original bytes', evidence_id: 'evidence-1', sha256: 'b'.repeat(64) },
        { id: 'entity:host:1', type: 'entity', label: 'host: ws-01', details: 'normalized entity' },
        { id: 'incident:c1', type: 'incident', label: 'Correlation · host:ws-01', details: 'Two sources shared a host.', rule_id: 'shared-entity-window-v1', rule_version: 1, matched_entities: ['host:ws-01'], window_seconds: 300 },
      ],
      edges: [
        { id: 'edge:evidence', source: 'event:r1', target: 'evidence:evidence-1', relationship: 'derived_from', rule_id: null, explanation: 'Stored evidence reference.', evidence_ids: ['evidence-1'] },
        { id: 'edge:entity', source: 'event:r1', target: 'entity:host:1', relationship: 'references', rule_id: 'entity-normalization-v1', explanation: 'Host key from canonical target.', evidence_ids: ['evidence-1'] },
        { id: 'edge:incident', source: 'event:r1', target: 'incident:c1', relationship: 'correlated_by', rule_id: 'shared-entity-window-v1', explanation: 'Two sources shared a host within 300 seconds.', evidence_ids: ['evidence-1', 'evidence-2'] },
      ],
    };
    const fetchMock = mockApi();
    fetchMock.mockImplementation(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes('/trust-graph')) return json(graph);
      if (url.includes('/anchors')) return json([]);
      if (url.endsWith('/api/v1/cases')) return json([oneCase]);
      if (url.includes('/api/v1/cases/')) return json({ items: [oneEvidence], total: 1, limit: 100, offset: 0 });
      return json({ detail: 'Not found' }, 404);
    });
    const user = userEvent.setup();
    await renderAuthenticatedApp();
    await screen.findByText('auth.log');
    await user.click(screen.getAllByRole('button', { name: 'Trust graph' })[0]!);
    const eventNode = await screen.findByRole('button', { name: 'Events: evt-graph' });
    await user.click(eventNode);
    expect(screen.getByText('Evidence reference')).toBeInTheDocument();
    expect(screen.getByText('evidence-1')).toBeInTheDocument();
    expect(screen.getByText(/shared-entity-window-v1/)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /^Correlations 1$/ }));
    expect(screen.queryByRole('button', { name: /Correlations: Correlation/ })).not.toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/cases/case-01/trust-graph', expect.objectContaining({ headers: expect.any(Headers) }));
  });

  it('shows an API error state when the backend cannot be reached', async () => {
    const fetchMock = mockApi({ fail: true });
    await renderAuthenticatedApp();
    expect(await screen.findByRole('alert')).toHaveTextContent('Workspace API unavailable');
    expect(screen.getByText(/Unable to reach the ChainProof API/)).toBeInTheDocument();
    fetchMock.mockImplementation(async (input: RequestInfo | URL) => String(input).endsWith('/api/v1/session') ? json({ role: 'analyst' }) : json([]));
    await userEvent.setup().click(screen.getByRole('button', { name: 'Retry' }));
    expect((await screen.findAllByRole('heading', { name: 'Start with a case record' })).length).toBeGreaterThan(0);
  });

  it('shows verification API failures without retaining a previous success', async () => {
    const fetchMock = mockApi();
    const user = userEvent.setup();
    await renderAuthenticatedApp();
    await screen.findByText('auth.log');
    await user.click(screen.getAllByRole('button', { name: 'Verification lab' })[0]!);
    fetchMock.mockResolvedValueOnce(json({ detail: 'evidence not found' }, 404));
    await user.click(screen.getByRole('button', { name: 'Run SHA-256 check' }));
    expect(await screen.findByText('evidence not found')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Result unavailable' })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Digest matches' })).not.toBeInTheDocument();
  });

  it('renders a useful state rather than trusting malformed successful case data', async () => {
    mockApi({ cases: [{ ...oneCase, evidence_count: 'unknown' }] });
    await renderAuthenticatedApp();
    expect(await screen.findByRole('alert')).toHaveTextContent('malformed case list response');
  });

  it('shows verification only after the API returns its result', async () => {
    const fetchMock = mockApi();
    const user = userEvent.setup();
    await renderAuthenticatedApp();
    await screen.findByText('auth.log');
    await user.click(screen.getAllByRole('button', { name: 'Verification lab' })[0]!);
    await screen.findByRole('button', { name: 'Run SHA-256 check' });
    expect(screen.queryByRole('heading', { name: 'Digest matches' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Run SHA-256 check' }));
    expect(await screen.findByText('Digest matches')).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/evidence/ev-01/verify', expect.objectContaining({ headers: expect.any(Headers) }));
    expect(screen.getByText(/does not attest to source-log truth/)).toBeInTheDocument();
  });

  it('uses API verifier outcomes for Merkle checks and reports manifest omissions', async () => {
    const fetchMock = mockApi();
    fetchMock.mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith('/verification/context')) return json({ case_id: oneCase.id, tree_version: 'cpx-merkle-v1', leaf_count: 1, root_hash: 'c'.repeat(64), proofs: [{ event_id: oneEvidence.event_id, canonical_event_base64: 'e30=', canonical_sha256: 'b'.repeat(64), proof: { version: 'cpx-merkle-v1', leafIndex: 0, leafCount: 1, steps: [] } }] });
      if (url.endsWith('/verification/proof')) {
        const body = JSON.parse(String(init?.body)) as { proof: { leafCount: number } };
        const valid = body.proof.leafCount === 1;
        return json({ valid, failed_check: valid ? null : 'merkle_inclusion_proof', reason: valid ? 'proof_valid' : 'proof_malformed_or_root_mismatch', checked_at: '2026-10-10T12:00:00Z' });
      }
      if (url.endsWith('/expected-events')) return json({ manifest_id: 'manifest-1', expected_event_ids: ['evt-01', 'missing'] });
      if (url.endsWith('/completeness')) return json({ manifest_present: true, complete: false, missing_event_ids: ['missing'], unexpected_event_ids: [], reason: 'expected_events_missing' });
      if (url.endsWith('/api/v1/cases')) return json([oneCase]);
      if (url.includes('/anchors')) return json([]);
      if (url.includes('/trust-graph')) return json({ case_id: oneCase.id, nodes: [], edges: [], correlation_count: 0 });
      if (url.includes('/api/v1/cases/')) return json({ items: [oneEvidence], total: 1, limit: 100, offset: 0 });
      return json({ detail: 'Not found' }, 404);
    });
    const user = userEvent.setup();
    await renderAuthenticatedApp();
    await screen.findByText('auth.log');
    await user.click(screen.getAllByRole('button', { name: 'Verification lab' })[0]!);
    await user.click(screen.getByRole('button', { name: 'Load proof context' }));
    expect(await screen.findByText('c'.repeat(64))).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Verify altered proof' }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/api/v1/cases/case-01/verification/proof', expect.objectContaining({ method: 'POST' })));
    expect(await screen.findByText('Merkle proof: Failed')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Verify server proof' }));
    expect(await screen.findByText('Merkle proof: Valid')).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Expected event IDs (JSON array)'), { target: { value: '["evt-01", "missing"]' } });
    await user.click(screen.getByRole('button', { name: 'Save manifest and compare' }));
    expect(await screen.findByText(/Missing: missing/)).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/cases/case-01/verification/proof', expect.objectContaining({ method: 'POST' }));
  });

  it('offers JSON and HTML report downloads for the selected case', async () => {
    mockApi();
    const user = userEvent.setup();
    await renderAuthenticatedApp();
    await screen.findByText('auth.log');
    await user.click(screen.getAllByRole('button', { name: 'Reports' })[0]!);
    expect(screen.getByRole('button', { name: 'Download JSON' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Download HTML' })).toBeInTheDocument();
  });

  it('provides every requested navigation page', async () => {
    mockApi();
    const user = userEvent.setup();
    await renderAuthenticatedApp();
    await screen.findAllByText('auth.log');
    for (const [name, heading] of [
      ['Evidence explorer', 'Evidence explorer'], ['Investigations', 'Investigations'], ['Trust graph', 'Trust graph'],
      ['Blockchain ledger', 'Blockchain ledger'], ['Verification lab', 'Verification lab'], ['Reports', 'Reports'],
    ]) {
      await user.click(screen.getAllByRole('button', { name })[0]!);
      expect(screen.getAllByRole('heading', { name: heading }).length).toBeGreaterThan(0);
    }
  });
});
