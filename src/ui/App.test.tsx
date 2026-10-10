import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import App from './App';

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
    if (options.fail) throw new TypeError('offline');
    if (url.endsWith('/api/v1/evidence/ev-01/verify')) return json({ evidence_id: 'ev-01', valid: true, expected_sha256: 'a'.repeat(64), actual_sha256: 'a'.repeat(64), expected_byte_length: 5, actual_byte_length: 5 });
    if (url.endsWith('/api/v1/cases')) return json(options.cases ?? [oneCase]);
    if (url.includes('/api/v1/cases/')) return json(options.evidence ?? { items: [oneEvidence], total: 1, limit: 100, offset: 0 });
    return json({ detail: 'Not found' }, 404);
  });
  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}

describe('ChainProof X application shell', () => {
  beforeEach(() => vi.unstubAllGlobals());

  it('renders API-backed case and evidence without prefilled verification', async () => {
    mockApi();
    render(<App />);
    expect(await screen.findByRole('heading', { name: 'Overview' })).toBeInTheDocument();
    expect(await screen.findByText('auth.log')).toBeInTheDocument();
    expect(screen.getByText('Not run')).toBeInTheDocument();
    expect(screen.getByText('Checks run on request')).toBeInTheDocument();
  });

  it('shows honest empty states and no blockchain activity', async () => {
    mockApi({ cases: [] });
    const user = userEvent.setup();
    render(<App />);
    expect((await screen.findAllByRole('heading', { name: 'Start with a case record' })).length).toBeGreaterThan(0);
    await user.click(screen.getAllByRole('button', { name: 'Blockchain ledger' })[0]!);
    expect(screen.getByText('No chain transactions recorded')).toBeInTheDocument();
    expect(screen.getByText(/Smart-contract anchoring is not implemented/)).toBeInTheDocument();
  });

  it('shows an API error state when the backend cannot be reached', async () => {
    const fetchMock = vi.fn().mockRejectedValueOnce(new TypeError('offline'));
    vi.stubGlobal('fetch', fetchMock);
    render(<App />);
    expect(await screen.findByRole('alert')).toHaveTextContent('Workspace API unavailable');
    expect(screen.getByText(/Unable to reach the ChainProof API/)).toBeInTheDocument();
    fetchMock.mockImplementationOnce(async () => json([]));
    await userEvent.setup().click(screen.getByRole('button', { name: 'Retry' }));
    expect((await screen.findAllByRole('heading', { name: 'Start with a case record' })).length).toBeGreaterThan(0);
  });

  it('shows verification API failures without retaining a previous success', async () => {
    const fetchMock = mockApi();
    const user = userEvent.setup();
    render(<App />);
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
    render(<App />);
    expect(await screen.findByRole('alert')).toHaveTextContent('malformed case list response');
  });

  it('shows verification only after the API returns its result', async () => {
    const fetchMock = mockApi();
    const user = userEvent.setup();
    render(<App />);
    await screen.findByText('auth.log');
    await user.click(screen.getAllByRole('button', { name: 'Verification lab' })[0]!);
    await screen.findByRole('button', { name: 'Run SHA-256 check' });
    expect(screen.queryByRole('heading', { name: 'Digest matches' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Run SHA-256 check' }));
    expect(await screen.findByText('Digest matches')).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/evidence/ev-01/verify', undefined);
    expect(screen.getByText(/does not attest to source-log truth/)).toBeInTheDocument();
  });

  it('provides every requested navigation page', async () => {
    mockApi();
    const user = userEvent.setup();
    render(<App />);
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
