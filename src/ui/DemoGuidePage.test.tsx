import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { DemoGuidePage } from './pages';

afterEach(cleanup);

describe('competition demo walkthrough', () => {
  it('shows API-derived empty states without prefilled successful checks', () => {
    render(<DemoGuidePage
      activeCase={{ id: 'demo-1', name: 'DEMO · synthetic test', created_at: '2026-01-15T12:00:00Z', evidence_count: 0, event_count: 0 }}
      evidence={{ status: 'ready', data: { items: [], total: 0, limit: 100, offset: 0 }, error: null }}
      verifications={{}}
      anchors={{ status: 'ready', data: [], error: null }}
      anchorChecks={{}}
      graph={{ status: 'ready', data: { case_id: 'demo-1', nodes: [], edges: [], correlation_count: 0 }, error: null }}
      onNavigate={vi.fn()}
      onDownload={vi.fn()}
      reportError={null}
    />);

    expect(screen.getByText('0 evidence objects in current case')).toBeInTheDocument();
    expect(screen.getByText('Not run yet')).toBeInTheDocument();
    expect(screen.getByText('No transaction recorded')).toBeInTheDocument();
    expect(screen.getByText('0 correlation candidates loaded from the API')).toBeInTheDocument();
    expect(screen.getByText('On demand')).toBeInTheDocument();
    expect(screen.queryByText('Check passed')).not.toBeInTheDocument();
  });
});
