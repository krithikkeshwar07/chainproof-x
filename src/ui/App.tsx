import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity, Bell, Blocks, ChevronDown, ChevronRight, CircleHelp, FileCheck2, FileSearch,
  FileText, Fingerprint, GitBranch, Menu, Network, PanelLeftClose, PanelLeftOpen, Plus,
  Search, ShieldCheck, X, AlertCircle, LockKeyhole, Route,
} from 'lucide-react';
import {
  anchorCase, createCase, createInvestigation, getInvestigations, getTrustGraph, ingestEvidence, listAnchors, listCases, listEvidence, recomputeCorrelations, updateInvestigationStatus, verifyAnchor, verifyEvidence,
  authenticateApi, clearApiToken, downloadForensicReport, setApiUnauthorizedHandler,
  type AnchorVerification, type ApiRole, type BlockchainAnchor, type CaseSummary, type CorrelationRun, type EvidenceItem, type EvidencePage, type Investigation, type TrustGraph, type VerificationResult,
} from './api';
import {
  DemoGuidePage, ErrorPanel, EvidenceExplorerPage, type PageKey, type Resource,
  type VerificationState, InvestigationsPage, LedgerPage, LoadingPanel, OverviewPage,
  ReportsPage, TrustGraphPage, VerificationLabPage,
} from './pages';

const NAVIGATION: Array<{ key: PageKey; label: string; group: string; icon: typeof Activity }> = [
  { key: 'overview', label: 'Overview', group: 'WORKSPACE', icon: Activity },
  { key: 'evidence', label: 'Evidence explorer', group: 'WORKSPACE', icon: FileSearch },
  { key: 'investigations', label: 'Investigations', group: 'ANALYSIS', icon: GitBranch },
  { key: 'graph', label: 'Trust graph', group: 'ANALYSIS', icon: Network },
  { key: 'ledger', label: 'Blockchain ledger', group: 'VERIFICATION', icon: Blocks },
  { key: 'verification', label: 'Verification lab', group: 'VERIFICATION', icon: Fingerprint },
  { key: 'reports', label: 'Reports', group: 'OUTPUT', icon: FileText },
  { key: 'demo', label: 'Competition demo', group: 'OUTPUT', icon: Route },
];

const PAGE_INFO: Record<PageKey, { title: string; crumb: string }> = {
  overview: { title: 'Overview', crumb: 'Workspace' },
  evidence: { title: 'Evidence explorer', crumb: 'Workspace' },
  investigations: { title: 'Investigations', crumb: 'Analysis' },
  graph: { title: 'Trust graph', crumb: 'Analysis' },
  ledger: { title: 'Blockchain ledger', crumb: 'Verification' },
  verification: { title: 'Verification lab', crumb: 'Verification' },
  reports: { title: 'Reports', crumb: 'Output' },
  demo: { title: 'Competition demo', crumb: 'Output' },
};

interface Loadable<T> extends Resource<T> {}

export default function App() {
  const [page, setPage] = useState<PageKey>('overview');
  const [cases, setCases] = useState<Loadable<CaseSummary[]>>({ status: 'loading', data: null, error: null });
  const [activeCaseId, setActiveCaseId] = useState('');
  const [evidence, setEvidence] = useState<Loadable<EvidencePage>>({ status: 'ready', data: { items: [], total: 0, limit: 100, offset: 0 }, error: null });
  const [verifications, setVerifications] = useState<Record<string, VerificationState>>({});
  const [anchors, setAnchors] = useState<Loadable<BlockchainAnchor[]>>({ status: 'ready', data: [], error: null });
  const [anchorChecks, setAnchorChecks] = useState<Record<string, { status: 'loading' } | { status: 'ready'; result: AnchorVerification } | { status: 'error'; message: string }>>({});
  const [anchoring, setAnchoring] = useState<'idle' | 'loading' | 'error'>('idle');
  const [anchorError, setAnchorError] = useState<string | null>(null);
  const [graph, setGraph] = useState<Loadable<TrustGraph>>({ status: 'ready', data: null, error: null });
  const [investigations, setInvestigations] = useState<Loadable<Investigation[]>>({ status: 'ready', data: [], error: null });
  const [correlationRun, setCorrelationRun] = useState<'idle' | 'loading'>('idle');
  const [correlationError, setCorrelationError] = useState<string | null>(null);
  const [collapsed, setCollapsed] = useState(false);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [caseMenuOpen, setCaseMenuOpen] = useState(false);
  const [notificationOpen, setNotificationOpen] = useState(false);
  const [aboutOpen, setAboutOpen] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);
  const [query, setQuery] = useState('');
  const searchInput = useRef<HTMLInputElement>(null);
  const [dialog, setDialog] = useState<'case' | 'evidence' | null>(null);
  const [toast, setToast] = useState<string | null>(null);
  const [apiRole, setApiRole] = useState<ApiRole | null>(null);
  const [tokenInput, setTokenInput] = useState('');
  const [authError, setAuthError] = useState<string | null>(null);
  const [authBusy, setAuthBusy] = useState(false);
  const [reportError, setReportError] = useState<string | null>(null);

  const activeCase = cases.data?.find((item) => item.id === activeCaseId) ?? null;
  const demoMode = __CPX_DEMO_MODE__;
  const searchShortcut = navigator.userAgent.includes('Mac') ? '⌘ K' : 'Ctrl K';

  const reloadCases = useCallback(async () => {
    setCases((current) => ({ ...current, status: 'loading', error: null }));
    try {
      const data = await listCases();
      setCases({ status: 'ready', data, error: null });
      setActiveCaseId((current) => current && data.some((entry) => entry.id === current) ? current : data[0]?.id ?? '');
    } catch (error) {
      setCases((current) => ({ ...current, status: 'error', error: error instanceof Error ? error.message : 'Unable to load cases.' }));
    }
  }, []);

  useEffect(() => { if (apiRole) void reloadCases(); else clearApiToken(); }, [apiRole, reloadCases]);

  useEffect(() => {
    setApiUnauthorizedHandler(() => {
      setApiRole(null); setCases({ status: 'loading', data: null, error: null }); setActiveCaseId('');
      setEvidence({ status: 'ready', data: { items: [], total: 0, limit: 100, offset: 0 }, error: null });
      setAnchors({ status: 'ready', data: [], error: null }); setGraph({ status: 'ready', data: null, error: null });
      setInvestigations({ status: 'ready', data: [], error: null }); setVerifications({}); setAnchorChecks({});
    });
    return () => setApiUnauthorizedHandler(null);
  }, []);

  const reloadEvidence = useCallback(async () => {
    if (!activeCaseId) {
      setEvidence({ status: 'ready', data: { items: [], total: 0, limit: 100, offset: 0 }, error: null });
      return;
    }
    setEvidence({ status: 'loading', data: null, error: null });
    try {
      const data = await listEvidence(activeCaseId);
      setEvidence({ status: 'ready', data, error: null });
    } catch (error) {
      setEvidence((current) => ({ ...current, status: 'error', error: error instanceof Error ? error.message : 'Unable to load evidence.' }));
    }
  }, [activeCaseId]);

  useEffect(() => { void reloadEvidence(); }, [reloadEvidence]);
  useEffect(() => { setVerifications({}); }, [activeCaseId]);

  const reloadAnchors = useCallback(async () => {
    if (!activeCaseId) {
      setAnchors({ status: 'ready', data: [], error: null });
      return;
    }
    setAnchors({ status: 'loading', data: null, error: null });
    try {
      const data = await listAnchors(activeCaseId);
      setAnchors({ status: 'ready', data, error: null });
    } catch (error) {
      setAnchors((current) => ({ ...current, status: 'error', error: error instanceof Error ? error.message : 'Unable to load the blockchain ledger.' }));
    }
  }, [activeCaseId]);

  useEffect(() => { void reloadAnchors(); setAnchorChecks({}); setAnchoring('idle'); setAnchorError(null); }, [reloadAnchors]);

  const reloadGraph = useCallback(async () => {
    if (!activeCaseId) {
      setGraph({ status: 'ready', data: null, error: null });
      return;
    }
    setGraph({ status: 'loading', data: null, error: null });
    try {
      const data = await getTrustGraph(activeCaseId);
      setGraph({ status: 'ready', data, error: null });
    } catch (error) {
      setGraph((current) => ({ ...current, status: 'error', error: error instanceof Error ? error.message : 'Unable to load the trust graph.' }));
    }
  }, [activeCaseId]);

  useEffect(() => { void reloadGraph(); setCorrelationRun('idle'); setCorrelationError(null); }, [reloadGraph]);

  const reloadInvestigations = useCallback(async () => {
    if (!activeCaseId) {
      setInvestigations({ status: 'ready', data: [], error: null });
      return;
    }
    setInvestigations({ status: 'loading', data: null, error: null });
    try {
      const data = await getInvestigations(activeCaseId);
      setInvestigations({ status: 'ready', data, error: null });
    } catch (error) {
      setInvestigations((current) => ({ ...current, status: 'error', error: error instanceof Error ? error.message : 'Unable to load investigations.' }));
    }
  }, [activeCaseId]);

  useEffect(() => { void reloadInvestigations(); }, [reloadInvestigations]);

  useEffect(() => {
    const handleShortcut = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        setSearchOpen(true);
        searchInput.current?.focus();
      }
      if (event.key === 'Escape') setAboutOpen(false);
    };
    document.addEventListener('keydown', handleShortcut);
    return () => document.removeEventListener('keydown', handleShortcut);
  }, []);

  useEffect(() => {
    if (!toast) return;
    const timer = window.setTimeout(() => setToast(null), 4000);
    return () => window.clearTimeout(timer);
  }, [toast]);

  const evidenceItems = evidence.data?.items ?? [];
  const searchResults = useMemo(() => {
    const term = query.trim().toLocaleLowerCase();
    if (!term) return { cases: [] as CaseSummary[], evidence: [] as EvidenceItem[] };
    return {
      cases: (cases.data ?? []).filter((item) => item.name.toLocaleLowerCase().includes(term) || item.id.toLowerCase().includes(term)).slice(0, 4),
      evidence: evidenceItems.filter((item) => [item.filename, item.event_id, item.event_type, item.source_id, item.sha256].some((value) => value.toLocaleLowerCase().includes(term))).slice(0, 5),
    };
  }, [query, cases.data, evidenceItems]);

  const verify = useCallback(async (item: EvidenceItem) => {
    setVerifications((current) => ({ ...current, [item.evidence_id]: { status: 'loading' } }));
    try {
      const result: VerificationResult = await verifyEvidence(item.evidence_id);
      setVerifications((current) => ({ ...current, [item.evidence_id]: { status: 'ready', result } }));
    } catch (error) {
      setVerifications((current) => ({ ...current, [item.evidence_id]: { status: 'error', message: error instanceof Error ? error.message : 'Verification could not be completed.' } }));
    }
  }, []);

  const handleCreateCase = async (name: string) => {
    const created = await createCase(name);
    setCases((current) => ({ status: 'ready', data: [created, ...(current.data ?? [])], error: null }));
    setActiveCaseId(created.id);
    setVerifications({});
    setPage('overview');
    setDialog(null);
    setToast('Case record created');
  };

  const handleIngest = async (file: File, eventJson: string) => {
    if (!activeCase) throw new Error('Select a case before ingesting evidence.');
    await ingestEvidence(activeCase.id, file, eventJson);
    setDialog(null);
    setToast('Evidence record ingested');
    await Promise.all([reloadEvidence(), reloadCases()]);
  };

  const handleAnchor = async () => {
    if (!activeCase) return;
    setAnchoring('loading');
    setAnchorError(null);
    try {
      const randomBytes = crypto.getRandomValues(new Uint8Array(32));
      const batchId = Array.from(randomBytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
      await anchorCase(activeCase.id, batchId);
      setAnchoring('idle');
      await reloadAnchors();
    } catch (error) {
      setAnchoring('error');
      setAnchorError(error instanceof Error ? error.message : 'The local chain could not confirm the anchor.');
    }
  };

  const handleVerifyAnchor = async (anchor: BlockchainAnchor) => {
    setAnchorChecks((current) => ({ ...current, [anchor.batch_id]: { status: 'loading' } }));
    try {
      const result = await verifyAnchor(anchor.batch_id);
      const matches = result.batch_id === anchor.batch_id && result.merkle_root === anchor.merkle_root
        && result.chain_id === anchor.chain_id && result.contract_address.toLowerCase() === anchor.contract_address.toLowerCase()
        && result.sender_address.toLowerCase() === anchor.sender_address.toLowerCase()
        && result.tx_hash === anchor.tx_hash && result.block_number === anchor.block_number
        && result.block_hash === anchor.block_hash && result.anchored_at === anchor.anchored_at;
      if (!matches) throw new Error('Verified receipt does not match the recorded anchor metadata.');
      setAnchorChecks((current) => ({ ...current, [anchor.batch_id]: { status: 'ready', result } }));
    } catch (error) {
      setAnchorChecks((current) => ({ ...current, [anchor.batch_id]: { status: 'error', message: error instanceof Error ? error.message : 'Independent verification failed.' } }));
    }
  };

  const handleRecomputeCorrelations = async () => {
    if (!activeCase) return;
    setCorrelationRun('loading');
    setCorrelationError(null);
    try {
      const result: CorrelationRun = await recomputeCorrelations(activeCase.id);
      setCorrelationRun('idle');
      setToast(`Correlation rules completed · ${result.correlation_count} match${result.correlation_count === 1 ? '' : 'es'}`);
      await reloadGraph();
    } catch (error) {
      setCorrelationRun('idle');
      setCorrelationError(error instanceof Error ? error.message : 'Correlation rules could not be applied.');
    }
  };

  const handleCreateInvestigation = async (input: { title: string; summary: string; evidence_ids: string[]; correlation_ids: string[] }) => {
    if (!activeCase) throw new Error('Select a case before creating an investigation.');
    const created = await createInvestigation(activeCase.id, input);
    setInvestigations((current) => ({ status: 'ready', data: [created, ...(current.data ?? []).filter((entry) => entry.id !== created.id)], error: null }));
    await reloadGraph();
    setToast('Investigation record created');
  };

  const handleInvestigationStatus = async (item: Investigation) => {
    const updated = await updateInvestigationStatus(item.id, item.status === 'open' ? 'closed' : 'open');
    setInvestigations((current) => ({ ...current, data: (current.data ?? []).map((entry) => entry.id === updated.id ? updated : entry) }));
    await reloadGraph();
  };

  const handleConnect = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setAuthBusy(true); setAuthError(null);
    try {
      const role = await authenticateApi(tokenInput.trim());
      setApiRole(role); setTokenInput('');
    } catch (error) {
      setAuthError(error instanceof Error ? error.message : 'API authentication failed.');
    } finally { setAuthBusy(false); }
  };

  const handleSignOut = () => {
    clearApiToken(); setApiRole(null); setCases({ status: 'loading', data: null, error: null });
    setActiveCaseId(''); setEvidence({ status: 'ready', data: { items: [], total: 0, limit: 100, offset: 0 }, error: null });
    setAnchors({ status: 'ready', data: [], error: null }); setGraph({ status: 'ready', data: null, error: null });
    setInvestigations({ status: 'ready', data: [], error: null }); setVerifications({}); setAnchorChecks({});
  };

  const handleReportDownload = async (format: 'json' | 'html') => {
    if (!activeCase) return;
    setReportError(null);
    try {
      const blob = await downloadForensicReport(activeCase.id, format);
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url; link.download = `chainproof-report.${format}`; link.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (error) { setReportError(error instanceof Error ? error.message : 'Report download failed.'); }
  };

  const navigate = (destination: PageKey) => {
    setPage(destination);
    setMobileNavOpen(false);
    setSearchOpen(false);
    setQuery('');
  };

  const content = () => {
    if (cases.status === 'loading' && !cases.data) return <LoadingPanel label="Connecting to the ChainProof API…" />;
    if (cases.status === 'error' && !cases.data) return <ErrorPanel title="Workspace API unavailable" message={cases.error ?? 'Cases could not be loaded.'} onRetry={() => void reloadCases()} />;
    if (cases.status === 'error') return <ErrorPanel title="Case list may be out of date" message={cases.error ?? 'The API returned an error.'} onRetry={() => void reloadCases()} />;
    switch (page) {
      case 'overview': return <OverviewPage cases={cases.data ?? []} activeCase={activeCase} evidence={evidence} verifications={verifications} graph={graph} anchors={anchors} anchorChecks={anchorChecks} onCreateCase={() => setDialog('case')} onRetry={() => void reloadEvidence()} onNavigate={navigate} />;
      case 'evidence': return <EvidenceExplorerPage activeCase={activeCase} resource={evidence} verifications={verifications} onVerify={(item) => void verify(item)} onUpload={() => setDialog('evidence')} onRetry={() => void reloadEvidence()} />;
      case 'investigations': return <InvestigationsPage activeCase={activeCase} evidence={evidence} graph={graph} resource={investigations} onRetry={() => void reloadInvestigations()} onCreate={handleCreateInvestigation} onToggleStatus={handleInvestigationStatus} />;
      case 'graph': return <TrustGraphPage activeCase={activeCase} resource={graph} correlation={correlationRun} correlationError={correlationError} onRetry={() => void reloadGraph()} onRecompute={() => void handleRecomputeCorrelations()} />;
      case 'ledger': return <LedgerPage activeCase={activeCase} resource={anchors} verification={anchorChecks} anchoring={anchoring} anchorError={anchorError} onRetry={() => void reloadAnchors()} onAnchor={() => void handleAnchor()} onVerify={(anchor) => void handleVerifyAnchor(anchor)} />;
      case 'verification': return <VerificationLabPage activeCase={activeCase} resource={evidence} verifications={verifications} onVerify={(item) => void verify(item)} onRetry={() => void reloadEvidence()} />;
      case 'reports': return <ReportsPage activeCase={activeCase} error={reportError} onDownload={handleReportDownload} />;
      case 'demo': return demoMode ? <DemoGuidePage activeCase={activeCase} evidence={evidence} verifications={verifications} anchors={anchors} anchorChecks={anchorChecks} graph={graph} onNavigate={navigate} onDownload={handleReportDownload} reportError={reportError} /> : <OverviewPage cases={cases.data ?? []} activeCase={activeCase} evidence={evidence} verifications={verifications} graph={graph} anchors={anchors} anchorChecks={anchorChecks} onCreateCase={() => setDialog('case')} onRetry={() => void reloadEvidence()} onNavigate={navigate} />;
    }
  };

  if (!apiRole) return <ApiAccessGate token={tokenInput} error={authError} busy={authBusy} onToken={setTokenInput} onSubmit={handleConnect} />;

  return (
    <div className={`app-shell ${collapsed ? 'is-collapsed' : ''} ${mobileNavOpen ? 'mobile-nav-open' : ''}`}>
      {mobileNavOpen && <button className="mobile-scrim" aria-label="Close navigation" onClick={() => setMobileNavOpen(false)} />}
      <aside className="sidebar" aria-label="Primary navigation">
        <div className="brand-row"><div className="brand-mark"><ShieldCheck size={18} strokeWidth={1.8} /></div><div className="brand-name"><strong>ChainProof <span>X</span></strong><small>FORENSIC INTEGRITY</small></div><button className="icon-button sidebar-collapse" aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'} onClick={() => setCollapsed((value) => !value)}>{collapsed ? <PanelLeftOpen size={16} /> : <PanelLeftClose size={16} />}</button></div>
        <div className="sidebar-workspace"><span className="workspace-avatar">{demoMode ? 'D' : 'CP'}</span><div className="workspace-label"><strong>{demoMode ? 'Competition demo' : 'Local workspace'}</strong><small>{demoMode ? 'Synthetic · isolated data' : 'Evidence environment'}</small></div><span className="local-indicator" /></div>
        <nav className="sidebar-nav">
          {['WORKSPACE', 'ANALYSIS', 'VERIFICATION', 'OUTPUT'].map((group) => <div className="nav-group" key={group}><div className="nav-group-label">{group}</div>{NAVIGATION.filter((entry) => entry.group === group && (entry.key !== 'demo' || demoMode)).map(({ key, label, icon: Icon }) => <button key={key} className={`nav-item ${page === key ? 'active' : ''}`} aria-current={page === key ? 'page' : undefined} title={collapsed ? label : undefined} onClick={() => navigate(key)}><Icon size={17} strokeWidth={1.8} /><span>{label}</span>{page === key && <ChevronRight className="nav-current" size={14} />}</button>)}</div>)}
        </nav>
        <div className="sidebar-bottom"><div className="connection-card"><span className="connection-mark"><Activity size={14} /></span><div className="workspace-label"><strong>API connection</strong><small>{cases.status === 'error' ? 'Unavailable' : cases.status === 'loading' ? 'Connecting…' : 'Local · ready'}</small></div><span className={`connection-dot ${cases.status === 'ready' ? 'up' : ''}`} /></div><div className="sidebar-version"><span>CHAINPROOF X</span><span>v0.1.0</span></div></div>
      </aside>

      <div className="main-column">
        <header className="topbar">
          <div className="topbar-leading"><button className="icon-button mobile-menu" aria-label="Open navigation" onClick={() => setMobileNavOpen(true)}><Menu size={18} /></button><div className="breadcrumbs"><span>{PAGE_INFO[page].crumb}</span><ChevronRight size={13} /><strong>{PAGE_INFO[page].title}</strong></div></div>
          <div className="topbar-actions">
            <div className="search-wrap"><Search size={15} /><input ref={searchInput} aria-label="Global search" placeholder="Search cases or evidence" value={query} onFocus={() => setSearchOpen(true)} onChange={(event) => { setQuery(event.target.value); setSearchOpen(true); }} onKeyDown={(event) => { if (event.key === 'Escape') setSearchOpen(false); }} /><kbd>{searchShortcut}</kbd>{searchOpen && query.trim() && <SearchResults cases={searchResults.cases} evidence={searchResults.evidence} onCase={(id) => { setActiveCaseId(id); navigate('overview'); }} onEvidence={() => navigate('evidence')} onClose={() => setSearchOpen(false)} />}</div>
            <div className="case-select-wrap"><button className="case-select" aria-expanded={caseMenuOpen} aria-label="Select case" onClick={() => { setCaseMenuOpen((value) => !value); setNotificationOpen(false); }}><span className="case-select-icon"><FileCheck2 size={15} /></span><span className="case-select-copy"><small>ACTIVE CASE</small><strong>{activeCase?.name ?? 'No case selected'}</strong></span><ChevronDown size={14} /></button>{caseMenuOpen && <div className="popover case-popover"><div className="popover-heading">Cases in this workspace</div>{(cases.data ?? []).length ? (cases.data ?? []).map((item) => <button className="case-option" key={item.id} onClick={() => { setActiveCaseId(item.id); setVerifications({}); setCaseMenuOpen(false); }}><span className="case-option-icon"><FileCheck2 size={15} /></span><span><strong>{item.name}</strong><small>{item.evidence_count} evidence objects</small></span>{item.id === activeCaseId && <span className="selected-check">✓</span>}</button>) : <div className="popover-empty">No cases in the local database.</div>}<button className="popover-add" onClick={() => { setCaseMenuOpen(false); setDialog('case'); }}><Plus size={14} /> Create a case</button></div>}</div>
            <div className="notification-wrap"><button className={`icon-button notification-button ${notificationOpen ? 'selected' : ''}`} aria-label="Notifications" aria-expanded={notificationOpen} onClick={() => { setNotificationOpen((value) => !value); setCaseMenuOpen(false); }}><Bell size={17} /></button>{notificationOpen && <div className="popover notification-popover"><div className="popover-heading">Notifications</div><div className="notification-empty"><span className="empty-icon small"><Bell size={15} /></span><strong>No new notifications</strong><small>System alerts will appear here when available.</small></div></div>}</div>
            <span className="access-role-badge">{apiRole === 'analyst' ? 'ANALYST' : 'VIEWER'}</span><button className="text-button signout-button" onClick={handleSignOut}>Sign out</button><span className="topbar-divider" /><div className="notification-wrap"><button className="help-button" aria-label="About this workspace" aria-expanded={aboutOpen} title="About this workspace" onClick={() => { setAboutOpen((value) => !value); setCaseMenuOpen(false); setNotificationOpen(false); }}><CircleHelp size={16} /></button>{aboutOpen && <div className="popover notification-popover"><div className="popover-heading">About this workspace</div><div className="notification-empty"><strong>Integrity is not source truth</strong><small>Hashes, signatures, Merkle proofs, and chain receipts validate recorded bytes and commitments. They do not establish that original source logs are truthful or complete.</small></div></div>}</div>
          </div>
        </header>

        <main className="content-area">
          <div className="page-container">
            <div className="content-title-row"><div><div className="eyebrow title-eyebrow">CHAINPROOF X <span>/</span> {PAGE_INFO[page].crumb.toUpperCase()}</div><h1>{PAGE_INFO[page].title}</h1></div><div className="title-context"><span className="api-state"><span className={`status-dot ${cases.status === 'ready' ? 'status-dot-green' : cases.status === 'error' ? 'status-dot-red' : 'status-dot-muted'}`} />{cases.status === 'ready' ? 'LOCAL API' : cases.status === 'error' ? 'API OFFLINE' : 'CONNECTING'}</span><button className="icon-button refresh-button" aria-label="Refresh workspace data" onClick={() => { void Promise.all([reloadCases(), reloadEvidence(), reloadAnchors(), reloadGraph(), reloadInvestigations()]); }}><Activity size={16} /></button></div></div>
            <div className="page-content">{content()}</div>
            <footer className="app-footer"><span>ChainProof X <span className="footer-separator">/</span> local evidence workspace</span><span>Integrity results describe stored bytes, not source truth.</span></footer>
          </div>
        </main>
      </div>

      {dialog === 'case' && <CreateCaseDialog onClose={() => setDialog(null)} onCreate={handleCreateCase} />}
      {dialog === 'evidence' && <IngestDialog caseName={activeCase?.name ?? ''} onClose={() => setDialog(null)} onIngest={handleIngest} />}
      {toast && <div className="toast" role="status"><span className="toast-icon"><ShieldCheck size={15} /></span>{toast}<button aria-label="Dismiss notification" onClick={() => setToast(null)}><X size={14} /></button></div>}
    </div>
  );
}

function ApiAccessGate({ token, error, busy, onToken, onSubmit }: { token: string; error: string | null; busy: boolean; onToken: (value: string) => void; onSubmit: (event: React.FormEvent<HTMLFormElement>) => void }) {
  return <main className="access-gate"><form className="surface access-card" onSubmit={onSubmit}>
    <div className="brand-mark"><ShieldCheck size={19} strokeWidth={1.8} /></div><div className="eyebrow">CHAINPROOF X / API ACCESS</div><h1>Connect to this workspace</h1>
    <p>Enter a configured viewer or analyst token. It stays in memory for this tab and is cleared when you sign out or reload.</p>
    <label htmlFor="api-access-token">API access token</label><input id="api-access-token" type="password" autoComplete="new-password" minLength={43} maxLength={512} required value={token} onChange={(event) => onToken(event.target.value)} />
    {error && <div className="access-error" role="alert">{error}</div>}
    <button className="button button-primary" type="submit" disabled={busy || token.trim().length < 43}>{busy ? 'Checking token…' : 'Connect securely'}<LockKeyhole size={15} /></button>
    <small>Access is validated by the API. The browser does not save bearer tokens or signing keys.</small>
  </form></main>;
}

function SearchResults({ cases, evidence, onCase, onEvidence, onClose }: { cases: CaseSummary[]; evidence: EvidenceItem[]; onCase: (id: string) => void; onEvidence: () => void; onClose: () => void }) {
  const total = cases.length + evidence.length;
  return <div className="search-results" role="listbox" aria-label="Search results">
    {total === 0 ? <div className="search-empty"><Search size={15} />No matching cases or loaded evidence.</div> : <>
      {cases.length > 0 && <><div className="search-group-label">CASES</div>{cases.map((item) => <button key={item.id} className="search-result" onClick={() => { onCase(item.id); onClose(); }}><FileCheck2 size={15} /><span><strong>{item.name}</strong><small>{item.evidence_count} evidence objects</small></span></button>)}</>}
      {evidence.length > 0 && <><div className="search-group-label">CURRENT CASE EVIDENCE</div>{evidence.map((item) => <button key={item.evidence_id} className="search-result" onClick={() => { onEvidence(); onClose(); }}><FileSearch size={15} /><span><strong>{item.filename}</strong><small>{item.event_id} · {item.event_type}</small></span></button>)}</>}
      <div className="search-footnote">Search covers loaded cases and the active case only.</div>
    </>}
  </div>;
}

function CreateCaseDialog({ onClose, onCreate }: { onClose: () => void; onCreate: (name: string) => Promise<void> }) {
  const [name, setName] = useState('');
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);
  const submit = async (event: React.FormEvent) => {
    event.preventDefault(); setSaving(true); setError('');
    try { await onCreate(name.trim()); } catch (failure) { setError(failure instanceof Error ? failure.message : 'Case could not be created.'); setSaving(false); }
  };
  return <Modal title="Create case" eyebrow="CASE MANAGEMENT" onClose={onClose}><form onSubmit={submit} className="dialog-form"><p className="dialog-copy">Create a local case record to organize incoming evidence and normalized events.</p><label className="field-label" htmlFor="case-name">Case name</label><input id="case-name" className="text-control" autoFocus maxLength={120} required value={name} onChange={(event) => setName(event.target.value)} placeholder="e.g. North region access review" />{error && <div className="form-error" role="alert"><AlertCircle size={15} />{error}</div>}<div className="dialog-actions"><button type="button" className="button button-secondary" onClick={onClose}>Cancel</button><button className="button button-primary" disabled={saving || !name.trim()}>{saving ? 'Creating…' : 'Create case'}<ChevronRight size={15} /></button></div></form></Modal>;
}

function IngestDialog({ caseName, onClose, onIngest }: { caseName: string; onClose: () => void; onIngest: (file: File, event: string) => Promise<void> }) {
  const [file, setFile] = useState<File | null>(null);
  const [eventJson, setEventJson] = useState('');
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);
  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!file) { setError('Choose an original evidence file.'); return; }
    if (!eventJson.trim()) { setError('Provide the normalized event JSON for this evidence object.'); return; }
    setSaving(true); setError('');
    try { await onIngest(file, eventJson); } catch (failure) { setError(failure instanceof Error ? failure.message : 'Evidence could not be ingested.'); setSaving(false); }
  };
  return <Modal title="Ingest evidence" eyebrow="NEW EVIDENCE OBJECT" onClose={onClose} wide><form className="dialog-form ingest-form" onSubmit={submit}>
    <div className="dialog-context"><span className="context-icon"><FileCheck2 size={15} /></span><span>Adding to <strong>{caseName}</strong></span></div>
    <label className="field-label" htmlFor="evidence-file">Original evidence file</label><label className={`file-drop ${file ? 'has-file' : ''}`} htmlFor="evidence-file"><input id="evidence-file" type="file" onChange={(event) => setFile(event.target.files?.[0] ?? null)} /><span className="file-drop-icon">{file ? <FileCheck2 size={19} /> : <Plus size={19} />}</span><span><strong>{file?.name ?? 'Choose a file to preserve'}</strong><small>{file ? `${file.size.toLocaleString()} bytes · original bytes remain unchanged` : 'Up to 16 MB · uploaded bytes are stored separately from event fields'}</small></span><span className="browse-label">Browse</span></label>
    <div className="field-header"><label className="field-label" htmlFor="event-json">Event JSON · canonical or supported source format</label><button type="button" className="text-button" onClick={() => setEventJson(JSON.stringify({ eventId: 'evt-demo-001', sourceId: 'synthetic-source', occurredAt: '2026-10-10T12:00:00.000Z', eventType: 'example.event', actor: 'synthetic-user', target: 'synthetic-resource' }, null, 2))}>Use canonical synthetic example</button></div>
    <textarea id="event-json" className="code-control" spellCheck={false} value={eventJson} onChange={(event) => setEventJson(event.target.value)} placeholder={'Canonical cpx-event-v1 object, or source profile:\nwindows_event_v1: account + computer\nlinux_audit_v1: user + host\nnetwork_event_v1: hostname + destinationIp'} />
    <p className="subtle">Supported source profiles normalize deterministically; the uploaded original file remains stored byte-for-byte.</p>
    <div className="form-note"><LockKeyhole size={14} /><span>The JSON above is canonicalized into a separate event record. It does not replace or rewrite the selected file.</span></div>
    {error && <div className="form-error" role="alert"><AlertCircle size={15} />{error}</div>}
    <div className="dialog-actions"><button type="button" className="button button-secondary" onClick={onClose}>Cancel</button><button className="button button-primary" disabled={saving || !file}>{saving ? 'Hashing and storing…' : 'Ingest evidence'}<ChevronRight size={15} /></button></div>
  </form></Modal>;
}

function Modal({ title, eyebrow, onClose, wide = false, children }: { title: string; eyebrow: string; onClose: () => void; wide?: boolean; children: React.ReactNode }) {
  useEffect(() => {
    const handle = (event: KeyboardEvent) => { if (event.key === 'Escape') onClose(); };
    window.addEventListener('keydown', handle);
    return () => window.removeEventListener('keydown', handle);
  }, [onClose]);
  return <div className="modal-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}><section className={`dialog ${wide ? 'dialog-wide' : ''}`} role="dialog" aria-modal="true" aria-labelledby="dialog-title"><div className="dialog-heading"><div><div className="eyebrow">{eyebrow}</div><h2 id="dialog-title">{title}</h2></div><button className="icon-button" aria-label="Close dialog" onClick={onClose}><X size={17} /></button></div>{children}</section></div>;
}
