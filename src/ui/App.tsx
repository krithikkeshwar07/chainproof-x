import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Activity, Bell, Blocks, ChevronDown, ChevronRight, CircleHelp, FileCheck2, FileSearch,
  FileText, Fingerprint, GitBranch, Menu, Network, PanelLeftClose, PanelLeftOpen, Plus,
  Search, ShieldCheck, X, AlertCircle, LockKeyhole,
} from 'lucide-react';
import {
  createCase, ingestEvidence, listCases, listEvidence, verifyEvidence,
  type CaseSummary, type EvidenceItem, type EvidencePage, type VerificationResult,
} from './api';
import {
  ErrorPanel, EvidenceExplorerPage, type PageKey, type Resource,
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
];

const PAGE_INFO: Record<PageKey, { title: string; crumb: string }> = {
  overview: { title: 'Overview', crumb: 'Workspace' },
  evidence: { title: 'Evidence explorer', crumb: 'Workspace' },
  investigations: { title: 'Investigations', crumb: 'Analysis' },
  graph: { title: 'Trust graph', crumb: 'Analysis' },
  ledger: { title: 'Blockchain ledger', crumb: 'Verification' },
  verification: { title: 'Verification lab', crumb: 'Verification' },
  reports: { title: 'Reports', crumb: 'Output' },
};

interface Loadable<T> extends Resource<T> {}

export default function App() {
  const [page, setPage] = useState<PageKey>('overview');
  const [cases, setCases] = useState<Loadable<CaseSummary[]>>({ status: 'loading', data: null, error: null });
  const [activeCaseId, setActiveCaseId] = useState('');
  const [evidence, setEvidence] = useState<Loadable<EvidencePage>>({ status: 'ready', data: { items: [], total: 0, limit: 100, offset: 0 }, error: null });
  const [verifications, setVerifications] = useState<Record<string, VerificationState>>({});
  const [collapsed, setCollapsed] = useState(false);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [caseMenuOpen, setCaseMenuOpen] = useState(false);
  const [notificationOpen, setNotificationOpen] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [dialog, setDialog] = useState<'case' | 'evidence' | null>(null);
  const [toast, setToast] = useState<string | null>(null);

  const activeCase = cases.data?.find((item) => item.id === activeCaseId) ?? null;

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

  useEffect(() => { void reloadCases(); }, [reloadCases]);

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
      case 'overview': return <OverviewPage cases={cases.data ?? []} activeCase={activeCase} evidence={evidence} onCreateCase={() => setDialog('case')} onRetry={() => void reloadEvidence()} onNavigate={navigate} />;
      case 'evidence': return <EvidenceExplorerPage activeCase={activeCase} resource={evidence} verifications={verifications} onVerify={(item) => void verify(item)} onUpload={() => setDialog('evidence')} onRetry={() => void reloadEvidence()} />;
      case 'investigations': return <InvestigationsPage />;
      case 'graph': return <TrustGraphPage />;
      case 'ledger': return <LedgerPage />;
      case 'verification': return <VerificationLabPage activeCase={activeCase} resource={evidence} verifications={verifications} onVerify={(item) => void verify(item)} onRetry={() => void reloadEvidence()} />;
      case 'reports': return <ReportsPage />;
    }
  };

  return (
    <div className={`app-shell ${collapsed ? 'is-collapsed' : ''} ${mobileNavOpen ? 'mobile-nav-open' : ''}`}>
      {mobileNavOpen && <button className="mobile-scrim" aria-label="Close navigation" onClick={() => setMobileNavOpen(false)} />}
      <aside className="sidebar" aria-label="Primary navigation">
        <div className="brand-row"><div className="brand-mark"><ShieldCheck size={18} strokeWidth={1.8} /></div><div className="brand-name"><strong>ChainProof <span>X</span></strong><small>FORENSIC INTEGRITY</small></div><button className="icon-button sidebar-collapse" aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'} onClick={() => setCollapsed((value) => !value)}>{collapsed ? <PanelLeftOpen size={16} /> : <PanelLeftClose size={16} />}</button></div>
        <div className="sidebar-workspace"><span className="workspace-avatar">CP</span><div className="workspace-label"><strong>Local workspace</strong><small>Evidence environment</small></div><span className="local-indicator" /></div>
        <nav className="sidebar-nav">
          {['WORKSPACE', 'ANALYSIS', 'VERIFICATION', 'OUTPUT'].map((group) => <div className="nav-group" key={group}><div className="nav-group-label">{group}</div>{NAVIGATION.filter((entry) => entry.group === group).map(({ key, label, icon: Icon }) => <button key={key} className={`nav-item ${page === key ? 'active' : ''}`} aria-current={page === key ? 'page' : undefined} title={collapsed ? label : undefined} onClick={() => navigate(key)}><Icon size={17} strokeWidth={1.8} /><span>{label}</span>{page === key && <ChevronRight className="nav-current" size={14} />}</button>)}</div>)}
        </nav>
        <div className="sidebar-bottom"><div className="connection-card"><span className="connection-mark"><Activity size={14} /></span><div className="workspace-label"><strong>API connection</strong><small>{cases.status === 'error' ? 'Unavailable' : cases.status === 'loading' ? 'Connecting…' : 'Local · ready'}</small></div><span className={`connection-dot ${cases.status === 'ready' ? 'up' : ''}`} /></div><div className="sidebar-version"><span>CHAINPROOF X</span><span>v0.1.0</span></div></div>
      </aside>

      <div className="main-column">
        <header className="topbar">
          <div className="topbar-leading"><button className="icon-button mobile-menu" aria-label="Open navigation" onClick={() => setMobileNavOpen(true)}><Menu size={18} /></button><div className="breadcrumbs"><span>{PAGE_INFO[page].crumb}</span><ChevronRight size={13} /><strong>{PAGE_INFO[page].title}</strong></div></div>
          <div className="topbar-actions">
            <div className="search-wrap"><Search size={15} /><input aria-label="Global search" placeholder="Search cases or evidence" value={query} onFocus={() => setSearchOpen(true)} onChange={(event) => { setQuery(event.target.value); setSearchOpen(true); }} onKeyDown={(event) => { if (event.key === 'Escape') setSearchOpen(false); }} /><kbd>⌘ K</kbd>{searchOpen && query.trim() && <SearchResults cases={searchResults.cases} evidence={searchResults.evidence} onCase={(id) => { setActiveCaseId(id); navigate('overview'); }} onEvidence={() => navigate('evidence')} onClose={() => setSearchOpen(false)} />}</div>
            <div className="case-select-wrap"><button className="case-select" aria-expanded={caseMenuOpen} aria-label="Select case" onClick={() => { setCaseMenuOpen((value) => !value); setNotificationOpen(false); }}><span className="case-select-icon"><FileCheck2 size={15} /></span><span className="case-select-copy"><small>ACTIVE CASE</small><strong>{activeCase?.name ?? 'No case selected'}</strong></span><ChevronDown size={14} /></button>{caseMenuOpen && <div className="popover case-popover"><div className="popover-heading">Cases in this workspace</div>{(cases.data ?? []).length ? (cases.data ?? []).map((item) => <button className="case-option" key={item.id} onClick={() => { setActiveCaseId(item.id); setVerifications({}); setCaseMenuOpen(false); }}><span className="case-option-icon"><FileCheck2 size={15} /></span><span><strong>{item.name}</strong><small>{item.evidence_count} evidence objects</small></span>{item.id === activeCaseId && <span className="selected-check">✓</span>}</button>) : <div className="popover-empty">No cases in the local database.</div>}<button className="popover-add" onClick={() => { setCaseMenuOpen(false); setDialog('case'); }}><Plus size={14} /> Create a case</button></div>}</div>
            <div className="notification-wrap"><button className={`icon-button notification-button ${notificationOpen ? 'selected' : ''}`} aria-label="Notifications" aria-expanded={notificationOpen} onClick={() => { setNotificationOpen((value) => !value); setCaseMenuOpen(false); }}><Bell size={17} /></button>{notificationOpen && <div className="popover notification-popover"><div className="popover-heading">Notifications</div><div className="notification-empty"><span className="empty-icon small"><Bell size={15} /></span><strong>No new notifications</strong><small>System alerts will appear here when available.</small></div></div>}</div>
            <span className="topbar-divider" /><button className="help-button" aria-label="About this workspace" title="About this workspace"><CircleHelp size={16} /></button>
          </div>
        </header>

        <main className="content-area">
          <div className="page-container">
            <div className="content-title-row"><div><div className="eyebrow title-eyebrow">CHAINPROOF X <span>/</span> {PAGE_INFO[page].crumb.toUpperCase()}</div><h1>{PAGE_INFO[page].title}</h1></div><div className="title-context"><span className="api-state"><span className={`status-dot ${cases.status === 'ready' ? 'status-dot-green' : cases.status === 'error' ? 'status-dot-red' : 'status-dot-muted'}`} />{cases.status === 'ready' ? 'LOCAL API' : cases.status === 'error' ? 'API OFFLINE' : 'CONNECTING'}</span><button className="icon-button refresh-button" aria-label="Refresh workspace data" onClick={() => { void reloadCases(); void reloadEvidence(); }}><Activity size={16} /></button></div></div>
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
    <div className="field-header"><label className="field-label" htmlFor="event-json">Normalized event JSON</label><button type="button" className="text-button" onClick={() => setEventJson(JSON.stringify({ eventId: 'evt-demo-001', sourceId: 'synthetic-source', occurredAt: '2026-10-10T12:00:00.000Z', eventType: 'example.event', actor: 'synthetic-user', target: 'synthetic-resource' }, null, 2))}>Use synthetic example</button></div>
    <textarea id="event-json" className="code-control" spellCheck={false} value={eventJson} onChange={(event) => setEventJson(event.target.value)} placeholder={'{\n  "eventId": "...",\n  "sourceId": "...",\n  "occurredAt": "2026-10-10T12:00:00.000Z",\n  "eventType": "...",\n  "actor": "...",\n  "target": "..."\n}'} />
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
