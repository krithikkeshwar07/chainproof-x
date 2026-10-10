import {
  AlertCircle,
  ArrowDownToLine,
  ArrowRight,
  Check,
  CheckCircle2,
  CircleDashed,
  Clock3,
  Database,
  FileCheck2,
  FileSearch,
  Fingerprint,
  GitBranch,
  LockKeyhole,
  Network,
  Plus,
  RefreshCw,
  ScanSearch,
  ShieldCheck,
  ShieldX,
  Waypoints,
} from 'lucide-react';
import { useState } from 'react';
import type { CaseSummary, EvidenceItem, EvidencePage, VerificationResult } from './api';
import { formatBytes, formatDate } from './api';

export type PageKey = 'overview' | 'evidence' | 'investigations' | 'graph' | 'ledger' | 'verification' | 'reports';

export interface Resource<T> {
  status: 'loading' | 'ready' | 'error';
  data: T | null;
  error: string | null;
}

interface OverviewProps {
  cases: CaseSummary[];
  activeCase: CaseSummary | null;
  evidence: Resource<EvidencePage>;
  onCreateCase: () => void;
  onRetry: () => void;
  onNavigate: (page: PageKey) => void;
}

export function OverviewPage({ cases, activeCase, evidence, onCreateCase, onRetry, onNavigate }: OverviewProps) {
  const evidenceCount = evidence.status === 'ready' ? evidence.data?.total : undefined;
  return (
    <div className="page-stack">
      <section className="overview-intro">
        <div>
          <div className="eyebrow"><span className="eyebrow-dot" /> EVIDENCE INTEGRITY WORKSPACE</div>
          <h2>Proof you can inspect.<br /><span>Records you can trace.</span></h2>
          <p>Preserve original evidence, normalize events deterministically, and verify the bytes when it matters.</p>
        </div>
        <div className="intro-mark" aria-hidden="true"><div className="intro-mark-ring ring-one" /><div className="intro-mark-ring ring-two" /><ShieldCheck size={33} strokeWidth={1.25} /></div>
      </section>

      <section className="metric-row" aria-label="Workspace counts">
        <Metric label="Cases in workspace" value={String(cases.length)} hint="Current local database" icon={<Database />} />
        <Metric label="Evidence in case" value={evidenceCount === undefined ? '—' : String(evidenceCount)} hint={activeCase?.name ?? 'Select a case'} icon={<FileCheck2 />} />
        <Metric label="Latest verification" value="Not run" hint="Checks run on request" icon={<Fingerprint />} subdued />
      </section>

      {evidence.status === 'error' && <ErrorPanel title="Evidence data could not be loaded" message={evidence.error ?? 'The API returned an error.'} onRetry={onRetry} />}
      {evidence.status === 'loading' && activeCase && <div className="surface loading-surface"><div className="skeleton skeleton-line wide" /><div className="skeleton skeleton-line" /><div className="skeleton skeleton-block" /><span className="subtle">Loading records from the local API…</span></div>}

      {!activeCase ? (
        <section className="empty-workspace surface">
          <div className="empty-icon"><Database size={20} /></div>
          <div className="eyebrow">NO CASE SELECTED</div>
          <h3>Start with a case record</h3>
          <p>Cases and evidence are read from the local ChainProof API. This workspace contains no seeded operational data.</p>
          <button className="button button-primary" onClick={onCreateCase}><Plus size={16} /> Create a case</button>
        </section>
      ) : (
        <div className="overview-grid">
          <section className="surface active-case-panel">
            <div className="section-heading">
              <div><div className="eyebrow">ACTIVE CASE</div><h3>{activeCase.name}</h3></div>
              <span className="case-id">{activeCase.id.slice(0, 8).toUpperCase()}</span>
            </div>
            <p className="case-summary">Evidence records attached to this case are verified against their stored SHA-256 digest on demand.</p>
            <div className="case-facts">
              <Fact label="Created" value={formatDate(activeCase.created_at)} />
              <Fact label="Evidence objects" value={evidenceCount === undefined ? 'Unavailable' : String(evidenceCount)} />
              <Fact label="Normalized events" value={String(activeCase.event_count)} />
            </div>
            <div className="case-actions">
              <button className="button button-primary" onClick={() => onNavigate('evidence')}><FileSearch size={16} /> Explore evidence</button>
              <span className="inline-status"><span className="status-dot status-dot-muted" /> Local workspace</span>
            </div>
          </section>
          <ImplementationPanel />
          <section className="surface recent-panel">
            <div className="section-heading">
              <div><div className="eyebrow">RECENT EVIDENCE</div><h3>Latest ingested objects</h3></div>
              <button className="text-button" onClick={() => onNavigate('evidence')}>View explorer <ArrowRight size={14} /></button>
            </div>
            {evidence.status === 'ready' && evidence.data?.items.length ? (
              <div className="recent-list">
                {evidence.data.items.slice(0, 4).map((item) => <EvidenceLine key={item.evidence_id} item={item} />)}
              </div>
            ) : evidence.status !== 'loading' && evidence.status !== 'error' ? (
              <div className="compact-empty"><CircleDashed size={18} /><span>No evidence has been ingested for this case.</span><button onClick={() => onNavigate('evidence')}>Open explorer</button></div>
            ) : null}
          </section>
          <IntegrityBoundary onNavigate={onNavigate} />
        </div>
      )}
    </div>
  );
}

interface EvidencePageProps {
  activeCase: CaseSummary | null;
  resource: Resource<EvidencePage>;
  verifications: Record<string, VerificationState>;
  onVerify: (item: EvidenceItem) => void;
  onUpload: () => void;
  onRetry: () => void;
}

export type VerificationState = { status: 'loading' } | { status: 'ready'; result: VerificationResult } | { status: 'error'; message: string };

export function EvidenceExplorerPage({ activeCase, resource, verifications, onVerify, onUpload, onRetry }: EvidencePageProps) {
  return (
    <div className="page-stack">
      <section className="page-lede">
        <div><div className="eyebrow">CASE RECORDS / EVIDENCE</div><h2>Evidence explorer</h2><p>Original bytes stay separate from their normalized event records.</p></div>
        <button className="button button-primary" onClick={onUpload} disabled={!activeCase}><Plus size={16} /> Ingest evidence</button>
      </section>
      {!activeCase ? <EmptyPanel icon={<Database />} title="Select a case to browse evidence" description="Choose a case from the top bar or create one to begin a new evidence record." /> : null}
      {activeCase && resource.status === 'loading' ? <LoadingPanel label="Loading evidence records…" /> : null}
      {activeCase && resource.status === 'error' ? <ErrorPanel title="Evidence could not be loaded" message={resource.error ?? 'The API returned an error.'} onRetry={onRetry} /> : null}
      {activeCase && resource.status === 'ready' && resource.data?.items.length === 0 ? (
        <EmptyPanel icon={<FileSearch />} title="No evidence in this case" description="Ingest a source file and its normalized event record. The original bytes are retained exactly as received." action={<button className="button button-secondary" onClick={onUpload}><Plus size={15} /> Add evidence</button>} />
      ) : null}
      {activeCase && resource.status === 'ready' && resource.data && resource.data.items.length > 0 ? (
        <section className="surface table-surface">
          <div className="table-toolbar"><div><strong>{resource.data.total}</strong><span> evidence object{resource.data.total === 1 ? '' : 's'}</span></div><span className="scope-label"><span className="status-dot status-dot-cyan" /> {activeCase.name}</span></div>
          <div className="table-scroll"><table><thead><tr><th>Object</th><th>Normalized event</th><th>Source</th><th>Ingested</th><th>Size</th><th>Digest check</th></tr></thead>
            <tbody>{resource.data.items.map((item) => <EvidenceRow key={item.evidence_id} item={item} state={verifications[item.evidence_id]} onVerify={() => onVerify(item)} />)}</tbody></table></div>
          <div className="table-footer"><span>Showing {resource.data.items.length} of {resource.data.total} records</span><span>SHA-256 is recomputed from the stored original on each check.</span></div>
        </section>
      ) : null}
      <div className="integrity-note"><LockKeyhole size={15} /><span>A matching digest supports byte integrity from recorded ingestion. It does not establish that the source log was truthful or complete.</span></div>
    </div>
  );
}

interface VerificationPageProps extends Pick<EvidencePageProps, 'activeCase' | 'resource' | 'verifications' | 'onVerify' | 'onRetry'> {}

export function VerificationLabPage({ activeCase, resource, verifications, onVerify, onRetry }: VerificationPageProps) {
  const [selected, setSelected] = useState('');
  const item = resource.data?.items.find((entry) => entry.evidence_id === selected) ?? resource.data?.items[0];
  const state = item ? verifications[item.evidence_id] : undefined;
  return (
    <div className="page-stack">
      <section className="page-lede"><div><div className="eyebrow">INTEGRITY / MANUAL CHECK</div><h2>Verification lab</h2><p>Recompute the digest of an ingested original file and compare it with its recorded digest.</p></div><span className="scope-label"><Fingerprint size={15} /> SHA-256</span></section>
      {!activeCase ? <EmptyPanel icon={<Fingerprint />} title="Select a case first" description="Verification runs against evidence already recorded in a case." /> : null}
      {activeCase && resource.status === 'loading' ? <LoadingPanel label="Loading evidence available for verification…" /> : null}
      {activeCase && resource.status === 'error' ? <ErrorPanel title="Evidence list is unavailable" message={resource.error ?? 'The API returned an error.'} onRetry={onRetry} /> : null}
      {activeCase && resource.status === 'ready' && !resource.data?.items.length ? <EmptyPanel icon={<Fingerprint />} title="Nothing to verify yet" description="Ingest an evidence object first. No verification result has been assumed or prefilled." /> : null}
      {activeCase && resource.status === 'ready' && item ? (
        <section className="verification-layout">
          <div className="surface verify-card">
            <div className="eyebrow">SELECT EVIDENCE OBJECT</div>
            <label className="field-label" htmlFor="verify-evidence">Evidence object</label>
            <select id="verify-evidence" className="select-control" value={item.evidence_id} onChange={(event) => setSelected(event.target.value)}>
              {resource.data!.items.map((candidate) => <option key={candidate.evidence_id} value={candidate.evidence_id}>{candidate.filename} · {candidate.event_id}</option>)}
            </select>
            <div className="digest-block"><span>Recorded SHA-256</span><code>{item.sha256}</code></div>
            <div className="digest-block"><span>Original size</span><code>{formatBytes(item.byte_length)}</code></div>
            <button className="button button-primary verify-button" onClick={() => onVerify(item)} disabled={state?.status === 'loading'}>
              {state?.status === 'loading' ? <RefreshCw className="spin" size={16} /> : <ScanSearch size={16} />}
              {state?.status === 'loading' ? 'Recomputing digest…' : 'Run SHA-256 check'}
            </button>
          </div>
          <VerificationResultPanel state={state} />
        </section>
      ) : null}
      <div className="integrity-note"><ShieldCheck size={15} /><span>This check compares stored bytes with the digest recorded at ingestion. It does not attest to source-log truth, collection completeness, or real-world events.</span></div>
    </div>
  );
}

export function InvestigationsPage() {
  return <FuturePage eyebrow="CORRELATION / RULE SETS" title="Investigations" icon={<GitBranch />} label="Correlation is not available yet" description="The backend does not yet implement cross-source event correlation or investigation records. This page will not display synthetic incidents or inferred relationships." />;
}

export function TrustGraphPage() {
  return <FuturePage eyebrow="RELATIONSHIPS / PROVENANCE" title="Trust graph" icon={<Network />} label="No graph records available" description="Graph nodes and edges must be backed by evidence and deterministic correlation results. Neither is implemented in this backend slice." />;
}

export function LedgerPage() {
  return <FuturePage eyebrow="ANCHORING / CHAIN RECEIPTS" title="Blockchain ledger" icon={<Waypoints />} label="No chain transactions recorded" description="Smart-contract anchoring is not implemented. There are no transaction hashes, blocks, or confirmations to display." strong />;
}

export function ReportsPage() {
  return <FuturePage eyebrow="EXPORT / REPRODUCIBILITY" title="Reports" icon={<ArrowDownToLine />} label="No reports generated" description="Reproducible report export is not implemented yet. No download is available until its inputs, versions, and output format can be reproduced." />;
}

export function ErrorPanel({ title, message, onRetry }: { title: string; message: string; onRetry?: () => void }) {
  return <div className="error-panel" role="alert"><AlertCircle size={17} /><div><strong>{title}</strong><span>{message}</span></div>{onRetry && <button className="button button-quiet" onClick={onRetry}><RefreshCw size={14} /> Retry</button>}</div>;
}

export function EmptyPanel({ icon, title, description, action }: { icon: React.ReactNode; title: string; description: string; action?: React.ReactNode }) {
  return <section className="surface empty-panel"><div className="empty-icon">{icon}</div><h3>{title}</h3><p>{description}</p>{action}</section>;
}

export function LoadingPanel({ label }: { label: string }) {
  return <section className="surface loading-panel" role="status"><div className="skeleton skeleton-line wide" /><div className="skeleton skeleton-line" /><div className="skeleton skeleton-block" /><span className="subtle">{label}</span></section>;
}

function Metric({ label, value, hint, icon, subdued = false }: { label: string; value: string; hint: string; icon: React.ReactNode; subdued?: boolean }) {
  return <div className="metric"><div className="metric-top"><span>{label}</span><i>{icon}</i></div><strong className={subdued ? 'metric-value muted-value' : 'metric-value'}>{value}</strong><small>{hint}</small></div>;
}

function Fact({ label, value }: { label: string; value: string }) {
  return <div className="fact"><span>{label}</span><strong>{value}</strong></div>;
}

function ImplementationPanel() {
  const items = [
    { label: 'Original byte storage', note: 'Content-addressed', icon: <Database size={15} />, status: 'ready' },
    { label: 'Canonical event record', note: 'Deterministic format', icon: <Fingerprint size={15} />, status: 'ready' },
    { label: 'Digest verification', note: 'On-demand check', icon: <ShieldCheck size={15} />, status: 'ready' },
    { label: 'Cross-source correlation', note: 'Not implemented', icon: <GitBranch size={15} />, status: 'unavailable' },
    { label: 'Smart-contract anchoring', note: 'Not implemented', icon: <Waypoints size={15} />, status: 'unavailable' },
  ];
  return <section className="surface implementation-panel"><div className="eyebrow">IMPLEMENTATION SCOPE</div><h3>Integrity pipeline</h3><div className="scope-list">{items.map((item) => <div className="scope-row" key={item.label}><span className="scope-icon">{item.icon}</span><span className="scope-label-text"><strong>{item.label}</strong><small>{item.note}</small></span><span className={`scope-state ${item.status}`}>{item.status === 'ready' ? 'Available' : 'Unavailable'}</span></div>)}</div></section>;
}

function IntegrityBoundary({ onNavigate }: { onNavigate: (page: PageKey) => void }) {
  return <section className="surface boundary-panel"><div className="boundary-head"><LockKeyhole size={16} /><strong>Integrity boundary</strong></div><p>Digest checks compare stored bytes with the value recorded at ingestion. They cannot establish that the original source log was truthful or complete.</p><button className="text-button" onClick={() => onNavigate('verification')}>Review verification scope <ArrowRight size={14} /></button></section>;
}

function EvidenceLine({ item }: { item: EvidenceItem }) {
  return <div className="recent-line"><div className="file-mark"><FileCheck2 size={16} /></div><div className="recent-main"><strong>{item.filename}</strong><span>{item.event_id} <span className="recent-separator">·</span> {item.event_type}</span></div><div className="recent-meta"><span>{formatBytes(item.byte_length)}</span><span>{formatDate(item.ingested_at)}</span></div></div>;
}

function EvidenceRow({ item, state, onVerify }: { item: EvidenceItem; state?: VerificationState; onVerify: () => void }) {
  return <tr>
    <td><div className="table-primary">{item.filename}</div><code className="hash-short">{item.sha256.slice(0, 12)}…</code></td>
    <td><div className="table-primary">{item.event_type}</div><code className="hash-short">{item.event_id}</code></td>
    <td>{item.source_id}</td>
    <td>{formatDate(item.ingested_at)}</td>
    <td>{formatBytes(item.byte_length)}</td>
    <td><div className="check-cell">{state?.status === 'ready' ? <span className={`check-result ${state.result.valid ? 'valid' : 'invalid'}`}><i>{state.result.valid ? <Check size={12} /> : <ShieldX size={12} />}</i>{state.result.valid ? 'Matches' : 'Mismatch'}</span> : state?.status === 'error' ? <span className="check-result invalid" title={state.message}>Check failed</span> : state?.status === 'loading' ? <span className="check-result pending"><RefreshCw size={12} className="spin" /> Checking</span> : <span className="check-result pending"><Clock3 size={12} /> Not checked</span>}<button className="verify-link" onClick={onVerify} disabled={state?.status === 'loading'}>{state?.status === 'ready' ? 'Recheck' : 'Verify'}</button></div></td>
  </tr>;
}

function VerificationResultPanel({ state }: { state?: VerificationState }) {
  if (!state || state.status === 'loading') return <section className="surface result-card"><div className="result-icon result-neutral"><CircleDashed size={21} /></div><div className="eyebrow">VERIFICATION RESULT</div><h3>{state?.status === 'loading' ? 'Check in progress' : 'No check run'}</h3><p>{state?.status === 'loading' ? 'The API is recomputing SHA-256 from the stored original object.' : 'Run a check to compare the file currently stored with its recorded digest.'}</p></section>;
  if (state.status === 'error') return <section className="surface result-card result-error"><div className="result-icon"><AlertCircle size={21} /></div><div className="eyebrow">VERIFICATION ERROR</div><h3>Result unavailable</h3><p>{state.message}</p></section>;
  return <section className={`surface result-card ${state.result.valid ? 'result-valid' : 'result-error'}`}>
    <div className="result-icon">{state.result.valid ? <CheckCircle2 size={22} /> : <ShieldX size={22} />}</div>
    <div className="eyebrow">ACTUAL API RESULT</div>
    <h3>{state.result.valid ? 'Digest matches' : state.result.reason ? 'Check incomplete' : 'Integrity mismatch'}</h3>
    <p>{state.result.valid ? 'The stored bytes match the SHA-256 digest and byte length recorded at ingestion.' : verificationReason(state.result.reason)}</p>
    <div className="result-details"><Fact label="Expected SHA-256" value={state.result.expected_sha256 ?? 'Unavailable'} /><Fact label="Observed SHA-256" value={state.result.actual_sha256 ?? 'Unavailable'} /><Fact label="Byte length" value={`${state.result.actual_byte_length ?? '—'} / ${state.result.expected_byte_length ?? '—'}`} /></div>
    <div className="result-boundary"><LockKeyhole size={14} /> A matching digest confirms byte consistency only, not source truth or completeness.</div>
  </section>;
}

function verificationReason(reason?: string | null): string {
  if (reason === 'stored_object_missing') return 'The metadata exists, but the content-addressed original file is missing.';
  if (reason === 'stored_object_exceeds_limit') return 'The stored object exceeds the configured evidence size limit.';
  return 'The stored bytes do not match their recorded digest or byte length.';
}

function FuturePage({ eyebrow, title, icon, label, description, strong = false }: { eyebrow: string; title: string; icon: React.ReactNode; label: string; description: string; strong?: boolean }) {
  return <div className="page-stack"><section className="page-lede"><div><div className="eyebrow">{eyebrow}</div><h2>{title}</h2><p>Capability status for this local workspace.</p></div><span className={`scope-label ${strong ? 'scope-label-warn' : ''}`}><span className="status-dot status-dot-muted" /> Not connected</span></section><section className="surface future-state"><div className="future-orbit"><div className="orbit-line orbit-line-a" /><div className="orbit-line orbit-line-b" /><div className="future-icon">{icon}</div><span className="orbit-node node-a" /><span className="orbit-node node-b" /></div><div className="eyebrow">NO OPERATIONAL DATA</div><h3>{label}</h3><p>{description}</p><span className="future-caption">This view will populate only from verified backend records.</span></section><div className="integrity-note"><LockKeyhole size={15} /><span>Demo data and simulated outcomes are not shown as live system records.</span></div></div>;
}
