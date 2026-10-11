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
  Route,
  RefreshCw,
  ScanSearch,
  ShieldCheck,
  ShieldX,
  Waypoints,
} from 'lucide-react';
import { useState } from 'react';
import type { AnchorVerification, BlockchainAnchor, CaseSummary, CompletenessResult, EvidenceItem, EvidencePage, Investigation, MerkleContext, TrustGraph, TrustNodeType, VerificationResult } from './api';
import { formatBytes, formatDate, getCompleteness, getVerificationContext, registerSigningKey, setExpectedEvents, verifyBatchSignature, verifyEvidenceCandidate, verifyMerkleProof } from './api';

export type PageKey = 'overview' | 'evidence' | 'investigations' | 'graph' | 'ledger' | 'verification' | 'reports' | 'demo';

export interface Resource<T> {
  status: 'loading' | 'ready' | 'error';
  data: T | null;
  error: string | null;
}

interface OverviewProps {
  cases: CaseSummary[];
  activeCase: CaseSummary | null;
  evidence: Resource<EvidencePage>;
  verifications: Record<string, VerificationState>;
  graph: Resource<TrustGraph>;
  anchors: Resource<BlockchainAnchor[]>;
  anchorChecks: Record<string, { status: 'loading' } | { status: 'ready'; result: AnchorVerification } | { status: 'error'; message: string }>;
  onCreateCase: () => void;
  onRetry: () => void;
  onNavigate: (page: PageKey) => void;
}

export function OverviewPage({ cases, activeCase, evidence, verifications, graph, anchors, anchorChecks, onCreateCase, onRetry, onNavigate }: OverviewProps) {
  const evidenceCount = evidence.status === 'ready' ? evidence.data?.total : undefined;
  const activeEvidenceIds = new Set(evidence.data?.items.map((item) => item.evidence_id) ?? []);
  const latestVerification = Object.entries(verifications)
    .filter(([id, state]) => activeEvidenceIds.has(id) && state.status === 'ready')
    .map(([, state]) => state.status === 'ready' ? state.result : null)
    .filter((result): result is VerificationResult => result !== null)
    .sort((left, right) => (Date.parse(right.checked_at ?? '') || 0) - (Date.parse(left.checked_at ?? '') || 0))[0];
  const currentEvidenceStates = Object.entries(verifications).filter(([id]) => activeEvidenceIds.has(id)).map(([, state]) => state);
  const verificationPending = currentEvidenceStates.some((state) => state.status === 'loading');
  const verificationError = currentEvidenceStates.find((state) => state.status === 'error');
  const latestVerificationValue = verificationPending ? 'Checking' : verificationError ? 'Check unavailable'
    : latestVerification ? (latestVerification.valid ? 'Digest matched' : 'Mismatch') : 'Not run in session';
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
        <Metric label="Latest verification" value={latestVerificationValue} hint={verificationError?.status === 'error' ? verificationError.message : latestVerification?.checked_at ? formatDate(latestVerification.checked_at) : 'Checks run on request'} icon={<Fingerprint />} subdued={!latestVerification?.valid} />
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
          <ImplementationPanel activeCase={activeCase} evidence={evidence} graph={graph} anchors={anchors} anchorChecks={anchorChecks} />
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
  const [context, setContext] = useState<MerkleContext | null>(null);
  const [labError, setLabError] = useState<string | null>(null);
  const [labBusy, setLabBusy] = useState(false);
  const [proofResult, setProofResult] = useState<Record<string, unknown> | null>(null);
  const [signatureResult, setSignatureResult] = useState<Record<string, unknown> | null>(null);
  const [candidateResult, setCandidateResult] = useState<Record<string, unknown> | null>(null);
  const [candidateFile, setCandidateFile] = useState<File | null>(null);
  const [completeness, setCompleteness] = useState<CompletenessResult | null>(null);
  const [manifestText, setManifestText] = useState('');
  const [keyDer, setKeyDer] = useState('');
  const [keyId, setKeyId] = useState('');
  const [batchId, setBatchId] = useState('verification-lab');
  const [signature, setSignature] = useState('');
  const item = resource.data?.items.find((entry) => entry.evidence_id === selected) ?? resource.data?.items[0];
  const state = item ? verifications[item.evidence_id] : undefined;
  const run = async (action: () => Promise<unknown>, done: (result: any) => void) => {
    setLabBusy(true); setLabError(null);
    try { done(await action()); } catch (error) { setLabError(error instanceof Error ? error.message : 'Verification request failed.'); }
    finally { setLabBusy(false); }
  };
  const loadContext = () => activeCase && void run(() => getVerificationContext(activeCase.id), (value) => setContext(value));
  const checkProof = (altered = false) => {
    if (!activeCase || !item || !context) return;
    const entry = context.proofs.find((proof) => proof.event_id === item.event_id);
    if (!entry) { setLabError('No server-generated inclusion proof is available for this event.'); return; }
    const proof = structuredClone(entry.proof);
    if (altered) proof.leafCount = 0;
    void run(() => verifyMerkleProof(activeCase.id, item.event_id, context.root_hash, proof), setProofResult);
  };
  const checkSignature = (testInvalid = false) => {
    if (!activeCase || !context) return;
    const supplied = testInvalid ? '00'.repeat(64) : signature.trim();
    void run(() => verifyBatchSignature(activeCase.id, batchId.trim(), keyId.trim(), supplied), setSignatureResult);
  };
  const loadCompleteness = () => activeCase && void run(() => getCompleteness(activeCase.id), setCompleteness);
  const saveManifest = () => {
    if (!activeCase) return;
    void run(async () => {
      let ids: unknown;
      try { ids = JSON.parse(manifestText); } catch { throw new Error('Manifest must be a JSON array of event IDs.'); }
      if (!Array.isArray(ids) || !ids.every((value) => typeof value === 'string')) throw new Error('Manifest must be a JSON array of event IDs.');
      const saved = await setExpectedEvents(activeCase.id, ids);
      return getCompleteness(activeCase.id).then((result) => ({ ...result, manifest_id: saved.manifest_id }));
    }, setCompleteness);
  };
  return (
    <div className="page-stack">
      <section className="page-lede"><div><div className="eyebrow">INTEGRITY / MANUAL CHECK</div><h2>Verification lab</h2><p>Run backend checks against stored evidence, normalized event records, registered public keys, and an explicit expected-event manifest.</p></div><span className="scope-label"><Fingerprint size={15} /> SHA-256 · Ed25519 · Merkle</span></section>
      {!activeCase ? <EmptyPanel icon={<Fingerprint />} title="Select a case first" description="Verification runs against evidence already recorded in a case." /> : null}
      {activeCase && resource.status === 'loading' ? <LoadingPanel label="Loading evidence available for verification…" /> : null}
      {activeCase && resource.status === 'error' ? <ErrorPanel title="Evidence list is unavailable" message={resource.error ?? 'The API returned an error.'} onRetry={onRetry} /> : null}
      {activeCase && resource.status === 'ready' && !resource.data?.items.length ? <EmptyPanel icon={<Fingerprint />} title="Nothing to verify yet" description="Ingest an evidence object first. No verification result has been assumed or prefilled." /> : null}
      {activeCase && resource.status === 'ready' && item ? (
        <>
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
            <label className="field-label" htmlFor="evidence-candidate">Compare a candidate copy (does not modify stored evidence)</label>
            <input id="evidence-candidate" className="text-control file-control" type="file" onChange={(event) => setCandidateFile(event.target.files?.[0] ?? null)} />
            <button className="button button-secondary verify-button" disabled={!candidateFile || labBusy} onClick={() => candidateFile && void run(() => verifyEvidenceCandidate(item.evidence_id, candidateFile), setCandidateResult)}>Check candidate bytes</button>
            {candidateResult && <CheckResult result={candidateResult} title="Candidate evidence" />}
          </div>
          <VerificationResultPanel state={state} />
        </section>
        <section className="surface verify-card lab-checks">
          <div className="section-heading"><div><div className="eyebrow">MERKLE INCLUSION / SIGNATURE / COMPLETENESS</div><h3>Case verification checks</h3></div><button className="button button-secondary" onClick={loadContext} disabled={labBusy}>{labBusy ? 'Checking…' : context ? 'Refresh proof context' : 'Load proof context'}</button></div>
          {labError && <div className="verification-reason" role="alert">{labError}<button className="button button-quiet" onClick={context ? loadContext : onRetry}>Retry</button></div>}
          {context && <>
            <div className="digest-block"><span>Backend-computed root · {context.leaf_count} leaves</span><code>{context.root_hash}</code></div>
            <div className="lab-actions"><button className="button button-secondary" onClick={() => checkProof(false)} disabled={labBusy}>Verify server proof</button><button className="button button-secondary" onClick={() => checkProof(true)} disabled={labBusy}>Verify altered proof</button></div>
            {proofResult && <CheckResult result={proofResult} title="Merkle proof" />}
            <div className="lab-divider" />
            <div className="eyebrow">ED25519 SIGNATURE</div>
            <p className="subtle">Register only public SPKI DER in base64. Signatures are checked against this case’s current root and leaf count. The private key stays outside ChainProof X.</p>
            <label className="field-label" htmlFor="public-key-der">Public key DER (base64)</label><input id="public-key-der" className="text-control" value={keyDer} onChange={(event) => setKeyDer(event.target.value)} />
            <button className="button button-secondary lab-register" disabled={labBusy || !keyDer.trim()} onClick={() => void run(() => registerSigningKey(keyDer.trim()), (result) => { setKeyId(result.key_id); })}>Register public key</button>
            <label className="field-label" htmlFor="batch-id">Signed batch ID</label><input id="batch-id" className="text-control" value={batchId} onChange={(event) => setBatchId(event.target.value)} />
            <label className="field-label" htmlFor="key-id">Registered key ID</label><input id="key-id" className="text-control" value={keyId} onChange={(event) => setKeyId(event.target.value)} />
            <label className="field-label" htmlFor="signature-hex">Ed25519 signature (128 hex characters)</label><input id="signature-hex" className="text-control" value={signature} onChange={(event) => setSignature(event.target.value)} />
            <div className="lab-actions"><button className="button button-secondary" disabled={labBusy || !keyId || !signature || !batchId.trim()} onClick={() => checkSignature(false)}>Verify supplied signature</button><button className="button button-secondary" disabled={labBusy || !keyId || !batchId.trim()} onClick={() => checkSignature(true)}>Check invalid signature</button></div>
            {signatureResult && <CheckResult result={signatureResult} title="Ed25519 signature" />}
          </>}
          <div className="lab-divider" />
          <div className="section-heading"><div><div className="eyebrow">EXPECTED EVENT MANIFEST</div><h3>Completeness check</h3></div><button className="button button-quiet" onClick={loadCompleteness} disabled={labBusy}>Load status</button></div>
          <label className="field-label" htmlFor="expected-event-ids">Expected event IDs (JSON array)</label><textarea id="expected-event-ids" className="text-control manifest-control" value={manifestText} onChange={(event) => setManifestText(event.target.value)} placeholder='["evt-001", "evt-002"]' />
          <button className="button button-secondary" onClick={saveManifest} disabled={labBusy || !manifestText.trim()}>Save manifest and compare</button>
          {completeness && <div className="digest-block"><span>{completeness.reason ?? (completeness.complete ? 'Manifest satisfied' : 'Completeness unknown')}</span><code>Missing: {completeness.missing_event_ids.join(', ') || 'none'}</code><code>Unexpected: {completeness.unexpected_event_ids.join(', ') || 'none'}</code></div>}
        </section>
        </>
      ) : null}
      <div className="integrity-note"><ShieldCheck size={15} /><span>Each displayed result comes from the API’s verifier. A failed byte, signature, or proof check identifies a failed integrity claim; this does not attest to source-log truth. Completeness is meaningful only against a supplied manifest.</span></div>
    </div>
  );
}

function CheckResult({ result, title }: { result: Record<string, unknown>; title: string }) {
  const valid = result.valid === true;
  return <div className={`digest-block ${valid ? 'check-pass' : 'check-fail'}`} role="status"><strong>{title}: {valid ? 'Valid' : 'Failed'}</strong><code>Failed check: {String(result.failed_check ?? 'none')}</code><code>Reason: {String(result.reason ?? 'none')}</code><code>Checked at: {String(result.checked_at ?? 'unknown')}</code></div>;
}

export function InvestigationsPage({ activeCase, evidence, graph, resource, onRetry, onCreate, onToggleStatus }: {
  activeCase: CaseSummary | null;
  evidence: Resource<EvidencePage>;
  graph: Resource<TrustGraph>;
  resource: Resource<Investigation[]>;
  onRetry: () => void;
  onCreate: (input: { title: string; summary: string; evidence_ids: string[]; correlation_ids: string[] }) => Promise<void>;
  onToggleStatus: (item: Investigation) => Promise<void>;
}) {
  const [title, setTitle] = useState('');
  const [summary, setSummary] = useState('');
  const [selectedEvidence, setSelectedEvidence] = useState<string[]>([]);
  const [selectedCorrelations, setSelectedCorrelations] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [statusBusy, setStatusBusy] = useState('');
  const [statusError, setStatusError] = useState<string | null>(null);
  const correlations = (graph.data?.nodes ?? []).filter((node) => node.type === 'incident' && node.rule_id && node.id.startsWith('incident:'));
  const toggle = (values: string[], value: string, setValues: (next: string[]) => void) => {
    setValues(values.includes(value) ? values.filter((entry) => entry !== value) : [...values, value]);
  };
  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true); setError(null);
    try {
      await onCreate({ title, summary, evidence_ids: selectedEvidence, correlation_ids: selectedCorrelations });
      setTitle(''); setSummary(''); setSelectedEvidence([]); setSelectedCorrelations([]);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Investigation could not be saved.');
    } finally { setBusy(false); }
  };
  const toggleStatus = async (item: Investigation) => {
    setStatusBusy(item.id); setStatusError(null);
    try { await onToggleStatus(item); }
    catch (cause) { setStatusError(cause instanceof Error ? cause.message : 'Investigation status could not be updated.'); }
    finally { setStatusBusy(''); }
  };
  return <div className="page-stack">
    <section className="page-lede"><div><div className="eyebrow">CORRELATION / CASE WORKFLOW</div><h2>Investigations</h2><p>Record analyst review, link preserved evidence and deterministic correlation candidates, and track open or closed status.</p></div><span className="scope-label"><GitBranch size={15} /> Analyst-authored records</span></section>
    {!activeCase ? <EmptyPanel icon={<Database />} title="Select a case first" description="Investigations are scoped to the active case." /> : <>
      {resource.status === 'loading' && !resource.data?.length && <LoadingPanel label="Loading investigation records…" />}
      {resource.status === 'error' && <ErrorPanel title="Investigations unavailable" message={resource.error ?? 'The API could not load investigations.'} onRetry={onRetry} />}
      {statusError && <ErrorPanel title="Investigation status was not updated" message={statusError} />}
      <section className="surface verify-card">
        <div className="eyebrow">NEW INVESTIGATION · {activeCase.name}</div>
        <form onSubmit={(event) => void submit(event)} className="investigation-form">
          <label className="field-label" htmlFor="investigation-title">Title</label>
          <input id="investigation-title" className="text-control" value={title} onChange={(event) => setTitle(event.target.value)} maxLength={160} required />
          <label className="field-label" htmlFor="investigation-summary">Analyst summary</label>
          <textarea id="investigation-summary" className="text-control" value={summary} onChange={(event) => setSummary(event.target.value)} maxLength={4000} rows={3} />
          <div className="investigation-reference-grid">
            <fieldset><legend className="field-label">Evidence references</legend>
              {evidence.status === 'error' ? <span className="subtle">Evidence list unavailable. Retry before linking.</span> : evidence.data?.items.length ? evidence.data.items.map((item) => <label className="reference-option" key={item.evidence_id}><input type="checkbox" checked={selectedEvidence.includes(item.evidence_id)} onChange={() => toggle(selectedEvidence, item.evidence_id, setSelectedEvidence)} /><span>{item.event_id}<small>{item.filename} · {item.sha256.slice(0, 12)}…</small></span></label>) : <span className="subtle">No evidence objects loaded for this case.</span>}
            </fieldset>
            <fieldset><legend className="field-label">Rule correlations</legend>
              {graph.status === 'loading' ? <span className="subtle">Loading Trust Graph correlations…</span> : graph.status === 'error' ? <span className="subtle">Trust Graph unavailable; correlation references cannot be selected.</span> : correlations.length ? correlations.map((node) => { const id = node.id.slice('incident:'.length); return <label className="reference-option" key={node.id}><input type="checkbox" checked={selectedCorrelations.includes(id)} onChange={() => toggle(selectedCorrelations, id, setSelectedCorrelations)} /><span>{node.label}<small>{node.rule_id} · candidate relationship</small></span></label>; }) : <span className="subtle">No deterministic correlation candidates are available. Recompute them in Trust Graph first.</span>}
            </fieldset>
          </div>
          {error && <ErrorPanel title="Investigation was not saved" message={error} />}
          <button className="button button-primary" type="submit" disabled={busy || !title.trim()}><Plus size={15} />{busy ? 'Saving…' : 'Create investigation'}</button>
        </form>
      </section>
      {resource.status === 'ready' && resource.data?.length === 0 && <EmptyPanel icon={<GitBranch />} title="No investigations recorded" description="Create an analyst-authored investigation above. It will appear in Trust Graph and forensic report exports." />}
      {resource.data && resource.data.length > 0 && <section className="investigation-list" aria-label="Investigation records">{resource.data.map((item) => <article className="surface investigation-card" key={item.id}>
        <header><div><div className="eyebrow">INVESTIGATION · {item.id.slice(0, 8).toUpperCase()}</div><h3>{item.title}</h3></div><span className={`scope-label investigation-status ${item.status}`}>{item.status.toUpperCase()}</span></header>
        <p>{item.summary || 'No analyst summary supplied.'}</p>
        <div className="investigation-counts"><span>{item.evidence_ids.length} evidence reference{item.evidence_ids.length === 1 ? '' : 's'}</span><span>{item.correlation_ids.length} correlation candidate{item.correlation_ids.length === 1 ? '' : 's'}</span><span>Updated {formatDate(item.updated_at)}</span></div>
        <div className="investigation-references">{item.evidence_ids.map((id) => <code key={id}>Evidence {id}</code>)}{item.correlation_ids.map((id) => <code key={id}>Rule match {id}</code>)}</div>
        <button className="button button-secondary" onClick={() => void toggleStatus(item)} disabled={statusBusy === item.id}>{statusBusy === item.id ? 'Saving status…' : item.status === 'open' ? 'Close investigation' : 'Reopen investigation'}</button>
      </article>)}</section>}
      <div className="integrity-note"><LockKeyhole size={15} /><span>An investigation records analyst review. Linked correlation results are deterministic candidates and do not prove a causal relationship.</span></div>
    </>}
  </div>;
}

export function TrustGraphPage({ activeCase, resource, correlation, correlationError, onRetry, onRecompute }: {
  activeCase: CaseSummary | null;
  resource: Resource<TrustGraph>;
  correlation: 'idle' | 'loading';
  correlationError: string | null;
  onRetry: () => void;
  onRecompute: () => void;
}) {
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [visibleTypes, setVisibleTypes] = useState<Set<TrustNodeType>>(
    new Set(['case', 'organization', 'entity', 'evidence', 'event', 'incident']),
  );
  const typeLabels: Record<TrustNodeType, string> = {
    case: 'Cases', organization: 'Organizations', entity: 'Entities', evidence: 'Evidence', event: 'Events', incident: 'Correlations', investigation: 'Investigations',
  };
  const data = resource.data;
  const nodes = (data?.nodes ?? []).filter((node) => visibleTypes.has(node.type));
  const nodeById = new Map(nodes.map((node) => [node.id, node]));
  const edges = (data?.edges ?? []).filter((edge) => nodeById.has(edge.source) && nodeById.has(edge.target));
  const lanes: TrustNodeType[] = ['case', 'organization', 'entity', 'event', 'evidence', 'incident', 'investigation'];
  const positions = new Map<string, { x: number; y: number }>();
  const laneX: Record<TrustNodeType, number> = { case: 90, organization: 90, entity: 285, event: 500, evidence: 735, incident: 930, investigation: 1080 };
  for (const lane of lanes) {
    const members = nodes.filter((node) => node.type === lane);
    members.forEach((node, index) => positions.set(node.id, {
      x: laneX[lane], y: 52 + (lane === 'organization' ? 48 : 0) + index * 78,
    }));
  }
  const height = Math.max(390, ...lanes.map((lane) => nodes.filter((node) => node.type === lane).length * 78 + 90));
  const selected = nodes.find((node) => node.id === selectedId) ?? null;
  const relatedEdges = selected ? edges.filter((edge) => edge.source === selected.id || edge.target === selected.id) : [];
  const connectedIds = new Set(relatedEdges.map((edge) => edge.source === selected?.id ? edge.target : edge.source));
  const toggleType = (type: TrustNodeType) => setVisibleTypes((current) => {
    const next = new Set(current);
    if (next.has(type)) next.delete(type); else next.add(type);
    if (selected && !next.has(selected.type)) setSelectedId(null);
    return next;
  });

  return <div className="page-stack">
    <section className="page-lede">
      <div><div className="eyebrow">RELATIONSHIPS / PROVENANCE</div><h2>Trust graph</h2><p>Every displayed relationship links to an evidence object or an explicit case association and rule result.</p></div>
      <button className="button button-primary" onClick={onRecompute} disabled={!activeCase || correlation === 'loading'}><Network size={15} />{correlation === 'loading' ? 'Applying rules…' : 'Recompute correlations'}</button>
    </section>
    {!activeCase ? <EmptyPanel icon={<Database />} title="Select a case to view its graph" description="Graph records are scoped to the active case." /> : null}
    {activeCase && correlationError ? <ErrorPanel title="Correlation run failed" message={correlationError} onRetry={onRecompute} /> : null}
    {activeCase && resource.status === 'loading' ? <LoadingPanel label="Loading evidence-backed graph records…" /> : null}
    {activeCase && resource.status === 'error' ? <ErrorPanel title="Trust graph unavailable" message={resource.error ?? 'The API could not load graph records.'} onRetry={onRetry} /> : null}
    {activeCase && resource.status === 'ready' && data && data.nodes.length === 0 ? <EmptyPanel icon={<Network />} title="No graph records for this case" description="Ingest supported Windows, Linux audit, or network events. Organizations appear only when explicitly associated with the case." /> : null}
    {activeCase && resource.status === 'ready' && data && data.nodes.length > 0 ? <>
      <section className="surface graph-toolbar">
        <div><strong>{data.nodes.length}</strong><span> graph nodes</span><i /> <strong>{data.edges.length}</strong><span> relationships</span><i /> <strong>{data.correlation_count}</strong><span> rule correlations</span></div>
        <div className="graph-filters" aria-label="Graph node filters">{lanes.map((type) => <button key={type} className={visibleTypes.has(type) ? 'active' : ''} aria-pressed={visibleTypes.has(type)} onClick={() => toggleType(type)}>{typeLabels[type]} <span>{data.nodes.filter((node) => node.type === type).length}</span></button>)}</div>
      </section>
      <section className="graph-layout">
        <div className="surface graph-canvas" aria-label="Interactive trust graph">
          <svg viewBox={`0 0 1240 ${height}`} role="img" aria-label="Evidence, entity, event, investigation, and correlation relationships">
            {lanes.map((type) => <g key={`lane-${type}`} className="graph-lane"><text x={laneX[type]} y="24" textAnchor="middle">{typeLabels[type].toUpperCase()}</text><line x1={laneX[type]} y1="36" x2={laneX[type]} y2={height - 15} /></g>)}
            {edges.map((edge) => {
              const from = positions.get(edge.source); const to = positions.get(edge.target);
              if (!from || !to) return null;
              return <line key={edge.id} className={`graph-edge ${edge.rule_id ? 'rule-edge' : ''} ${selected && relatedEdges.some((item) => item.id === edge.id) ? 'selected-edge' : ''}`} x1={from.x + 68} y1={from.y + 19} x2={to.x + 68} y2={to.y + 19}><title>{edge.relationship}: {edge.explanation}</title></line>;
            })}
            {nodes.map((node) => {
              const point = positions.get(node.id)!;
              const active = selected?.id === node.id;
              const related = connectedIds.has(node.id);
              const label = node.label.length > 22 ? `${node.label.slice(0, 21)}…` : node.label;
              return <g key={node.id} className={`graph-node graph-node-${node.type} ${active ? 'selected' : ''} ${selected && !active && !related ? 'dimmed' : ''}`} transform={`translate(${point.x},${point.y})`} role="button" tabIndex={0} aria-label={`${typeLabels[node.type]}: ${node.label}`} aria-pressed={active} onClick={() => setSelectedId(node.id)} onKeyDown={(event) => { if (event.key === 'Enter' || event.key === ' ') setSelectedId(node.id); }}>
                <rect width="136" height="40" rx="6" />
                <text x="9" y="16" className="graph-node-kind">{node.type.toUpperCase()}</text>
                <text x="9" y="31" className="graph-node-label">{label}</text>
                <title>{node.label} — {node.details}</title>
              </g>;
            })}
          </svg>
        </div>
        <aside className="surface graph-inspector" aria-label="Selected graph node details">
          {!selected ? <div className="graph-inspector-empty"><Network size={18} /><strong>Select a graph node</strong><span>Evidence references and rule explanations appear here.</span></div> : <>
            <div className="eyebrow">SELECTED {selected.type.toUpperCase()}</div><h3>{selected.label}</h3><p>{selected.details}</p>
            {selected.event && <div className="graph-event-facts"><GraphFact label="Source" value={selected.event.sourceId} /><GraphFact label="Event type" value={selected.event.eventType} /><GraphFact label="Occurred at" value={selected.event.occurredAt} /><GraphFact label="Actor" value={selected.event.actor} /><GraphFact label="Target" value={selected.event.target} /></div>}
            {selected.evidence_id && <GraphFact label="Evidence reference" value={selected.evidence_id} />}
            {selected.canonical_sha256 && <GraphFact label="Canonical event SHA-256" value={selected.canonical_sha256} />}
            {selected.rule_id && <GraphFact label="Correlation rule" value={`${selected.rule_id} · v${selected.rule_version}`} />}
            {selected.matched_entities && <GraphFact label="Matched entity keys" value={selected.matched_entities.join(', ')} />}
            <div className="graph-linked"><div className="eyebrow">CONNECTED RELATIONSHIPS</div>{relatedEdges.length === 0 ? <span className="subtle">No visible relationships for this node.</span> : relatedEdges.map((edge) => <div className="graph-relation" key={edge.id}><strong>{edge.relationship}{edge.rule_id ? ` · ${edge.rule_id}` : ''}</strong><span>{edge.explanation}</span>{edge.evidence_ids.length > 0 && <small>Evidence: {edge.evidence_ids.join(', ')}</small>}</div>)}</div>
          </>}
        </aside>
      </section>
      <div className="integrity-note"><ShieldCheck size={15} /><span>Correlations are deterministic candidate relationships from the recorded rules and time window. They do not establish that a log is truthful, that collection is complete, or that related events were caused by the same actor.</span></div>
    </> : null}
  </div>;
}

function GraphFact({ label, value }: { label: string; value: string }) {
  return <div className="graph-fact"><span>{label}</span><code title={value}>{value}</code></div>;
}

export function LedgerPage({ activeCase, resource, verification, anchoring, anchorError, onRetry, onAnchor, onVerify }: {
  activeCase: CaseSummary | null;
  resource: Resource<BlockchainAnchor[]>;
  verification: Record<string, { status: 'loading' } | { status: 'ready'; result: AnchorVerification } | { status: 'error'; message: string }>;
  anchoring: 'idle' | 'loading' | 'error';
  anchorError: string | null;
  onRetry: () => void;
  onAnchor: () => void;
  onVerify: (anchor: BlockchainAnchor) => void;
  }) {
  return <div className="page-stack">
    <section className="page-lede">
      <div><div className="eyebrow">ANCHORING / CHAIN RECEIPTS</div><h2>Blockchain ledger</h2><p>Stored anchors show recorded metadata. Use Verify receipt to check the transaction and committed root against the local EvidenceRegistry.</p></div>
      <button className="button button-primary" onClick={onAnchor} disabled={!activeCase || anchoring === 'loading'}><Waypoints size={15} />{anchoring === 'loading' ? 'Anchoring…' : 'Anchor current events'}</button>
    </section>
    {!activeCase ? <EmptyPanel icon={<Database />} title="Select a case to view anchors" description="Ledger records are scoped to the active case." /> : null}
    {activeCase && anchoring === 'error' ? <ErrorPanel title="Anchoring failed" message={`${anchorError ?? 'The API or local Hardhat network did not confirm this anchor.'} No successful transaction is shown.`} onRetry={onAnchor} /> : null}
    {activeCase && resource.status === 'loading' ? <LoadingPanel label="Loading recorded chain anchors…" /> : null}
    {activeCase && resource.status === 'error' ? <ErrorPanel title="Blockchain ledger unavailable" message={resource.error ?? 'The API could not load the case ledger.'} onRetry={onRetry} /> : null}
    {activeCase && resource.status === 'ready' && resource.data?.length === 0 ? <EmptyPanel icon={<Waypoints />} title="No chain transactions recorded" description="No anchors are stored for this case. Anchoring requires a running local Hardhat node and a deployed EvidenceRegistry." /> : null}
    {activeCase && resource.status === 'ready' && resource.data && resource.data.length > 0 ? <section className="ledger-list" aria-label="Recorded blockchain anchors">
      {resource.data.map((anchor) => <article className="surface ledger-record" key={anchor.batch_id}>
        <div className="ledger-record-head"><div><div className="eyebrow">EVIDENCE REGISTRY ANCHOR</div><h3>Batch <code>{anchor.batch_id}</code></h3></div><span className="scope-label"><span className="status-dot status-dot-cyan" />Chain {anchor.chain_id}</span></div>
        <div className="ledger-fields">
          <LedgerField label="Contract address" value={anchor.contract_address} />
          <LedgerField label="Merkle root" value={anchor.merkle_root} />
          <LedgerField label="Transaction hash" value={anchor.tx_hash} />
          <LedgerField label="Block number" value={String(anchor.block_number)} />
          <LedgerField label="Leaf count / tree" value={`${anchor.leaf_count} / ${anchor.tree_version}`} />
          <LedgerField label="Recorded at (UTC)" value={new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'medium', timeZone: 'UTC' }).format(new Date(anchor.anchored_at * 1000))} />
        </div>
        <div className="ledger-record-footer">
          <span className={`ledger-verification ${verification[anchor.batch_id]?.status === 'ready' ? 'ledger-verified' : verification[anchor.batch_id]?.status === 'error' ? 'ledger-failed' : ''}`}>
            {ledgerVerificationText(verification[anchor.batch_id])}
          </span>
          <button className="button button-secondary" onClick={() => onVerify(anchor)} disabled={verification[anchor.batch_id]?.status === 'loading'}><ShieldCheck size={14} /> Verify receipt</button>
        </div>
      </article>)}
      <div className="integrity-note"><ShieldCheck size={15} /><span>A valid anchor proves that the recorded Merkle root was committed by this contract. It does not prove the source logs are truthful or complete.</span></div>
    </section> : null}
  </div>;
}

function LedgerField({ label, value }: { label: string; value: string }) {
  return <div className="ledger-field"><span>{label}</span><code title={value}>{value}</code></div>;
}

function ledgerVerificationText(state: { status: 'loading' } | { status: 'ready'; result: AnchorVerification } | { status: 'error'; message: string } | undefined): string {
  if (!state) return 'Verification not run in this session';
  if (state.status === 'loading') return 'Checking receipt…';
  if (state.status === 'ready') return 'Receipt independently verified';
  return `Verification failed: ${state.message}`;
}

export function ReportsPage({ activeCase, error, onDownload }: { activeCase: CaseSummary | null; error: string | null; onDownload: (format: 'json' | 'html') => void }) {
  return <div className="page-stack"><section className="page-lede"><div><div className="eyebrow">EXPORT / REPRODUCIBILITY</div><h2>Forensic report</h2><p>Download a point-in-time report assembled from recorded case data and fresh evidence-byte checks.</p></div><span className="scope-label"><ArrowDownToLine size={15} /> JSON · HTML</span></section>
    {!activeCase ? <EmptyPanel icon={<FileCheck2 />} title="Select a case first" description="Reports are generated for a selected case." /> : <section className="surface verify-card report-export"><div className="eyebrow">{activeCase.name}</div><code>{activeCase.id}</code><p>Both exports include evidence identifiers and hashes, current byte-integrity checks, normalized events, Merkle proofs, recorded signature/proof checks, stored blockchain transaction references, correlations, manifest completeness, timestamps, and limitations.</p><ReportDownloadButtons onDownload={onDownload} error={error} /></section>}
    <div className="integrity-note"><ShieldCheck size={15} /><span>Blockchain references are reported as stored metadata; this export does not re-query the chain. Reports explicitly state that evidence integrity cannot establish source truth or completeness.</span></div>
  </div>;
}

function ReportDownloadButtons({ onDownload, error }: { onDownload: (format: 'json' | 'html') => void; error: string | null }) {
  return <><div className="lab-actions"><button className="button button-secondary" onClick={() => onDownload('json')}><ArrowDownToLine size={15} /> Download JSON</button><button className="button button-secondary" onClick={() => onDownload('html')}><ArrowDownToLine size={15} /> Download HTML</button></div>{error && <div className="error-panel report-download-error" role="alert"><AlertCircle size={16} /><div><strong>Report download failed</strong><span>{error}</span></div></div>}</>;
}

export function DemoGuidePage({ activeCase, evidence, verifications, anchors, anchorChecks, graph, onNavigate, onDownload, reportError }: {
  activeCase: CaseSummary | null;
  evidence: Resource<EvidencePage>;
  verifications: Record<string, VerificationState>;
  anchors: Resource<BlockchainAnchor[]>;
  anchorChecks: Record<string, { status: 'loading' } | { status: 'ready'; result: AnchorVerification } | { status: 'error'; message: string }>;
  graph: Resource<TrustGraph>;
  onNavigate: (page: PageKey) => void;
  onDownload: (format: 'json' | 'html') => void;
  reportError: string | null;
}) {
  const isScenario = activeCase?.name.startsWith('DEMO ·') ?? false;
  const evidenceItems = evidence.data?.items ?? [];
  const hasVerifiedEvidence = evidenceItems.some((item) => {
    const state = verifications[item.evidence_id];
    return state?.status === 'ready' && state.result.valid;
  });
  const hasVerifiedAnchor = (anchors.data ?? []).some((anchor) => {
    const state = anchorChecks[anchor.batch_id];
    return state?.status === 'ready' && state.result.verification_status === 'verified';
  });
  const verificationText = evidence.status === 'error' ? 'Evidence API unavailable'
    : evidence.status === 'loading' ? 'Loading evidence state…'
      : hasVerifiedEvidence ? 'A real evidence integrity check passed'
        : Object.values(verifications).some((state) => state.status === 'ready') ? 'A real check failed; inspect its reason in Verification Lab'
          : 'Not run yet';
  const anchorText = anchors.status === 'error' ? 'Ledger unavailable'
    : anchors.status === 'loading' ? 'Loading ledger state…'
      : hasVerifiedAnchor ? 'Receipt independently verified'
        : anchors.data?.length ? 'Real transaction recorded; receipt check pending'
          : 'No transaction recorded';
  const graphText = graph.status === 'error' ? 'Trust Graph unavailable'
    : graph.status === 'loading' ? 'Loading graph state…'
      : graph.data ? `${graph.data.correlation_count} correlation candidate${graph.data.correlation_count === 1 ? '' : 's'} loaded from the API`
        : 'No graph data loaded';

  return <div className="page-stack demo-guide">
    <section className="demo-banner"><div className="demo-banner-icon"><Route size={17} /></div><div><div className="eyebrow">SYNTHETIC DATA · ISOLATED DATABASE AND CHAIN</div><strong>Competition demo scenario</strong><p>Only use the case labeled <b>DEMO ·</b>. The demo stack stores its database, evidence objects, deployment metadata, and Hardhat chain under separate local paths. No result on this page is prefilled.</p></div><span className="demo-badge">DEMO MODE</span></section>
    {!isScenario && <div className="demo-selection-note" role="status">{activeCase ? 'The selected case is not the seeded synthetic scenario. Select the case beginning “DEMO ·” to follow this walkthrough.' : 'The synthetic scenario has not been seeded. Stop here, then run the documented reset, demo stack, and seed commands.'}</div>}
    <section className="page-lede"><div><div className="eyebrow">GUIDED WORKFLOW / REAL API CHECKS</div><h2>Follow the evidence path</h2><p>Seed once, then perform each check explicitly. Seeding creates no signature result or blockchain transaction; this guide shows those only after the corresponding real checks.</p></div><span className="scope-label"><ShieldCheck size={15} /> No assumed results</span></section>
    <ol className="demo-steps">
      <DemoStep number="01" title="Ingest the synthetic source events" status={evidence.status === 'error' ? 'API error' : evidence.status === 'loading' ? 'Loading…' : `${evidence.data?.total ?? 0} evidence object${evidence.data?.total === 1 ? '' : 's'} in current case`} description="The seed command sends three synthetic source-event records through the real ingestion endpoint. Review their original-byte digests and separate normalized event fields." onClick={() => onNavigate('evidence')} action="Open evidence explorer" enabled={isScenario} />
      <DemoStep number="02" title="Run evidence verification" status={verificationText} description="Run the API verifier against a stored original. A passing byte-integrity result compares bytes with the recorded digest; it does not prove source truth." onClick={() => onNavigate('verification')} action="Open Verification Lab" complete={hasVerifiedEvidence} enabled={isScenario} />
      <DemoStep number="03" title="Anchor and independently check the root" status={anchorText} description="Submit a new batch to the isolated local Hardhat EvidenceRegistry, then run receipt verification. Both actions use actual API calls and an actual local transaction." onClick={() => onNavigate('ledger')} action="Open Blockchain Ledger" complete={hasVerifiedAnchor} enabled={isScenario} />
      <DemoStep number="04" title="Inspect deterministic correlations" status={graphText} description="Recompute the documented rule if needed. Examine each source-event reference and rule explanation in the graph; relationships are candidates, not causation." onClick={() => onNavigate('graph')} action="Open Trust Graph" complete={Boolean(graph.data?.correlation_count)} enabled={isScenario} />
      <li className="surface demo-step"><div className="demo-step-number">05</div><div className="demo-step-copy"><div className="eyebrow">EXPORT</div><h3>Generate a forensic report</h3><p>Download the selected case snapshot from the report endpoint. The response includes recorded evidence checks, available chain metadata, correlations, completeness findings, timestamps, and limitations. A download is not tracked as a completed state.</p><div className="demo-step-actions"><button className="button button-secondary" disabled={!isScenario} onClick={() => onDownload('json')}><ArrowDownToLine size={15} /> Download JSON</button><button className="button button-secondary" disabled={!isScenario} onClick={() => onDownload('html')}><ArrowDownToLine size={15} /> Download HTML</button><button className="text-button" onClick={() => onNavigate('reports')} disabled={!isScenario}>Report details <ArrowRight size={14} /></button></div>{reportError && <div className="error-panel report-download-error" role="alert"><AlertCircle size={16} /><div><strong>Report download failed</strong><span>{reportError}</span></div></div>}</div><div className="demo-step-state">On demand</div></li>
    </ol>
    <div className="integrity-note"><ShieldCheck size={15} /><span>Synthetic events are illustrative inputs. Integrity, signature, proof, chain, and completeness claims are limited to the exact checks performed and stored; none validates the truth or completeness of the originating logs.</span></div>
  </div>;
}

function DemoStep({ number, title, status, description, onClick, action, complete = false, enabled = false }: {
  number: string;
  title: string;
  status: string;
  description: string;
  onClick: () => void;
  action: string;
  complete?: boolean;
  enabled?: boolean;
}) {
  return <li className="surface demo-step"><div className="demo-step-number">{number}</div><div className="demo-step-copy"><div className="eyebrow">STEP {number}</div><h3>{title}</h3><p>{description}</p><button className="button button-secondary" onClick={onClick} disabled={!enabled}>{action}<ArrowRight size={14} /></button></div><div className={`demo-step-state ${complete ? 'is-complete' : ''}`}>{complete ? 'Check passed' : status}</div></li>;
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

function ImplementationPanel({ activeCase, evidence, graph, anchors, anchorChecks }: Pick<OverviewProps, 'activeCase' | 'evidence' | 'graph' | 'anchors' | 'anchorChecks'>) {
  const verifiedAnchors = Object.values(anchorChecks).filter((state) => state.status === 'ready').length;
  const items = [
    { label: 'Original evidence bytes', note: evidence.status === 'ready' ? `${evidence.data?.total ?? 0} object(s) loaded for this case` : 'Evidence API state unavailable', icon: <Database size={15} />, value: evidence.status === 'ready' ? 'Loaded' : evidence.status === 'loading' ? 'Loading' : 'Unavailable', unavailable: evidence.status === 'error' },
    { label: 'Normalized events', note: activeCase ? `${activeCase.event_count} event record(s) in this case` : 'No case selected', icon: <Fingerprint size={15} />, value: activeCase ? 'Recorded' : '—', unavailable: !activeCase },
    { label: 'Deterministic correlations', note: graph.data ? `${graph.data.correlation_count} correlation candidate(s)` : 'Trust Graph data has not loaded', icon: <GitBranch size={15} />, value: graph.status === 'error' ? 'Unavailable' : graph.status === 'loading' ? 'Loading' : graph.data ? 'Loaded' : 'Not loaded', unavailable: graph.status === 'error' },
    { label: 'Blockchain references', note: verifiedAnchors ? `${verifiedAnchors} receipt(s) verified in this session` : 'Recorded metadata is not live verification', icon: <Waypoints size={15} />, value: anchors.status === 'error' ? 'Unavailable' : anchors.status === 'loading' ? 'Loading' : `${anchors.data?.length ?? 0} recorded`, unavailable: anchors.status === 'error' },
  ];
  return <section className="surface implementation-panel"><div className="eyebrow">LIVE CASE STATE</div><h3>Integrity pipeline</h3><div className="scope-list">{items.map((item) => <div className="scope-row" key={item.label}><span className="scope-icon">{item.icon}</span><span className="scope-label-text"><strong>{item.label}</strong><small>{item.note}</small></span><span className={`scope-state ${item.unavailable ? 'unavailable' : ''}`}>{item.value}</span></div>)}</div></section>;
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
    {!state.result.valid && <div className="result-boundary"><strong>Failed check:</strong><code>original_evidence_sha256</code><span>Reason: {state.result.reason ?? 'unknown'}</span></div>}
    <div className="result-details"><Fact label="Expected SHA-256" value={state.result.expected_sha256 ?? 'Unavailable'} /><Fact label="Observed SHA-256" value={state.result.actual_sha256 ?? 'Unavailable'} /><Fact label="Byte length" value={`${state.result.actual_byte_length ?? '—'} / ${state.result.expected_byte_length ?? '—'}`} /></div>
    <div className="result-boundary"><LockKeyhole size={14} /> A matching digest confirms byte consistency only, not source truth or completeness.</div>
  </section>;
}

function verificationReason(reason?: string | null): string {
  if (reason === 'stored_object_missing') return 'The metadata exists, but the content-addressed original file is missing.';
  if (reason === 'stored_object_exceeds_limit') return 'The stored object exceeds the configured evidence size limit.';
  return 'The stored bytes do not match their recorded digest or byte length.';
}
