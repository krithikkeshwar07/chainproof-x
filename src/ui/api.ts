export interface CaseSummary {
  id: string;
  name: string;
  created_at: string;
  evidence_count: number;
  event_count: number;
}

export interface EventRecord {
  eventId: string;
  sourceId: string;
  occurredAt: string;
  eventType: string;
  actor: string;
  target: string;
}

export interface EvidenceItem {
  evidence_id: string;
  filename: string;
  media_type: string;
  byte_length: number;
  sha256: string;
  ingested_at: string;
  event_id: string;
  source_id: string;
  occurred_at: string;
  event_type: string;
  canonical_event_sha256: string;
  event: EventRecord;
}

export interface EvidencePage {
  items: EvidenceItem[];
  total: number;
  limit: number;
  offset: number;
}

export interface VerificationResult {
  evidence_id: string;
  valid: boolean;
  checked_at?: string;
  expected_sha256?: string;
  actual_sha256?: string;
  expected_byte_length?: number;
  actual_byte_length?: number;
  reason?: string | null;
}

export interface MerkleContextProof { event_id: string; canonical_event_base64: string; canonical_sha256: string; proof: { version: string; leafIndex: number; leafCount: number; steps: Array<{ side: string; hash?: string }> } }
export interface MerkleContext { case_id: string; tree_version: string; leaf_count: number; root_hash: string; proofs: MerkleContextProof[] }
export interface LabCheck { valid: boolean; failed_check: string | null; reason: string; checked_at: string; [key: string]: unknown }
export interface CompletenessResult { manifest_present: boolean; complete: boolean | null; missing_event_ids: string[]; unexpected_event_ids: string[]; reason: string | null; [key: string]: unknown }

export interface CaseCreateResult extends Omit<CaseSummary, 'evidence_count' | 'event_count'> {
  evidence_count: number;
  event_count: number;
}

export interface BlockchainAnchor {
  batch_id: string;
  case_id: string;
  merkle_root: string;
  leaf_count: number;
  tree_version: string;
  chain_id: number;
  contract_address: string;
  sender_address: string;
  tx_hash: string;
  block_number: number;
  block_hash: string;
  anchored_at: number;
  created_at: string;
  verification_status: 'recorded' | 'not_verified';
}

export interface AnchorSubmission extends Omit<BlockchainAnchor, 'verification_status'> {
  verification_status: 'verified';
}

export interface AnchorVerification {
  batch_id: string;
  merkle_root: string;
  chain_id: number;
  contract_address: string;
  sender_address: string;
  tx_hash: string;
  block_number: number;
  block_hash: string;
  anchored_at: number;
  verification_status: 'verified';
}

export type TrustNodeType = 'case' | 'organization' | 'entity' | 'evidence' | 'event' | 'incident' | 'investigation';
export interface TrustGraphNode {
  id: string;
  type: TrustNodeType;
  label: string;
  details: string;
  evidence_id?: string;
  sha256?: string;
  event?: EventRecord;
  canonical_sha256?: string;
  rule_id?: string;
  rule_version?: number;
  matched_entities?: string[];
  window_seconds?: number;
  entity_type?: string;
  entity_key?: string;
}
export interface TrustGraphEdge {
  id: string;
  source: string;
  target: string;
  relationship: string;
  rule_id: string | null;
  explanation: string;
  evidence_ids: string[];
}
export interface TrustGraph {
  case_id: string;
  nodes: TrustGraphNode[];
  edges: TrustGraphEdge[];
  correlation_count: number;
}
export interface CorrelationRun {
  case_id: string;
  rule_id: string;
  rule_version: number;
  window_seconds: number;
  event_count: number;
  correlation_count: number;
}

export interface Investigation {
  id: string;
  case_id: string;
  title: string;
  summary: string;
  status: 'open' | 'closed';
  created_at: string;
  updated_at: string;
  evidence_ids: string[];
  correlation_ids: string[];
}

export type ApiRole = 'viewer' | 'analyst';
let apiToken: string | null = null;
let unauthorizedHandler: (() => void) | null = null;

export function clearApiToken(): void { apiToken = null; }
export function setApiUnauthorizedHandler(handler: (() => void) | null): void { unauthorizedHandler = handler; }

export async function authenticateApi(token: string): Promise<ApiRole> {
  apiToken = token;
  try {
    const session = await request('/api/v1/session') as { role?: unknown };
    if (session.role !== 'viewer' && session.role !== 'analyst') throw new Error('The API returned an invalid access role.');
    return session.role;
  } catch (error) {
    apiToken = null;
    throw error;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    const headers = new Headers(init?.headers);
    if (apiToken) headers.set('Authorization', `Bearer ${apiToken}`);
    response = await fetch(`${import.meta.env.VITE_API_BASE_URL ?? ''}${path}`, { ...init, headers });
  } catch {
    throw new Error('Unable to reach the ChainProof API. Check that the local backend is running.');
  }
  if (response.status === 401) { clearApiToken(); unauthorizedHandler?.(); }
  if (!response.ok) {
    let detail = `Request failed (${response.status})`;
    try {
      const body = await response.json() as { detail?: unknown };
      if (typeof body.detail === 'string') detail = body.detail;
    } catch {
      // Keep a useful status message when the server does not return JSON.
    }
    throw new Error(detail);
  }
  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    throw new Error('The ChainProof API returned malformed JSON.');
  }
  return payload as T;
}

export async function downloadForensicReport(caseId: string, format: 'json' | 'html'): Promise<Blob> {
  let response: Response;
  try {
    const headers = new Headers();
    if (apiToken) headers.set('Authorization', `Bearer ${apiToken}`);
    response = await fetch(`${import.meta.env.VITE_API_BASE_URL ?? ''}/api/v1/cases/${encodeURIComponent(caseId)}/reports/forensic.${format}`, { headers });
  } catch {
    throw new Error('Unable to reach the ChainProof API. Check that the local backend is running.');
  }
  if (response.status === 401) { clearApiToken(); unauthorizedHandler?.(); }
  if (!response.ok) {
    let detail = `Request failed (${response.status})`;
    try { const body = await response.json() as { detail?: unknown }; if (typeof body.detail === 'string') detail = body.detail; } catch { /* Use the status fallback. */ }
    throw new Error(detail);
  }
  const blob = await response.blob();
  if (blob.size === 0) throw new Error('The ChainProof API returned an empty report.');
  return blob;
}

export function listCases(): Promise<CaseSummary[]> {
  return request('/api/v1/cases').then((value) => {
    if (!Array.isArray(value) || !value.every(isCaseSummary)) throw malformedResponse('case list');
    return value;
  });
}

export function listEvidence(caseId: string): Promise<EvidencePage> {
  return request(`/api/v1/cases/${encodeURIComponent(caseId)}/evidence?limit=100&offset=0`).then((value) => {
    if (!isRecord(value) || !Array.isArray(value.items) || !value.items.every(isEvidenceItem)
      || !isNonNegativeInteger(value.total) || !isPositiveInteger(value.limit) || !isNonNegativeInteger(value.offset)
      || value.items.length > value.limit || value.total < value.offset + value.items.length) {
      throw malformedResponse('evidence list');
    }
    return value as unknown as EvidencePage;
  });
}

export function createCase(name: string): Promise<CaseCreateResult> {
  return request('/api/v1/cases', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name }),
  }).then((value) => {
    if (!isRecord(value) || !isNonEmptyString(value.id) || !isNonEmptyString(value.name)
      || !isNonEmptyString(value.created_at) || Number.isNaN(Date.parse(value.created_at))) throw malformedResponse('created case');
    return {
      id: value.id,
      name: value.name,
      created_at: value.created_at,
      evidence_count: isNonNegativeInteger(value.evidence_count) ? value.evidence_count : 0,
      event_count: isNonNegativeInteger(value.event_count) ? value.event_count : 0,
    };
  });
}

export function ingestEvidence(caseId: string, file: File, event: string): Promise<{
  evidence_id: string;
  event: EventRecord;
  sha256: string;
}> {
  const body = new FormData();
  body.append('file', file);
  body.append('event', event);
  return request(`/api/v1/cases/${encodeURIComponent(caseId)}/evidence`, { method: 'POST', body }).then((value) => {
    if (!isRecord(value) || !isNonEmptyString(value.evidence_id) || !isLowerHex(value.sha256, 64)
      || !isEventRecord(value.event)) throw malformedResponse('evidence ingestion');
    return value as { evidence_id: string; event: EventRecord; sha256: string };
  });
}

export function verifyEvidence(evidenceId: string): Promise<VerificationResult> {
  return request(`/api/v1/evidence/${encodeURIComponent(evidenceId)}/verify`).then((value) => {
    if (!isRecord(value) || value.evidence_id !== evidenceId || typeof value.valid !== 'boolean') throw malformedResponse('verification');
    if (value.valid && (!isLowerHex(value.expected_sha256, 64) || !isLowerHex(value.actual_sha256, 64)
      || !isNonNegativeInteger(value.expected_byte_length) || !isNonNegativeInteger(value.actual_byte_length)
      || value.expected_sha256 !== value.actual_sha256 || value.expected_byte_length !== value.actual_byte_length)) {
      throw malformedResponse('verification');
    }
    if (!value.valid && value.reason !== null && typeof value.reason !== 'string') throw malformedResponse('verification');
    if (value.checked_at !== undefined && (typeof value.checked_at !== 'string' || Number.isNaN(Date.parse(value.checked_at)))) throw malformedResponse('verification');
    return value as unknown as VerificationResult;
  });
}

export function verifyEvidenceCandidate(evidenceId: string, file: File): Promise<VerificationResult & { failed_check?: string | null; candidate_stored: false }> {
  const body = new FormData();
  body.append('file', file);
  return request(`/api/v1/evidence/${encodeURIComponent(evidenceId)}/verify-candidate`, { method: 'POST', body }).then((value) => {
    if (!isRecord(value) || value.evidence_id !== evidenceId || typeof value.valid !== 'boolean'
      || !isLowerHex(value.expected_sha256, 64) || !isLowerHex(value.actual_sha256, 64)
      || !isNonNegativeInteger(value.expected_byte_length) || !isNonNegativeInteger(value.actual_byte_length)
      || value.candidate_stored !== false || !isNonEmptyString(value.reason)
      || (value.failed_check !== null && !isNonEmptyString(value.failed_check))) throw malformedResponse('candidate verification');
    return value as unknown as VerificationResult & { failed_check?: string | null; candidate_stored: false };
  });
}

export function getVerificationContext(caseId: string): Promise<MerkleContext> {
  return request(`/api/v1/cases/${encodeURIComponent(caseId)}/verification/context`).then((value) => {
    if (!isRecord(value) || value.case_id !== caseId || value.tree_version !== 'cpx-merkle-v1'
      || !isPositiveInteger(value.leaf_count) || !isLowerHex(value.root_hash, 64) || !Array.isArray(value.proofs)
      || !value.proofs.every((entry) => isRecord(entry) && isNonEmptyString(entry.event_id)
        && isNonEmptyString(entry.canonical_event_base64) && isLowerHex(entry.canonical_sha256, 64)
        && isRecord(entry.proof) && Number.isSafeInteger(entry.proof.leafIndex) && Array.isArray(entry.proof.steps))) {
      throw malformedResponse('verification context');
    }
    return value as unknown as MerkleContext;
  });
}

export function verifyMerkleProof(caseId: string, eventId: string, expectedRoot: string, proof: unknown): Promise<LabCheck> {
  return request(`/api/v1/cases/${encodeURIComponent(caseId)}/verification/proof`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ event_id: eventId, expected_root: expectedRoot, proof }),
  }).then((value) => {
    if (!isRecord(value) || typeof value.valid !== 'boolean' || !isNonEmptyString(value.reason)
      || (value.failed_check !== null && !isNonEmptyString(value.failed_check)) || !isNonEmptyString(value.checked_at)) throw malformedResponse('Merkle verification');
    return value as unknown as LabCheck;
  });
}

export function verifyBatchSignature(caseId: string, batchId: string, keyId: string, signatureHex: string): Promise<LabCheck> {
  return request(`/api/v1/cases/${encodeURIComponent(caseId)}/verification/signature`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ batch_id: batchId, key_id: keyId, signature_hex: signatureHex }),
  }).then((value) => {
    if (!isRecord(value) || typeof value.valid !== 'boolean' || !isNonEmptyString(value.reason)
      || (value.failed_check !== null && !isNonEmptyString(value.failed_check)) || !isNonEmptyString(value.checked_at)) throw malformedResponse('signature verification');
    return value as unknown as LabCheck;
  });
}

export function registerSigningKey(publicKeyDerBase64: string): Promise<{ key_id: string; status: string; registered_at: string }> {
  return request('/api/v1/signing-keys', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ public_key_der_base64: publicKeyDerBase64 }) }).then((value) => {
    if (!isRecord(value) || !isLowerHex(value.key_id, 64) || value.status !== 'active' || !isNonEmptyString(value.registered_at)) throw malformedResponse('signing key registration');
    return value as { key_id: string; status: string; registered_at: string };
  });
}

export function setExpectedEvents(caseId: string, expectedEventIds: string[]): Promise<CompletenessResult> {
  return request(`/api/v1/cases/${encodeURIComponent(caseId)}/expected-events`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ expected_event_ids: expectedEventIds }) }).then((value) => {
    if (!isRecord(value) || !isNonEmptyString(value.manifest_id) || !Array.isArray(value.expected_event_ids)) throw malformedResponse('expected event manifest');
    return value as unknown as CompletenessResult;
  });
}

export function getCompleteness(caseId: string): Promise<CompletenessResult> {
  return request(`/api/v1/cases/${encodeURIComponent(caseId)}/completeness`).then((value) => {
    if (!isRecord(value) || typeof value.manifest_present !== 'boolean' || !Array.isArray(value.missing_event_ids)
      || !Array.isArray(value.unexpected_event_ids) || (value.complete !== null && typeof value.complete !== 'boolean')) throw malformedResponse('completeness result');
    return value as unknown as CompletenessResult;
  });
}

export function forensicReportUrl(caseId: string, format: 'json' | 'html'): string {
  return `${import.meta.env.VITE_API_BASE_URL ?? ''}/api/v1/cases/${encodeURIComponent(caseId)}/reports/forensic.${format}`;
}

export function listAnchors(caseId: string): Promise<BlockchainAnchor[]> {
  return request(`/api/v1/cases/${encodeURIComponent(caseId)}/anchors`).then((value) => {
    if (!Array.isArray(value) || !value.every(isBlockchainAnchor)) throw malformedResponse('blockchain ledger');
    return value;
  });
}

export function anchorCase(caseId: string, batchId: string): Promise<AnchorSubmission> {
  if (!isLowerHex(batchId, 64)) throw new Error('Batch ID must be 32 bytes of lowercase hexadecimal.');
  return request(`/api/v1/cases/${encodeURIComponent(caseId)}/anchors`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ batch_id: `0x${batchId}` }),
  }).then((value) => {
    if (!isAnchorSubmission(value)) throw malformedResponse('blockchain anchor');
    return value;
  });
}

export function verifyAnchor(batchId: string): Promise<AnchorVerification> {
  return request(`/api/v1/anchors/${encodeURIComponent(batchId)}/verify`).then((value) => {
    if (!isAnchorVerification(value)) throw malformedResponse('blockchain verification');
    return value;
  });
}

export function getTrustGraph(caseId: string): Promise<TrustGraph> {
  return request(`/api/v1/cases/${encodeURIComponent(caseId)}/trust-graph`).then((value) => {
    if (!isTrustGraph(value)) throw malformedResponse('trust graph');
    return value;
  });
}

export function recomputeCorrelations(caseId: string): Promise<CorrelationRun> {
  return request(`/api/v1/cases/${encodeURIComponent(caseId)}/correlations/recompute`, { method: 'POST' }).then((value) => {
    if (!isRecord(value) || value.case_id !== caseId || value.rule_id !== 'shared-entity-window-v1'
      || value.rule_version !== 1 || value.window_seconds !== 300
      || !isNonNegativeInteger(value.event_count) || !isNonNegativeInteger(value.correlation_count)) {
      throw malformedResponse('correlation result');
    }
    return value as unknown as CorrelationRun;
  });
}

export function getInvestigations(caseId: string): Promise<Investigation[]> {
  return request(`/api/v1/cases/${encodeURIComponent(caseId)}/investigations`).then((value) => {
    if (!Array.isArray(value) || !value.every(isInvestigation) || value.some((item) => item.case_id !== caseId)) {
      throw malformedResponse('investigation list');
    }
    return value;
  });
}

export function createInvestigation(caseId: string, input: { title: string; summary: string; evidence_ids: string[]; correlation_ids: string[] }): Promise<Investigation> {
  return request(`/api/v1/cases/${encodeURIComponent(caseId)}/investigations`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(input),
  }).then((value) => {
    if (!isInvestigation(value) || value.case_id !== caseId) throw malformedResponse('investigation');
    return value;
  });
}

export function updateInvestigationStatus(id: string, status: Investigation['status']): Promise<Investigation> {
  return request(`/api/v1/investigations/${encodeURIComponent(id)}/status`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ status }),
  }).then((value) => {
    if (!isInvestigation(value) || value.id !== id || value.status !== status) throw malformedResponse('investigation status');
    return value;
  });
}

function malformedResponse(resource: string): Error {
  return new Error(`The ChainProof API returned a malformed ${resource} response.`);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

function isNonNegativeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0;
}

function isPositiveInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) > 0;
}

function isLowerHex(value: unknown, length: number): value is string {
  return typeof value === 'string' && new RegExp(`^[0-9a-f]{${length}}$`).test(value);
}

function isCaseSummary(value: unknown): value is CaseSummary {
  return isRecord(value) && isNonEmptyString(value.id) && isNonEmptyString(value.name)
    && isNonEmptyString(value.created_at) && !Number.isNaN(Date.parse(value.created_at))
    && isNonNegativeInteger(value.evidence_count) && isNonNegativeInteger(value.event_count);
}

function isEventRecord(value: unknown): value is EventRecord {
  return isRecord(value) && ['eventId', 'sourceId', 'occurredAt', 'eventType', 'actor', 'target'].every((key) => isNonEmptyString(value[key]))
    && !Number.isNaN(Date.parse(value.occurredAt as string));
}

function isEvidenceItem(value: unknown): value is EvidenceItem {
  return isRecord(value) && isNonEmptyString(value.evidence_id) && isNonEmptyString(value.filename)
    && isNonEmptyString(value.media_type) && isNonNegativeInteger(value.byte_length)
    && isLowerHex(value.sha256, 64) && isNonEmptyString(value.ingested_at) && !Number.isNaN(Date.parse(value.ingested_at))
    && isNonEmptyString(value.event_id) && isNonEmptyString(value.source_id) && isNonEmptyString(value.occurred_at)
    && !Number.isNaN(Date.parse(value.occurred_at)) && isNonEmptyString(value.event_type)
    && isLowerHex(value.canonical_event_sha256, 64) && isEventRecord(value.event);
}

function isBlockchainAnchor(value: unknown): value is BlockchainAnchor {
  return isRecord(value) && /^0x[0-9a-f]{64}$/.test(String(value.batch_id))
    && isNonEmptyString(value.case_id) && /^0x[0-9a-f]{64}$/.test(String(value.merkle_root))
    && isPositiveInteger(value.leaf_count) && value.tree_version === 'cpx-merkle-v1'
    && isPositiveInteger(value.chain_id) && /^0x[0-9a-fA-F]{40}$/.test(String(value.contract_address))
    && /^0x[0-9a-fA-F]{40}$/.test(String(value.sender_address))
    && /^0x[0-9a-f]{64}$/.test(String(value.tx_hash)) && isNonNegativeInteger(value.block_number)
    && /^0x[0-9a-f]{64}$/.test(String(value.block_hash))
    && isNonNegativeInteger(value.anchored_at)
    && isNonEmptyString(value.created_at) && !Number.isNaN(Date.parse(value.created_at))
    && (value.verification_status === 'recorded' || value.verification_status === 'not_verified');
}

function isAnchorSubmission(value: unknown): value is AnchorSubmission {
  return isRecord(value) && isBlockchainAnchor({ ...value, verification_status: 'recorded' })
    && value.verification_status === 'verified';
}

function isAnchorVerification(value: unknown): value is AnchorVerification {
  return isRecord(value) && /^0x[0-9a-f]{64}$/.test(String(value.batch_id))
    && /^0x[0-9a-f]{64}$/.test(String(value.merkle_root)) && isPositiveInteger(value.chain_id)
    && /^0x[0-9a-fA-F]{40}$/.test(String(value.contract_address))
    && /^0x[0-9a-fA-F]{40}$/.test(String(value.sender_address))
    && /^0x[0-9a-f]{64}$/.test(String(value.tx_hash)) && isNonNegativeInteger(value.block_number)
    && /^0x[0-9a-f]{64}$/.test(String(value.block_hash)) && isNonNegativeInteger(value.anchored_at)
    && value.verification_status === 'verified';
}

function isTrustGraph(value: unknown): value is TrustGraph {
  if (!isRecord(value) || !isNonEmptyString(value.case_id) || !Array.isArray(value.nodes)
    || !Array.isArray(value.edges) || !isNonNegativeInteger(value.correlation_count)) return false;
  const nodeIds = new Set<string>();
  for (const node of value.nodes) {
    if (!isRecord(node) || !isNonEmptyString(node.id) || !isNonEmptyString(node.label)
      || !isNonEmptyString(node.details) || !['case', 'organization', 'entity', 'evidence', 'event', 'incident', 'investigation'].includes(String(node.type))
      || nodeIds.has(node.id)) return false;
    nodeIds.add(node.id);
  }
  for (const edge of value.edges) {
    if (!isRecord(edge) || !isNonEmptyString(edge.id) || !isNonEmptyString(edge.source)
      || !isNonEmptyString(edge.target) || !isNonEmptyString(edge.relationship)
      || (edge.rule_id !== null && !isNonEmptyString(edge.rule_id)) || !isNonEmptyString(edge.explanation)
      || !Array.isArray(edge.evidence_ids) || !edge.evidence_ids.every(isNonEmptyString)
      || !nodeIds.has(edge.source) || !nodeIds.has(edge.target)) return false;
  }
  return true;
}

function isInvestigation(value: unknown): value is Investigation {
  return isRecord(value) && isNonEmptyString(value.id) && isNonEmptyString(value.case_id)
    && isNonEmptyString(value.title) && typeof value.summary === 'string'
    && (value.status === 'open' || value.status === 'closed')
    && isNonEmptyString(value.created_at) && !Number.isNaN(Date.parse(value.created_at))
    && isNonEmptyString(value.updated_at) && !Number.isNaN(Date.parse(value.updated_at))
    && Array.isArray(value.evidence_ids) && value.evidence_ids.every(isNonEmptyString)
    && Array.isArray(value.correlation_ids) && value.correlation_ids.every((id) => isLowerHex(id, 64));
}

export function formatBytes(value: number): string {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(2)} MB`;
}

export function formatDate(value: string): string {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.valueOf())) return 'Unknown time';
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
    timeZone: 'UTC',
  }).format(parsed);
}
