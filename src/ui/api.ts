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
  expected_sha256?: string;
  actual_sha256?: string;
  expected_byte_length?: number;
  actual_byte_length?: number;
  reason?: string | null;
}

export interface CaseCreateResult extends Omit<CaseSummary, 'evidence_count' | 'event_count'> {
  evidence_count: number;
  event_count: number;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${import.meta.env.VITE_API_BASE_URL ?? ''}${path}`, init);
  } catch {
    throw new Error('Unable to reach the ChainProof API. Check that the local backend is running.');
  }
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
    return value as unknown as VerificationResult;
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
