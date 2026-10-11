const fs = require('node:fs');
const path = require('node:path');
const { rehearsalEnvironment } = require('./rehearsal-config.cjs');
const { analystAuthorization, assertAuthenticationConfigured } = require('./local-env.cjs');

const root = path.resolve(__dirname, '..');
const api = 'http://127.0.0.1:8110';
const caseName = 'DEMO · ChainProof X competition rehearsal';
const original = fs.readFileSync(path.join(root, 'fixtures', 'synthetic-evidence.json'));

async function request(label, url, options) {
  let response;
  try {
    const headers = new Headers(options?.headers);
    if (new URL(url).pathname.startsWith('/api/v1/')) headers.set('Authorization', analystAuthorization());
    response = await fetch(url, { ...options, headers });
  }
  catch (error) { throw new Error(`${label}: rehearsal API is unavailable at ${api} (${error instanceof Error ? error.message : String(error)}).`); }
  const text = await response.text();
  if (!response.ok) throw new Error(`${label}: API returned HTTP ${response.status}: ${text.slice(0, 400)}`);
  try { return text ? JSON.parse(text) : null; }
  catch { throw new Error(`${label}: API returned malformed JSON.`); }
}

async function main() {
  assertAuthenticationConfigured();
  const expected = rehearsalEnvironment();
  const url = new URL(api);
  if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || url.port !== '8110') {
    throw new Error('Refusing to seed anything except the rehearsal API on loopback port 8110.');
  }
  if (!fs.existsSync(expected.CHAINPROOF_DEPLOYMENT_FILE)) throw new Error('Rehearsal deployment metadata is missing; start and deploy the isolated chain first.');
  const health = await request('Check rehearsal workspace', `${api}/health`, { method: 'GET' });
  if (health?.status !== 'ok' || health.workspace_mode !== 'competition-rehearsal') {
    throw new Error('Refusing to seed: port 8110 is not the isolated competition-rehearsal API. No data changed.');
  }
  const cases = await request('Check rehearsal case list', `${api}/api/v1/cases`, { method: 'GET' });
  if (!Array.isArray(cases)) throw new Error('Refusing to seed: API returned a malformed case list.');
  if (cases.length !== 0 || cases.some((item) => item?.name === caseName)) {
    throw new Error('Refusing to seed: the rehearsal database already contains a case. Existing data was preserved; reuse it without seeding.');
  }

  const created = await request('Create isolated synthetic case', `${api}/api/v1/cases`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ name: caseName }),
  });
  if (!created || typeof created.id !== 'string') throw new Error('Case creation response did not include a case ID.');
  const base = Date.parse('2026-10-11T08:00:00.000Z');
  const events = [
    { format: 'windows_event_v1', eventId: 'evt-rehearsal-win-001', sourceId: 'rehearsal-windows-01', occurredAt: new Date(base).toISOString(), eventType: 'logon', account: 'demo-user@example.test', computer: 'rehearsal-ws-01' },
    { format: 'linux_audit_v1', eventId: 'evt-rehearsal-linux-001', sourceId: 'rehearsal-linux-01', occurredAt: new Date(base + 5000).toISOString(), eventType: 'login', user: 'demo-user@example.test', host: 'rehearsal-ws-01' },
    { format: 'network_event_v1', eventId: 'evt-rehearsal-net-001', sourceId: 'rehearsal-network-01', occurredAt: new Date(base + 10000).toISOString(), eventType: 'connection', hostname: 'rehearsal-ws-01', destinationIp: '192.0.2.25' },
  ];
  for (let index = 0; index < events.length; index += 1) {
    const form = new FormData();
    form.append('file', new Blob([original], { type: 'application/json' }), `rehearsal-event-${index + 1}.json`);
    form.append('event', JSON.stringify(events[index]));
    await request(`Ingest rehearsal event ${index + 1}`, `${api}/api/v1/cases/${created.id}/evidence`, { method: 'POST', body: form });
  }
  const correlations = await request('Compute deterministic rehearsal correlations', `${api}/api/v1/cases/${created.id}/correlations/recompute`, { method: 'POST' });
  const count = Array.isArray(correlations?.correlations) ? correlations.correlations.length : correlations?.correlation_count;
  process.stdout.write(`Synthetic rehearsal case: ${created.id}\nEvidence events ingested: ${events.length}\nDeterministic correlation candidates: ${Number.isInteger(count) ? count : 'see API'}\nData directory: ${expected.CHAINPROOF_DB}\nNo signature result or blockchain transaction was fabricated. Seed is one-time; this command never deletes or reseeds existing data.\n`);
}

main().catch((error) => {
  process.stderr.write(`Rehearsal seed refused or failed: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
