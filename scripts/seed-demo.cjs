const fs = require('node:fs');
const path = require('node:path');
const { analystAuthorization, assertAuthenticationConfigured, loadProjectEnv } = require('./local-env.cjs');

const root = path.resolve(__dirname, '..');
const api = 'http://127.0.0.1:8100';
const original = fs.readFileSync(path.join(root, 'fixtures', 'synthetic-evidence.json'));

async function request(label, url, options) {
  let response;
  try {
    const headers = new Headers(options?.headers);
    if (new URL(url).pathname.startsWith('/api/v1/')) headers.set('Authorization', analystAuthorization());
    response = await fetch(url, { ...options, headers });
  } catch (error) {
    throw new Error(`${label}: API is unavailable at ${api} (${error instanceof Error ? error.message : String(error)}). Start the local stack first.`);
  }
  const body = await response.text();
  if (!response.ok) throw new Error(`${label}: API returned HTTP ${response.status}: ${body.slice(0, 500)}`);
  try { return body ? JSON.parse(body) : null; }
  catch { throw new Error(`${label}: API returned malformed JSON.`); }
}

async function main() {
  loadProjectEnv(root);
  assertAuthenticationConfigured();
  const parsedApi = new URL(api);
  if (parsedApi.protocol !== 'http:' || !['127.0.0.1', 'localhost', '::1'].includes(parsedApi.hostname) || parsedApi.port !== '8100') {
    throw new Error('The demo seeder only accepts the isolated competition demo API on loopback port 8100.');
  }
  const health = await request('Check isolated demo workspace', `${api}/health`, { method: 'GET' });
  if (health?.status !== 'ok' || health.workspace_mode !== 'competition-demo') {
    throw new Error('Refusing to seed: port 8100 is not running in competition-demo mode. Start with npm run demo:stack.');
  }
  const existingCases = await request('Check for an existing synthetic scenario', `${api}/api/v1/cases`, { method: 'GET' });
  if (!Array.isArray(existingCases)) throw new Error('Check for an existing synthetic scenario: API returned malformed case list.');
  if (existingCases.some((item) => item && item.name === 'DEMO · ChainProof X synthetic investigation')) {
    throw new Error('The synthetic scenario already exists. Stop the stack, run npm run demo:reset, restart it, then seed once.');
  }
  const created = await request('Create synthetic demo case', `${api}/api/v1/cases`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ name: 'DEMO · ChainProof X synthetic investigation' }),
  });
  if (!created || typeof created.id !== 'string') throw new Error('Create synthetic demo case: response did not include a case ID.');

  const iso = (offset) => new Date(Date.parse('2026-01-15T12:00:00.000Z') + offset).toISOString();
  const events = [
    { format: 'windows_event_v1', eventId: 'evt-demo-win-001', sourceId: 'demo-windows-01', occurredAt: iso(0), eventType: 'logon', account: 'demo-user@example.test', computer: 'demo-ws-01' },
    { format: 'linux_audit_v1', eventId: 'evt-demo-linux-001', sourceId: 'demo-linux-01', occurredAt: iso(5000), eventType: 'login', user: 'demo-user@example.test', host: 'demo-ws-01' },
    { format: 'network_event_v1', eventId: 'evt-demo-net-001', sourceId: 'demo-network-01', occurredAt: iso(10000), eventType: 'connection', hostname: 'demo-ws-01', destinationIp: '192.0.2.25' },
  ];

  for (let i = 0; i < events.length; i += 1) {
    const form = new FormData();
    form.append('file', new Blob([original], { type: 'application/json' }), `synthetic-event-${i + 1}.json`);
    form.append('event', JSON.stringify(events[i]));
    await request(`Ingest synthetic event ${i + 1}`, `${api}/api/v1/cases/${created.id}/evidence`, { method: 'POST', body: form });
  }

  const correlations = await request('Compute deterministic correlations', `${api}/api/v1/cases/${created.id}/correlations/recompute`, { method: 'POST' });
  const count = Array.isArray(correlations?.correlations) ? correlations.correlations.length : correlations?.correlation_count;
  process.stdout.write(`Synthetic demo case created: ${created.id}\nSynthetic source events ingested: ${events.length}\nDeterministic correlation candidates: ${Number.isInteger(count) ? count : 'see API response'}\nThe synthetic case is in data/demo/ and is isolated from the normal workspace.\nNo blockchain transaction was created. The case does not represent a real investigation.\n`);
}

main().catch((error) => {
  process.stderr.write(`Demo seed failed: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
