const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { rehearsalEnvironment } = require('./rehearsal-config.cjs');
const { assertAuthenticationConfigured } = require('./local-env.cjs');

const root = path.resolve(__dirname, '..');
const env = rehearsalEnvironment();
const children = [];
let stopping = false;

async function rpc(method, params = []) {
  const response = await fetch(env.CHAINPROOF_RPC_URL, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  const body = await response.json();
  if (!response.ok || body?.error) throw new Error(`Rehearsal chain RPC rejected ${method}.`);
  return body.result;
}

function portIsFree(port) {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', (error) => error.code === 'EADDRINUSE' ? resolve(false) : reject(error));
    server.listen(port, '127.0.0.1', () => server.close(() => resolve(true)));
  });
}

function start(label, command, args, childEnv) {
  process.stdout.write(`[${label}] ${command} ${args.join(' ')}\n`);
  const child = spawn(command, args, { cwd: root, env: childEnv, stdio: 'inherit', shell: process.platform === 'win32' });
  children.push({ label, child });
  child.once('error', (error) => {
    process.stderr.write(`[${label}] Could not start: ${error.message}\n`);
    void stop(1);
  });
  child.once('exit', (code, signal) => {
    if (!stopping) {
      process.stderr.write(`[${label}] exited${signal ? ` (${signal})` : ` with code ${code}`}; stopping the other app service.\n`);
      void stop(code && code !== 0 ? code : 1);
    }
  });
  return child;
}

async function waitFor(label, check, child, timeoutMs = 30000) {
  const deadline = Date.now() + timeoutMs;
  let lastError = 'not ready';
  while (Date.now() < deadline && !stopping) {
    if (child.exitCode !== null || child.signalCode !== null) throw new Error(`${label} process exited during startup.`);
    try { if (await check()) { process.stdout.write(`[${label}] Ready\n`); return; } }
    catch (error) { lastError = error instanceof Error ? error.message : String(error); }
    await new Promise((resolve) => setTimeout(resolve, 350));
  }
  throw new Error(`${label} did not become ready: ${lastError}`);
}

async function stop(exitCode = 0) {
  if (stopping) return;
  stopping = true;
  for (const { child } of children) if (child.exitCode === null && child.signalCode === null) child.kill('SIGTERM');
  await Promise.all(children.map(({ child }) => new Promise((resolve) => {
    if (child.exitCode !== null || child.signalCode !== null) resolve();
    else child.once('exit', resolve);
  })));
  process.exitCode = exitCode;
}

async function main() {
  assertAuthenticationConfigured();
  const metadataPath = env.CHAINPROOF_DEPLOYMENT_FILE;
  if (!fs.existsSync(metadataPath)) throw new Error(`No rehearsal deployment metadata at ${metadataPath}. Run rehearsal:deploy once after starting rehearsal:chain.`);
  const metadata = JSON.parse(fs.readFileSync(metadataPath, 'utf8'));
  if (metadata.chain_id !== 31337 || !/^0x[0-9a-fA-F]{40}$/u.test(metadata.contract_address || '')) {
    throw new Error('Rehearsal deployment metadata is invalid; preserving it without starting services.');
  }
  if (await rpc('eth_chainId') !== '0x7a69') throw new Error('Port 8556 is not the configured chain ID 31337.');
  const code = await rpc('eth_getCode', [metadata.contract_address, 'latest']);
  if (typeof code !== 'string' || code === '0x') throw new Error('EvidenceRegistry code is absent on the current chain. The rehearsal chain history may have been lost; do not redeploy into this data directory.');
  for (const port of [8110, 5184]) if (!(await portIsFree(port))) throw new Error(`Refusing to start: port ${port} is already occupied.`);

  const python = process.platform === 'win32' ? path.join(root, '.venv', 'Scripts', 'python.exe') : path.join(root, '.venv', 'bin', 'python');
  const api = start('FastAPI', fs.existsSync(python) ? python : (process.platform === 'win32' ? 'python' : 'python3'),
    ['-m', 'uvicorn', 'backend.app:app', '--host', '127.0.0.1', '--port', '8110'], env);
  await waitFor('FastAPI rehearsal API', async () => {
    const response = await fetch('http://127.0.0.1:8110/health');
    const body = response.ok ? await response.json() : null;
    return body?.status === 'ok' && body.workspace_mode === 'competition-rehearsal';
  }, api);

  const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
  const vite = start('Vite', npm, ['run', 'dev', '--', '--host', '127.0.0.1', '--port', '5184', '--strictPort'], env);
  await waitFor('Vite rehearsal frontend', async () => {
    const response = await fetch('http://127.0.0.1:5184/');
    return response.ok && (await response.text()).includes('ChainProof X');
  }, vite);
  process.stdout.write(`\nRehearsal app ready: http://127.0.0.1:5184\nAPI: http://127.0.0.1:8110 (competition-rehearsal)\nHardhat: http://127.0.0.1:8556 (left running separately)\nData: ${path.dirname(metadataPath)}\nCtrl+C stops FastAPI and Vite only; keep the Hardhat terminal running to preserve chain history.\n`);
}

process.on('SIGINT', () => { void stop(0); });
process.on('SIGTERM', () => { void stop(0); });
main().catch(async (error) => {
  process.stderr.write(`Rehearsal app refused or failed: ${error instanceof Error ? error.message : String(error)}\n`);
  await stop(1);
});
