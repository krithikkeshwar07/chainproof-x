const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');
const { assertAuthenticationConfigured, loadProjectEnv } = require('./local-env.cjs');

const root = path.resolve(__dirname, '..');
const demoMode = process.argv.includes('--demo');
const children = [];
let stopping = false;

function npm(args, options = {}) {
  return spawnSync(process.platform === 'win32' ? 'npm.cmd' : 'npm', args, {
    cwd: root, env: process.env, stdio: 'inherit', shell: process.platform === 'win32', ...options,
  });
}

function start(label, command, args) {
  process.stdout.write(`\n[${label}] ${command} ${args.join(' ')}\n`);
  const child = spawn(command, args, { cwd: root, env: process.env, stdio: 'inherit', shell: process.platform === 'win32' });
  children.push(child);
  child.once('error', (error) => {
    process.stderr.write(`[${label}] Could not start: ${error.message}\n`);
    void stop(1);
  });
  child.once('exit', (code, signal) => {
    if (stopping) return;
    process.stderr.write(`[${label}] Stopped${signal ? ` (${signal})` : ` with exit code ${code}`}\n`);
    void stop(code && code !== 0 ? code : 1);
  });
  return child;
}

function assertPortFree(port) {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', (error) => error.code === 'EADDRINUSE'
      ? reject(new Error(`Refusing to start: loopback port ${port} is already occupied.`))
      : reject(error));
    server.listen(port, '127.0.0.1', () => server.close((error) => error ? reject(error) : resolve()));
  });
}

function existingAnchorCount(databasePath) {
  if (!fs.existsSync(databasePath)) return 0;
  const venvPython = process.platform === 'win32'
    ? path.join(root, '.venv', 'Scripts', 'python.exe')
    : path.join(root, '.venv', 'bin', 'python');
  const python = process.env.PYTHON || (fs.existsSync(venvPython) ? venvPython : (process.platform === 'win32' ? 'python' : 'python3'));
  const query = [
    'import pathlib, sqlite3, sys',
    "uri = pathlib.Path(sys.argv[1]).resolve().as_uri() + '?mode=ro'",
    'connection = sqlite3.connect(uri, uri=True)',
    "tables = {row[0] for row in connection.execute(\"SELECT name FROM sqlite_master WHERE type='table'\")}",
    "count = connection.execute('SELECT count(*) FROM blockchain_anchors').fetchone()[0] if 'blockchain_anchors' in tables else 0",
    'print(count)',
  ].join('; ');
  const result = spawnSync(python, ['-c', query, databasePath], { cwd: root, encoding: 'utf8', env: process.env });
  if (result.error || result.status !== 0 || !/^\d+\s*$/u.test(result.stdout || '')) {
    throw new Error('Cannot safely inspect the existing database read-only; refusing to start a fresh local chain.');
  }
  return Number(result.stdout.trim());
}

async function waitFor(label, check, timeoutMs = 30000) {
  const until = Date.now() + timeoutMs;
  let lastError = 'not ready';
  while (Date.now() < until && !stopping) {
    try {
      if (await check()) {
        process.stdout.write(`[${label}] Ready\n`);
        return;
      }
    } catch (error) {
      lastError = error instanceof Error ? error.message : String(error);
    }
    await new Promise((resolve) => setTimeout(resolve, 400));
  }
  throw new Error(`${label} did not become ready within ${timeoutMs / 1000}s (${lastError}).`);
}

async function rpcReady() {
  const response = await fetch(process.env.CHAINPROOF_RPC_URL, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_chainId', params: [] }),
  });
  const value = await response.json();
  return response.ok && typeof value.result === 'string' && Number.parseInt(value.result, 16) === Number(process.env.CHAINPROOF_CHAIN_ID);
}

async function stop(exitCode = 0) {
  if (stopping) return;
  stopping = true;
  for (const child of children) if (child.exitCode === null && child.signalCode === null) child.kill('SIGTERM');
  await Promise.all(children.map((child) => new Promise((resolve) => {
    if (child.exitCode !== null || child.signalCode !== null) resolve();
    else child.once('exit', resolve);
  })));
  process.exitCode = exitCode;
}

async function main() {
  loadProjectEnv(root);
  assertAuthenticationConfigured();
  const chainPort = demoMode ? 8546 : 8545;
  const apiPort = demoMode ? 8100 : 8000;
  const frontendPort = demoMode ? 5174 : 5173;
  if (demoMode) {
    const demoRoot = path.join(root, 'data', 'demo');
    process.env.CPX_DEMO_MODE = '1';
    process.env.CPX_WORKSPACE_MODE = 'competition-demo';
    process.env.CHAINPROOF_RPC_URL = `http://127.0.0.1:${chainPort}`;
    process.env.CHAINPROOF_CHAIN_ID = '31337';
    process.env.CHAINPROOF_DEPLOYMENT_FILE = path.join(demoRoot, 'hardhat-deployment.json');
    process.env.CHAINPROOF_DB = path.join(demoRoot, 'chainproof.sqlite3');
    process.env.CHAINPROOF_EVIDENCE_DIR = path.join(demoRoot, 'evidence');
    process.env.CPX_FRONTEND_PORT = String(frontendPort);
    process.env.CPX_API_PORT = String(apiPort);
    process.env.CPX_VITE_API_PROXY_TARGET = `http://127.0.0.1:${apiPort}`;
  } else {
    process.env.CPX_DEMO_MODE = '0';
    process.env.CPX_WORKSPACE_MODE = 'local';
    process.env.CPX_FRONTEND_PORT = String(frontendPort);
    process.env.CPX_API_PORT = String(apiPort);
    process.env.CPX_VITE_API_PROXY_TARGET = `http://127.0.0.1:${apiPort}`;
  }
  process.env.CHAINPROOF_RPC_URL ||= `http://127.0.0.1:${chainPort}`;
  process.env.CHAINPROOF_CHAIN_ID ||= '31337';
  process.env.CHAINPROOF_DEPLOYMENT_FILE ||= path.join(root, 'data', 'hardhat-deployment.json');
  process.env.CHAINPROOF_DB ||= path.join(root, 'data', 'chainproof.sqlite3');
  process.env.CHAINPROOF_EVIDENCE_DIR ||= path.join(root, 'data', 'evidence');
  process.env.CPX_FRONTEND_PORT ||= String(frontendPort);
  process.env.CPX_API_PORT ||= String(apiPort);

  // All startup preconditions are checked before starting a service or sending
  // a transaction. This launcher always creates a fresh in-memory chain.
  await Promise.all([chainPort, apiPort, frontendPort].map(assertPortFree));
  if (fs.existsSync(process.env.CHAINPROOF_DEPLOYMENT_FILE)) {
    throw new Error(`Refusing to start a fresh Hardhat chain over existing deployment metadata: ${process.env.CHAINPROOF_DEPLOYMENT_FILE}. Select a new isolated data directory.`);
  }
  const recordedAnchors = existingAnchorCount(process.env.CHAINPROOF_DB);
  if (recordedAnchors > 0) {
    throw new Error(`Refusing to start a fresh Hardhat chain while the selected database contains ${recordedAnchors} stored anchor reference(s). Preserve those records and select a new isolated data directory.`);
  }

  const [nodeMajor, nodeMinor] = process.versions.node.split('.').map(Number);
  if (nodeMajor < 22 || (nodeMajor === 22 && nodeMinor < 6)) {
    throw new Error('Node.js 22.6 or newer is required (use Node 22 LTS or newer).');
  }
  const rpc = new URL(process.env.CHAINPROOF_RPC_URL);
  if (!['127.0.0.1', 'localhost', '::1'].includes(rpc.hostname) || rpc.port !== String(chainPort)) {
    throw new Error(`The bundled local Hardhat workflow requires CHAINPROOF_RPC_URL on loopback port ${chainPort}.`);
  }
  if (Number(process.env.CHAINPROOF_CHAIN_ID) !== 31337) {
    throw new Error('The bundled local Hardhat workflow requires CHAINPROOF_CHAIN_ID=31337.');
  }

  const node = start('Hardhat', process.platform === 'win32' ? 'npm.cmd' : 'npm', ['run', demoMode ? 'chain:node:demo' : 'chain:node']);
  await waitFor('Hardhat JSON-RPC', async () => {
    if (node.exitCode !== null || node.signalCode !== null) throw new Error('Hardhat node exited during startup');
    return rpcReady();
  });

  process.stdout.write('\n[Hardhat] Deploying EvidenceRegistry to the local network…\n');
  const deploy = npm(['run', 'chain:deploy']);
  if (deploy.error) throw deploy.error;
  if (deploy.status !== 0) throw new Error(`Local contract deployment failed (exit code ${deploy.status ?? 'unknown'}).`);

  const venvPython = process.platform === 'win32'
    ? path.join(root, '.venv', 'Scripts', 'python.exe')
    : path.join(root, '.venv', 'bin', 'python');
  const python = process.env.PYTHON || (fs.existsSync(venvPython) ? venvPython : (process.platform === 'win32' ? 'python' : 'python3'));
  const backend = start('FastAPI', python, ['-m', 'uvicorn', 'backend.app:app', '--host', '127.0.0.1', '--port', String(apiPort)]);
  await waitFor('FastAPI health endpoint', async () => {
    if (backend.exitCode !== null || backend.signalCode !== null) throw new Error('FastAPI exited during startup');
    const response = await fetch(`http://127.0.0.1:${apiPort}/health`);
    const health = response.ok ? await response.json() : null;
    return health?.status === 'ok' && health.workspace_mode === (demoMode ? 'competition-demo' : 'local');
  });

  const frontend = start('Vite', process.platform === 'win32' ? 'npm.cmd' : 'npm', ['run', 'dev', '--', '--host', '127.0.0.1', '--port', String(frontendPort)]);
  await waitFor('Frontend', async () => {
    if (frontend.exitCode !== null || frontend.signalCode !== null) throw new Error('Vite exited during startup');
    const response = await fetch(`http://127.0.0.1:${frontendPort}/`);
    return response.ok && (await response.text()).includes('ChainProof X');
  });
  process.stdout.write(`\nChainProof X ${demoMode ? 'isolated synthetic competition demo' : 'local'} stack is ready:\n  Frontend:  http://127.0.0.1:${frontendPort}\n  API docs:  http://127.0.0.1:${apiPort}/docs\n  Hardhat:   http://127.0.0.1:${chainPort}\n${demoMode ? '  Data:      data/demo/ (isolated from the normal workspace)\n' : ''}\nPress Ctrl+C to stop all services.\n`);
}

process.on('SIGINT', () => { void stop(0); });
process.on('SIGTERM', () => { void stop(0); });
main().catch(async (error) => {
  process.stderr.write(`ChainProof X startup failed: ${error instanceof Error ? error.message : String(error)}\n`);
  await stop(1);
});
