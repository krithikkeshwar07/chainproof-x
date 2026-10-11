const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { getRehearsalRoot, rehearsalEnvironment } = require('./rehearsal-config.cjs');

async function main() {
  const root = getRehearsalRoot();
  const env = rehearsalEnvironment();
  const metadata = env.CHAINPROOF_DEPLOYMENT_FILE;
  const db = env.CHAINPROOF_DB;
  const evidence = env.CHAINPROOF_EVIDENCE_DIR;
  if (fs.existsSync(metadata) || fs.existsSync(db) || fs.existsSync(evidence)) {
    throw new Error(`Refusing to deploy over an existing rehearsal. Keep its data and use it only with its original running chain: ${root}`);
  }

  const response = await fetch(env.CHAINPROOF_RPC_URL, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_chainId', params: [] }),
  });
  if (!response.ok) throw new Error('Rehearsal Hardhat RPC is unavailable at 127.0.0.1:8556. Start rehearsal:chain first.');
  const rpc = await response.json();
  if (rpc?.result !== '0x7a69') throw new Error('Refusing deployment: port 8556 is not serving chain ID 31337.');

  fs.mkdirSync(root, { recursive: true, mode: 0o700 });
  const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
  const result = spawnSync(npm, ['run', 'chain:deploy'], { cwd: path.resolve(__dirname, '..'), env, stdio: 'inherit', shell: process.platform === 'win32' });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`EvidenceRegistry deployment failed with exit code ${result.status ?? 'unknown'}.`);
  if (!fs.existsSync(metadata)) throw new Error('Deployment command completed without creating rehearsal deployment metadata.');
  const deployed = JSON.parse(fs.readFileSync(metadata, 'utf8'));
  if (deployed.chain_id !== 31337 || !/^0x[0-9a-fA-F]{40}$/u.test(deployed.contract_address || '')) {
    throw new Error('Deployment metadata does not describe a valid rehearsal deployment. Preserve it for inspection.');
  }
  process.stdout.write(`Rehearsal EvidenceRegistry deployed on chain ${deployed.chain_id}.\nMetadata: ${metadata}\nThis command is one-time for this rehearsal directory; it refuses to overwrite metadata.\n`);
}

main().catch((error) => {
  process.stderr.write(`Rehearsal deployment refused or failed: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
