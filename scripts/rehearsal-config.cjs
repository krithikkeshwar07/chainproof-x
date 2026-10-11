const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { loadProjectEnv } = require('./local-env.cjs');

const projectRoot = path.resolve(__dirname, '..');
loadProjectEnv(projectRoot);
const rehearsalParent = path.resolve(os.homedir(), 'Documents', 'Codex', 'ChainProof X rehearsal');
const defaultRoot = path.join(rehearsalParent, 'competition-2026-10-11');

function canonicalFuturePath(value) {
  let cursor = path.resolve(value);
  const suffix = [];
  while (true) {
    try {
      return path.resolve(fs.realpathSync.native(cursor), ...suffix);
    } catch (error) {
      try {
        const existing = fs.lstatSync(cursor);
        if (existing.isSymbolicLink()) throw new Error(`Refusing symlinked rehearsal path: ${cursor}`);
        throw error;
      } catch (statError) {
        if (statError.code !== 'ENOENT') throw statError;
      }
      const parent = path.dirname(cursor);
      if (parent === cursor) throw new Error(`Cannot resolve safe rehearsal path: ${value}`);
      suffix.unshift(path.basename(cursor));
      cursor = parent;
    }
  }
}

function isWithin(base, candidate) {
  const relative = path.relative(base, candidate);
  return relative === '' || (relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative));
}

function getRehearsalRoot() {
  const root = path.resolve(process.env.CPX_REHEARSAL_ROOT || defaultRoot);
  const relative = path.relative(rehearsalParent, root);
  if (!relative || relative.startsWith(`..${path.sep}`) || relative === '..' || path.isAbsolute(relative)
      || relative.includes(path.sep) || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$/u.test(relative)) {
    throw new Error(`Rehearsal data must be a single named directory inside ${rehearsalParent}.`);
  }
  const workspaceRelative = path.relative(projectRoot, root);
  if (root === projectRoot || (!workspaceRelative.startsWith(`..${path.sep}`) && workspaceRelative !== '..' && !path.isAbsolute(workspaceRelative))) {
    throw new Error('Rehearsal data must stay outside the project workspace.');
  }
  const canonicalParent = canonicalFuturePath(rehearsalParent);
  const canonicalRoot = canonicalFuturePath(root);
  const canonicalProject = fs.realpathSync.native(projectRoot);
  if (!isWithin(canonicalParent, canonicalRoot) || isWithin(canonicalProject, canonicalRoot) || isWithin(canonicalRoot, canonicalProject)) {
    throw new Error('Rehearsal data must resolve outside the project workspace and inside the approved rehearsal directory.');
  }
  return root;
}

function rehearsalEnvironment() {
  const root = getRehearsalRoot();
  const env = {
    ...process.env,
    CPX_DEMO_MODE: '1',
    CPX_WORKSPACE_MODE: 'competition-rehearsal',
    CPX_API_PORT: '8110',
    CPX_FRONTEND_PORT: '5184',
    CPX_VITE_API_PROXY_TARGET: 'http://127.0.0.1:8110',
    CHAINPROOF_RPC_URL: 'http://127.0.0.1:8556',
    CHAINPROOF_CHAIN_ID: '31337',
    CHAINPROOF_DEPLOYMENT_FILE: path.join(root, 'hardhat-deployment.json'),
    CHAINPROOF_DB: path.join(root, 'chainproof.sqlite3'),
    CHAINPROOF_EVIDENCE_DIR: path.join(root, 'evidence'),
  };
  // A shell override must not redirect this rehearsal to another registry or account.
  delete env.CHAINPROOF_CONTRACT_ADDRESS;
  delete env.CHAINPROOF_ANCHOR_ACCOUNT;
  return env;
}

module.exports = { getRehearsalRoot, rehearsalEnvironment, rehearsalParent };
