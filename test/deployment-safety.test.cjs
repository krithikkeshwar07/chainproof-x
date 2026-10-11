const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { after, test } = require('node:test');

const projectRoot = path.resolve(__dirname, '..');
const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'cpx-deploy-safety-'));
after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));

test('contract deploy refuses existing metadata without changing its bytes', () => {
  const metadataPath = path.join(tempRoot, 'hardhat-deployment.json');
  const original = '{"preserve":"existing deployment reference"}\n';
  fs.writeFileSync(metadataPath, original, { mode: 0o600 });
  const result = spawnSync(process.execPath, ['scripts/deploy.cjs'], {
    cwd: projectRoot,
    encoding: 'utf8',
    env: { ...process.env, CHAINPROOF_DEPLOYMENT_FILE: metadataPath },
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Refusing to overwrite existing deployment metadata/);
  assert.equal(fs.readFileSync(metadataPath, 'utf8'), original);
});

test('combined stack refuses existing deployment metadata before starting Hardhat', () => {
  const metadataPath = path.join(tempRoot, 'existing-stack-metadata.json');
  const databasePath = path.join(tempRoot, 'new-empty.sqlite3');
  const original = '{"preserve":"existing stack metadata"}\n';
  fs.writeFileSync(metadataPath, original, { mode: 0o600 });
  const result = spawnSync(process.execPath, ['scripts/dev-stack.cjs'], {
    cwd: projectRoot,
    encoding: 'utf8',
    env: {
      ...process.env,
      CHAINPROOF_DEPLOYMENT_FILE: metadataPath,
      CHAINPROOF_DB: databasePath,
      CHAINPROOF_EVIDENCE_DIR: path.join(tempRoot, 'evidence'),
      CPX_API_VIEWER_TOKEN: 'viewer-test-token-' + 'v'.repeat(50),
      CPX_API_ANALYST_TOKEN: 'analyst-test-token-' + 'a'.repeat(50),
    },
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Refusing to start a fresh Hardhat chain over existing deployment metadata/);
  assert.doesNotMatch(result.stdout, /\[Hardhat\]/);
  assert.equal(fs.readFileSync(metadataPath, 'utf8'), original);
  assert.equal(fs.existsSync(databasePath), false);
});

test('combined stack refuses missing authentication configuration before binding ports', () => {
  const result = spawnSync(process.execPath, ['scripts/dev-stack.cjs'], {
    cwd: projectRoot,
    encoding: 'utf8',
    env: { ...process.env, CPX_API_VIEWER_TOKEN: '', CPX_API_ANALYST_TOKEN: '' },
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Set distinct CPX_API_VIEWER_TOKEN and CPX_API_ANALYST_TOKEN/);
  assert.doesNotMatch(result.stderr, /listen .*127\.0\.0\.1/);
});
