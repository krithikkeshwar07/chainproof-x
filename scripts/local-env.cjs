const fs = require('node:fs');
const path = require('node:path');

function loadProjectEnv(projectRoot) {
  const envPath = path.join(projectRoot, '.env');
  if (!fs.existsSync(envPath)) return;
  for (const line of fs.readFileSync(envPath, 'utf8').split(/\r?\n/u)) {
    const match = line.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/u);
    if (!match || match[1].startsWith('#') || Object.hasOwn(process.env, match[1])) continue;
    let value = match[2];
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) value = value.slice(1, -1);
    else value = value.replace(/\s+#.*$/u, '');
    process.env[match[1]] = value;
  }
}

function assertAuthenticationConfigured() {
  const viewer = process.env.CPX_API_VIEWER_TOKEN || '';
  const analyst = process.env.CPX_API_ANALYST_TOKEN || '';
  const valid = (token) => token.length >= 43 && token.length <= 512 && /^[\x21-\x7e]+$/u.test(token);
  if (!valid(viewer) || !valid(analyst) || viewer === analyst) {
    throw new Error('Set distinct CPX_API_VIEWER_TOKEN and CPX_API_ANALYST_TOKEN values (each generated with at least 32 random bytes) in .env before starting the API.');
  }
}

function analystAuthorization() {
  assertAuthenticationConfigured();
  return `Bearer ${process.env.CPX_API_ANALYST_TOKEN}`;
}

module.exports = { analystAuthorization, assertAuthenticationConfigured, loadProjectEnv };
