const assert = require('node:assert/strict');
const fs = require('node:fs');
const test = require('node:test');
const lodash = require('lodash');
const tmp = require('tmp');

test('security overrides use patched compatible packages and preserve Solc tmp API', () => {
  assert.equal(lodash.VERSION, '4.18.1');
  const scratch = tmp.fileSync({ postfix: '.smt2' });
  try {
    fs.writeFileSync(scratch.name, '(check-sat)');
    assert.equal(fs.readFileSync(scratch.name, 'utf8'), '(check-sat)');
  } finally {
    scratch.removeCallback();
  }
  assert.equal(fs.existsSync(scratch.name), false);
});
