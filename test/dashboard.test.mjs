// Phase 7 dashboard checks. dashboard/ is a self-contained static site (no
// build step) that imports its own copies of the two portable src/ modules
// it needs, rather than reaching outside its own directory with a relative
// "../src/..." import -- that would work locally but 404 once dashboard/ is
// deployed to Vercel as its own static root. The tradeoff is a manual sync
// duty: these tests catch the copies silently drifting from their source
// of truth, since there's no bundler here to enforce it automatically.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const REPO_ROOT = fileURLToPath(new URL('..', import.meta.url));

function read(relPath) {
  return readFileSync(join(REPO_ROOT, relPath), 'utf8');
}

for (const name of ['auditchain.mjs', 'policy.mjs']) {
  test(`dashboard/lib/${name} is byte-identical to src/${name} (manual sync, not a build step)`, () => {
    const source = read(`src/${name}`);
    const copy = read(`dashboard/lib/${name}`);
    assert.equal(
      copy,
      source,
      `dashboard/lib/${name} has drifted from src/${name} -- re-run: cp src/${name} dashboard/lib/${name}`,
    );
  });
}

test('dashboard/demo-data/audit.json is a genuinely valid, verifiable hash chain (not just present)', async () => {
  const { verifyChain } = await import('../dashboard/lib/auditchain.mjs');
  const { createHash } = await import('node:crypto');
  const records = JSON.parse(read('dashboard/demo-data/audit.json'));
  assert.ok(records.length > 0, 'demo audit data must not be empty');
  const nodeDigest = (text) => createHash('sha256').update(text, 'utf8').digest('hex');
  const result = await verifyChain(records, nodeDigest);
  assert.equal(result.valid, true, `baked demo audit data must be a valid chain -- got ${JSON.stringify(result)}`);
});

test('dashboard/demo-data/state.json and policy.txt exist and parse/compile cleanly', async () => {
  const { compile } = await import('../dashboard/lib/policy.mjs');

  const statePath = join(REPO_ROOT, 'dashboard/demo-data/state.json');
  assert.ok(existsSync(statePath));
  const state = JSON.parse(read('dashboard/demo-data/state.json'));
  assert.ok('currentIncidentId' in state);

  const policyText = read('dashboard/demo-data/policy.txt');
  const { rules, errors } = compile(policyText);
  assert.equal(errors.length, 0, `baked demo policy must compile clean -- got ${JSON.stringify(errors)}`);
  assert.ok(rules.length > 0);
});

test('the three featured demo incidents referenced in dashboard/app.mjs actually exist in the baked audit data', () => {
  const records = JSON.parse(read('dashboard/demo-data/audit.json'));
  const appSource = read('dashboard/app.mjs');
  const featuredIdMatches = [...appSource.matchAll(/'([0-9a-f-]{36})':/g)].map((m) => m[1]);
  assert.ok(featuredIdMatches.length >= 3, 'expected at least 3 featured incident ids in app.mjs');
  for (const id of featuredIdMatches) {
    const found = records.some((r) => r.payload?.incidentId === id);
    assert.ok(found, `featured incident id ${id} referenced in app.mjs was not found in the baked demo audit data`);
  }
});
