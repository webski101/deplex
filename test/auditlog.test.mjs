import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync, copyFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import {
  append,
  readAll,
  verify,
  migrateFile,
  rechainRecords,
  nodeDigestHex,
  GENESIS_PREV_HASH,
} from '../src/auditlog.mjs';
import { verifyChain, webCryptoDigestHex, recordPreimage } from '../src/auditchain.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REAL_LOG = join(__dirname, '..', 'deplex-audit.jsonl');
const CONCURRENT_WORKER = join(__dirname, 'fixtures', 'concurrent-append-worker.mjs');

let tmpDir;
let logPath;

beforeEach(() => {
  tmpDir = mkdtempSync(join(tmpdir(), 'deplex-audit-'));
  logPath = join(tmpDir, 'audit.jsonl');
});

afterEach(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

function appendMany(path, n) {
  const recs = [];
  for (let i = 0; i < n; i++) recs.push(append(path, 'EVENT', { i, note: `record ${i}` }));
  return recs;
}

// ---------------------------------------------------------------------------
// Chain construction
// ---------------------------------------------------------------------------

test('first append links to the genesis prevHash and starts at seq 0', () => {
  const rec = append(logPath, 'DECISION', { hello: 'world' });
  assert.equal(rec.seq, 0);
  assert.equal(rec.prevHash, GENESIS_PREV_HASH);
  assert.equal(rec.hash, nodeDigestHex(recordPreimage(0, rec.ts, 'DECISION', { hello: 'world' }, GENESIS_PREV_HASH)));
});

test('each record links to the previous one and seq increments monotonically', () => {
  const recs = appendMany(logPath, 5);
  for (let i = 1; i < recs.length; i++) {
    assert.equal(recs[i].seq, i);
    assert.equal(recs[i].prevHash, recs[i - 1].hash, 'prevHash must equal the prior record hash');
  }
});

test('append preserves type and payload intact (readAll consumers still see them)', () => {
  append(logPath, 'EXECUTION_RESULT', { status: 'confirmed', txHash: '0xabc' });
  const [r] = readAll(logPath);
  assert.equal(r.type, 'EXECUTION_RESULT');
  assert.deepEqual(r.payload, { status: 'confirmed', txHash: '0xabc' });
});

test('a fresh process resumes the chain from the persisted tail without breaking it', async () => {
  appendMany(logPath, 3);
  // append() always reads the tail fresh from disk (no in-memory cache to
  // go stale across a restart -- see the concurrent-writer fix), so this is
  // just a direct append against the same path, same as a real process
  // restarting would do.
  const resumed = append(logPath, 'EVENT', { afterRestart: true });
  assert.equal(resumed.seq, 3, 'seq must continue from the persisted tail, not reset to 0');
  const { valid, brokenAt } = await verify(logPath, nodeDigestHex);
  assert.equal(valid, true, `chain must stay valid across restart (broke at ${brokenAt})`);
});

// ---------------------------------------------------------------------------
// verify(): valid chains
// ---------------------------------------------------------------------------

test('verify() passes for an intact chain, via both node:crypto and WebCrypto digests', async () => {
  appendMany(logPath, 10);
  const viaNode = await verify(logPath, nodeDigestHex);
  const viaWebCrypto = await verify(logPath, webCryptoDigestHex);
  assert.deepEqual(viaNode, { valid: true, brokenAt: null, reason: null });
  assert.deepEqual(viaWebCrypto, { valid: true, brokenAt: null, reason: null });
});

test('node:crypto and WebCrypto produce byte-identical hashes for the same input', async () => {
  const preimage = recordPreimage(7, '2026-07-16T00:00:00.000Z', 'EVENT', { a: 1, b: 'two' }, GENESIS_PREV_HASH);
  assert.equal(nodeDigestHex(preimage), await webCryptoDigestHex(preimage));
});

test('an empty log verifies as valid (no records, nothing to break)', async () => {
  writeFileSync(logPath, '');
  assert.deepEqual(await verify(logPath, nodeDigestHex), { valid: true, brokenAt: null, reason: null });
});

// ---------------------------------------------------------------------------
// Tamper detection -- the core Phase 4 guarantee
// ---------------------------------------------------------------------------

test('tampering a payload byte mid-chain: verify() pinpoints the exact record', async () => {
  appendMany(logPath, 8);
  const lines = readFileSync(logPath, 'utf8').trim().split('\n');
  const target = 4;
  const rec = JSON.parse(lines[target]);
  rec.payload.note = rec.payload.note.replace('record 4', 'record 4!'); // one-char change to the signed payload
  lines[target] = JSON.stringify(rec);
  writeFileSync(logPath, lines.join('\n') + '\n');

  const { valid, brokenAt, reason } = await verify(logPath, nodeDigestHex);
  assert.equal(valid, false);
  assert.equal(brokenAt, target, 'brokenAt must point at the altered record');
  assert.match(reason, /hash mismatch|contents were altered/);
});

test('flipping a single byte in the middle of the raw file is caught at that record', async () => {
  appendMany(logPath, 6);
  const lines = readFileSync(logPath, 'utf8').trim().split('\n');
  const target = 3;
  // flip one hex char of the stored hash -- a genuine single-byte mutation
  // that keeps the line valid JSON (so it parses, but no longer verifies)
  const rec = JSON.parse(lines[target]);
  const c = rec.hash[10];
  rec.hash = rec.hash.slice(0, 10) + (c === 'a' ? 'b' : 'a') + rec.hash.slice(11);
  lines[target] = JSON.stringify(rec);
  writeFileSync(logPath, lines.join('\n') + '\n');

  const { valid, brokenAt } = await verify(logPath, nodeDigestHex);
  assert.equal(valid, false);
  assert.equal(brokenAt, target);
});

test('deleting a record mid-chain is caught (seq gap / linkage break)', async () => {
  appendMany(logPath, 6);
  const lines = readFileSync(logPath, 'utf8').trim().split('\n');
  lines.splice(3, 1); // remove record 3
  writeFileSync(logPath, lines.join('\n') + '\n');

  const { valid, brokenAt } = await verify(logPath, nodeDigestHex);
  assert.equal(valid, false);
  assert.equal(brokenAt, 3, 'the gap surfaces at the index where the removed record used to be');
});

test('reordering two records is caught', async () => {
  appendMany(logPath, 6);
  const lines = readFileSync(logPath, 'utf8').trim().split('\n');
  [lines[2], lines[3]] = [lines[3], lines[2]];
  writeFileSync(logPath, lines.join('\n') + '\n');

  const { valid, brokenAt } = await verify(logPath, nodeDigestHex);
  assert.equal(valid, false);
  assert.equal(brokenAt, 2);
});

test('appending a forged record with a made-up hash is caught at the forged record', async () => {
  appendMany(logPath, 4);
  const forged = { seq: 4, ts: new Date().toISOString(), type: 'EXECUTION_RESULT', payload: { status: 'confirmed' }, prevHash: 'deadbeef'.repeat(8), hash: 'f'.repeat(64) };
  writeFileSync(logPath, readFileSync(logPath, 'utf8') + JSON.stringify(forged) + '\n');
  const { valid, brokenAt } = await verify(logPath, nodeDigestHex);
  assert.equal(valid, false);
  assert.equal(brokenAt, 4);
});

// ---------------------------------------------------------------------------
// Ordering under rapid sequential appends
// ---------------------------------------------------------------------------

test('rapid sequential appends yield a densely-ordered, valid chain (no interleaved hashes)', async () => {
  const recs = appendMany(logPath, 100);
  assert.deepEqual(
    recs.map((r) => r.seq),
    Array.from({ length: 100 }, (_, i) => i),
  );
  const { valid } = await verify(logPath, nodeDigestHex);
  assert.equal(valid, true);
});

// ---------------------------------------------------------------------------
// Concurrent writers -- regression for the real production incident
// (docs/FAILURE-MODES.md: the systemd watcher and a manually-run
// attack/run-demo.mjs both appended to the same default deplex-audit.jsonl
// path as genuinely independent OS processes, producing a duplicate seq
// and a permanently broken chain). A same-process test cannot reproduce
// this -- JS's single-threaded execution already prevents a process from
// racing itself -- so this spawns real child processes.
// ---------------------------------------------------------------------------

test('multiple independent OS processes appending to the same log never collide on seq -- the chain stays dense and valid', async () => {
  const WORKERS = 4;
  const PER_WORKER = 15;

  function runWorker() {
    return new Promise((resolve, reject) => {
      const child = spawn(process.execPath, [CONCURRENT_WORKER, logPath, String(PER_WORKER)]);
      let stderr = '';
      child.stderr.on('data', (d) => (stderr += d));
      child.on('error', reject);
      child.on('exit', (code) => (code === 0 ? resolve() : reject(new Error(`worker exited ${code}: ${stderr}`))));
    });
  }

  // Launched together (not awaited one at a time) so their appends actually
  // overlap in real time, the same way the watcher and a manually-run
  // attack demo genuinely do.
  await Promise.all(Array.from({ length: WORKERS }, runWorker));

  const records = readAll(logPath);
  assert.equal(records.length, WORKERS * PER_WORKER, 'no write lost, none duplicated');

  const seqs = records.map((r) => r.seq).sort((a, b) => a - b);
  assert.deepEqual(
    seqs,
    Array.from({ length: WORKERS * PER_WORKER }, (_, i) => i),
    'seq must be dense 0..N-1 with no gaps or duplicates across processes',
  );

  const { valid, brokenAt, reason } = await verify(logPath, nodeDigestHex);
  assert.equal(valid, true, `chain must verify after concurrent multi-process writes (broke at ${brokenAt}: ${reason})`);
});

// ---------------------------------------------------------------------------
// Migration of the legacy (pre-Phase-4) format
// ---------------------------------------------------------------------------

test('rechainRecords rebuilds a valid chain from legacy {ts,type,payload} records', async () => {
  const legacy = [
    { ts: '2026-07-01T00:00:00.000Z', type: 'OBSERVATION', payload: { a: 1 } },
    { ts: '2026-07-01T00:00:01.000Z', type: 'EVENT', payload: { b: 2 } },
    { ts: '2026-07-01T00:00:02.000Z', type: 'DECISION', payload: { c: 3 } },
  ];
  const chained = rechainRecords(legacy);
  assert.deepEqual(chained.map((r) => r.seq), [0, 1, 2]);
  assert.equal(chained[0].prevHash, GENESIS_PREV_HASH);
  assert.deepEqual(await verifyChain(chained, nodeDigestHex), { valid: true, brokenAt: null, reason: null });
  // original ts/type/payload preserved verbatim
  assert.equal(chained[1].type, 'EVENT');
  assert.deepEqual(chained[2].payload, { c: 3 });
});

test('migrateFile upgrades a legacy log file in place and the result verifies', async () => {
  const legacyLines = [
    { ts: '2026-07-01T00:00:00.000Z', type: 'OBSERVATION', payload: { a: 1 } },
    { ts: '2026-07-01T00:00:01.000Z', type: 'EVENT', payload: { b: 2 } },
  ].map((r) => JSON.stringify(r));
  writeFileSync(logPath, legacyLines.join('\n') + '\n');

  const count = migrateFile(logPath);
  assert.equal(count, 2);
  const { valid } = await verify(logPath, nodeDigestHex);
  assert.equal(valid, true);
  // and appends continue the chain cleanly post-migration
  const next = append(logPath, 'RESET', { kind: 'operator_reset' });
  assert.equal(next.seq, 2);
  assert.equal((await verify(logPath, nodeDigestHex)).valid, true);
});

test('appending to a legacy (unchained) log throws instead of silently corrupting the chain', () => {
  writeFileSync(logPath, JSON.stringify({ ts: '2026-07-01T00:00:00.000Z', type: 'EVENT', payload: {} }) + '\n');
  assert.throws(() => append(logPath, 'EVENT', {}), /unchained format|migrate/);
});

// ---------------------------------------------------------------------------
// The real, historical log as a fixture (skips gracefully if absent)
// ---------------------------------------------------------------------------

test('the real migrated audit log verifies, and a mid-chain tamper is pinpointed', async (t) => {
  if (!existsSync(REAL_LOG)) {
    t.skip('deplex-audit.jsonl not present (clean checkout) -- run the watcher/demo to generate it');
    return;
  }
  const records = readAll(REAL_LOG);
  if (records.length < 5 || typeof records[0].hash !== 'string') {
    t.skip('real log too short or not yet migrated to chained format');
    return;
  }
  // verify the untouched real chain
  const intact = await verifyChain(records, webCryptoDigestHex);
  assert.equal(intact.valid, true, `real log should verify but broke at ${intact.brokenAt}: ${intact.reason}`);

  // copy to temp, flip one byte partway through, confirm the exact record is found
  const fixture = join(tmpDir, 'real-copy.jsonl');
  copyFileSync(REAL_LOG, fixture);
  const lines = readFileSync(fixture, 'utf8').trim().split('\n');
  const target = Math.floor(lines.length / 2);
  const rec = JSON.parse(lines[target]);
  const c = rec.hash[0];
  rec.hash = (c === '0' ? '1' : '0') + rec.hash.slice(1); // one-char flip of the stored hash
  lines[target] = JSON.stringify(rec);
  writeFileSync(fixture, lines.join('\n') + '\n');

  const tampered = await verify(fixture, webCryptoDigestHex);
  assert.equal(tampered.valid, false);
  assert.equal(tampered.brokenAt, target, 'tamper in the real log must be pinpointed to the exact record');
});
