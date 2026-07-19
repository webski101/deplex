// SHA-256 hash-chained append-only incident log (Node file-I/O layer).
//
// The cross-platform chain logic (preimage, walk, WebCrypto digest) lives in
// auditchain.mjs with zero node imports so the dashboard can verify in the
// browser. This file adds synchronous, ordered appends and file reads.
//
// Record shape: { seq, ts, type, payload, prevHash, hash }
//   hash = SHA-256(seq + ts + type + JSON(payload) + prevHash)  [hex]
//   genesis prevHash = "0".repeat(64)

import { appendFileSync, readFileSync, writeFileSync, renameSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { GENESIS_PREV_HASH, recordPreimage, verifyChain, webCryptoDigestHex } from './auditchain.mjs';

export { GENESIS_PREV_HASH, verifyChain, webCryptoDigestHex } from './auditchain.mjs';

// Synchronous node:crypto digest -- used by the hot append path, which must
// stay sync so appends can't interleave and corrupt the chain. Produces
// byte-identical output to webCryptoDigestHex for the same input.
export function nodeDigestHex(text) {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

// Per-path tail cache: { seq, hash } of the last appended record. Lazily
// seeded from the file so a fresh process resumes the chain correctly after
// a restart. Keyed by path so multiple logs don't cross-contaminate.
const tailCache = new Map();

class LegacyAuditLogError extends Error {}

function readLines(path) {
  if (!existsSync(path)) return [];
  return readFileSync(path, 'utf8')
    .split('\n')
    .filter((line) => line.trim().length > 0);
}

function parseLines(lines) {
  return lines.map((line) => {
    try {
      return JSON.parse(line);
    } catch {
      return null;
    }
  });
}

function loadTail(path) {
  const lines = readLines(path);
  if (lines.length === 0) return { seq: -1, hash: GENESIS_PREV_HASH };
  const last = parseLines(lines.slice(-1))[0];
  // A record written before Phase 4 has no seq/hash. Continuing the chain
  // from it would silently produce an unverifiable log, so refuse loudly and
  // point at the one-time migration instead of corrupting the ledger.
  if (last == null || typeof last.seq !== 'number' || typeof last.hash !== 'string') {
    throw new LegacyAuditLogError(
      `audit log ${path} is in the pre-Phase-4 unchained format; run scripts/migrate-audit.mjs to upgrade it before appending`,
    );
  }
  return { seq: last.seq, hash: last.hash };
}

export function append(path, type, payload) {
  let tail = tailCache.get(path);
  if (!tail) {
    tail = loadTail(path);
    tailCache.set(path, tail);
  }
  const seq = tail.seq + 1;
  const ts = new Date().toISOString();
  const prevHash = tail.hash;
  const hash = nodeDigestHex(recordPreimage(seq, ts, type, payload, prevHash));
  const record = { seq, ts, type, payload, prevHash, hash };

  const line = JSON.stringify(record);
  console.log(line);
  appendFileSync(path, line + '\n');
  tailCache.set(path, { seq, hash }); // advance only after the write succeeds
  return record;
}

export function readAll(path) {
  return parseLines(readLines(path)).filter(Boolean);
}

// Verify a log file. Defaults to WebCrypto so identical code runs here and in
// the dashboard; pass nodeDigestHex for a fully-synchronous Node check.
export async function verify(path, digest = webCryptoDigestHex) {
  return verifyChain(readAll(path), digest);
}

// Rebuild a valid chain over existing records, preserving their original
// ts/type/payload but recomputing seq/prevHash/hash. Pure (no I/O) so it can
// be unit-tested and reused; used by migrateFile below.
export function rechainRecords(records) {
  let prevHash = GENESIS_PREV_HASH;
  return records.map((r, i) => {
    const seq = i;
    const { ts, type, payload } = r;
    const hash = nodeDigestHex(recordPreimage(seq, ts, type, payload, prevHash));
    const record = { seq, ts, type, payload, prevHash, hash };
    prevHash = hash;
    return record;
  });
}

// One-time upgrade of a legacy (unchained) log to chained format. Writes
// atomically via a temp file + rename so a crash mid-migration can't leave a
// half-written ledger. Returns the number of records chained.
export function migrateFile(srcPath, destPath = srcPath) {
  const chained = rechainRecords(readAll(srcPath));
  const out = chained.map((r) => JSON.stringify(r)).join('\n') + (chained.length ? '\n' : '');
  const tmp = `${destPath}.tmp`;
  writeFileSync(tmp, out);
  renameSync(tmp, destPath);
  tailCache.delete(destPath); // force re-seed from the freshly migrated file
  return chained.length;
}

// Test seam: drop cached tail state (e.g. between temp-file test cases).
export function _resetTailCache() {
  tailCache.clear();
}
