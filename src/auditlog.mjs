// SHA-256 hash-chained append-only incident log (Node file-I/O layer).
//
// The cross-platform chain logic (preimage, walk, WebCrypto digest) lives in
// auditchain.mjs with zero node imports so the dashboard can verify in the
// browser. This file adds synchronous, ordered appends and file reads.
//
// Record shape: { seq, ts, type, payload, prevHash, hash }
//   hash = SHA-256(seq + ts + type + JSON(payload) + prevHash)  [hex]
//   genesis prevHash = "0".repeat(64)

import { appendFileSync, readFileSync, writeFileSync, renameSync, existsSync, openSync, closeSync, unlinkSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { GENESIS_PREV_HASH, recordPreimage, verifyChain, webCryptoDigestHex } from './auditchain.mjs';

export { GENESIS_PREV_HASH, verifyChain, webCryptoDigestHex } from './auditchain.mjs';

// Synchronous node:crypto digest -- used by the hot append path, which must
// stay sync so appends can't interleave and corrupt the chain. Produces
// byte-identical output to webCryptoDigestHex for the same input.
export function nodeDigestHex(text) {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

class LegacyAuditLogError extends Error {}

// ---------------------------------------------------------------------------
// Cross-process advisory lock
//
// Confirmed live (2026-07-20, see docs/FAILURE-MODES.md's "concurrent-
// writer seq collision" entry): the systemd watcher and a manually-run
// `attack/run-demo.mjs` both append to the SAME default deplex-audit.jsonl
// path, as two genuinely independent OS processes. append() previously
// trusted an in-memory tail cache seeded once per process -- fine within
// one process (JS is single-threaded, no self-interleaving possible), but
// each process's cache went stale the instant the OTHER process appended,
// so both eventually computed the same "next seq" and both wrote it,
// producing a duplicate seq and a permanently broken chain from that point
// forward. A single process is not the unit of coordination this project
// actually needs -- the attack demo is deliberately designed to run
// alongside the watcher (see attack/run-demo.mjs's own header), so the fix
// has to coordinate ACROSS processes, not just avoid a stale cache: an
// exclusive lockfile around the read-tail-then-write critical section,
// with the tail always re-read fresh from disk while holding it.
// ---------------------------------------------------------------------------

const LOCK_RETRY_MS = 20;
const LOCK_TIMEOUT_MS = 10000; // loud failure beats a silent hang
const LOCK_STALE_MS = 30000; // recovers from a process that crashed mid-append still holding the lock

function acquireLock(path) {
  const lockPath = `${path}.lock`;
  const deadline = Date.now() + LOCK_TIMEOUT_MS;
  // eslint-disable-next-line no-constant-condition
  while (true) {
    try {
      closeSync(openSync(lockPath, 'wx')); // atomic exclusive create -- fails if another process already holds it
      return lockPath;
    } catch (err) {
      if (err.code !== 'EEXIST') throw err;
      try {
        if (Date.now() - statSync(lockPath).mtimeMs > LOCK_STALE_MS) {
          unlinkSync(lockPath); // stale -- the process that held it is gone; retry immediately
          continue;
        }
      } catch {
        // lock file vanished between the EEXIST and this check -- another
        // process released it; fall through to retry below
      }
      if (Date.now() > deadline) {
        throw new Error(`audit log ${path} is locked by another process and did not release within ${LOCK_TIMEOUT_MS}ms`);
      }
      // Synchronous busy-wait, deliberately: append() is used from the hot
      // synchronous path throughout this codebase (see nodeDigestHex's own
      // comment) -- making it async would ripple into every call site.
      // Contention should be rare and hold time is always a single
      // read-then-write of one line, never seconds under normal operation.
      const spinUntil = Date.now() + LOCK_RETRY_MS;
      while (Date.now() < spinUntil) {
        /* spin */
      }
    }
  }
}

function releaseLock(lockPath) {
  try {
    unlinkSync(lockPath);
  } catch {
    // already gone -- fine
  }
}

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
  const lockPath = acquireLock(path);
  try {
    // Always read the true current tail from disk while holding the lock --
    // trusting a per-process cache here is exactly what caused the
    // concurrent-writer collision this lock exists to prevent (see the
    // module comment above).
    const tail = loadTail(path);
    const seq = tail.seq + 1;
    const ts = new Date().toISOString();
    const prevHash = tail.hash;
    const hash = nodeDigestHex(recordPreimage(seq, ts, type, payload, prevHash));
    const record = { seq, ts, type, payload, prevHash, hash };

    const line = JSON.stringify(record);
    console.log(line);
    appendFileSync(path, line + '\n');
    return record;
  } finally {
    releaseLock(lockPath);
  }
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
//
// Holds the same lock append() does: a full-file rewrite racing an
// in-flight append could otherwise silently lose that append's write (the
// migration's rename would overwrite it). migrateFile is a manual,
// operator-invoked, one-time operation -- not something the watcher or any
// automated process calls -- so this mainly guards against running it by
// hand while something else happens to be mid-append, rather than a
// scenario expected in normal operation.
export function migrateFile(srcPath, destPath = srcPath) {
  const lockPath = acquireLock(destPath);
  try {
    const chained = rechainRecords(readAll(srcPath));
    const out = chained.map((r) => JSON.stringify(r)).join('\n') + (chained.length ? '\n' : '');
    const tmp = `${destPath}.tmp`;
    writeFileSync(tmp, out);
    renameSync(tmp, destPath);
    return chained.length;
  } finally {
    releaseLock(lockPath);
  }
}
