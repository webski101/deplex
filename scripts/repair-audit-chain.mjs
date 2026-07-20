// One-time repair for an already-chained audit log broken mid-chain --
// e.g. a duplicate seq from a confirmed concurrent-writer collision (see
// docs/FAILURE-MODES.md's "concurrent-writer seq collision" entry).
//
// Unlike migrate-audit.mjs (which only upgrades a pre-Phase-4 UNCHAINED
// log, and only VERIFIES an already-chained one without fixing it), this
// re-derives a consistent chain from the records' CURRENT FILE ORDER,
// preserving every record's original ts/type/payload verbatim. Nothing is
// dropped, nothing is invented, nothing is reordered -- only seq/prevHash/
// hash are recomputed to match physical file position.
//
// This is NOT the right tool for a log broken by genuine tampering (an
// altered payload or forged hash) -- rechaining would silently "heal" a
// tampered record instead of flagging it. Confirm WHY the chain is broken
// before running this; only use it once the cause is understood and
// confirmed to be a structural/ordering issue (like this project's
// concurrent-writer incident), not tampering.
//
// Usage: node scripts/repair-audit-chain.mjs [path]
//   path defaults to the configured AUDIT_LOG_FILE (./deplex-audit.jsonl).
// Always backs up the original first, to <path>.pre-repair-bak -- kept
// permanently, not cleaned up automatically, so the broken original stays
// available for the record.

import { copyFileSync, existsSync } from 'node:fs';
import { loadConfig } from '../src/config.mjs';
import { readAll, migrateFile, verify, nodeDigestHex } from '../src/auditlog.mjs';

const cfg = loadConfig();
const path = process.argv[2] || cfg.auditLogPath;

if (!existsSync(path)) {
  console.error(`no audit log at ${path} -- nothing to repair`);
  process.exit(1);
}

const before = await verify(path, nodeDigestHex);
if (before.valid) {
  console.log(`${path} already verifies end to end -- nothing to repair.`);
  process.exit(0);
}
console.log(`${path}: broken at record ${before.brokenAt} (${before.reason})`);

const records = readAll(path);
console.log(`${records.length} total records read (raw file order preserved)`);

// Evidence, before touching anything -- exactly what's at and around the
// break point, for the incident writeup.
const around = records.slice(Math.max(0, before.brokenAt - 2), before.brokenAt + 3);
console.log(`\nRecords around the break point (unmodified):`);
for (const r of around) {
  console.log(`  seq=${r.seq} ts=${r.ts} type=${r.type}`);
}

const backup = `${path}.pre-repair-bak`;
copyFileSync(path, backup);
console.log(`\nbacked up the broken original to ${backup} (kept permanently)`);

const count = migrateFile(path); // rechains in place: same ts/type/payload per record, fresh seq/prevHash/hash
console.log(`rechained ${count} records from current file order`);

const after = await verify(path, nodeDigestHex);
if (after.valid) {
  console.log(`\nVALID -- repaired chain verifies end to end.`);
  console.log(`Original (broken) file preserved at ${backup} for the record.`);
  process.exit(0);
} else {
  console.error(`\nSTILL BROKEN at record ${after.brokenAt}: ${after.reason} -- rechaining alone did not fix this.`);
  console.error(`Original preserved at ${backup}. Do not proceed without investigating further.`);
  process.exit(1);
}
