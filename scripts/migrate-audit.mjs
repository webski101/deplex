// One-time upgrade of a pre-Phase-4 (unchained) audit log to the SHA-256
// hash-chained format. Non-destructive: writes a .legacy-bak backup of the
// original first, then migrates in place and verifies the result.
//
// Usage: node scripts/migrate-audit.mjs [path]
//   path defaults to the configured AUDIT_LOG_FILE (./deplex-audit.jsonl).

import { copyFileSync, existsSync } from 'node:fs';
import { loadConfig } from '../src/config.mjs';
import { readAll, migrateFile, verify, nodeDigestHex } from '../src/auditlog.mjs';

const cfg = loadConfig();
const path = process.argv[2] || cfg.auditLogPath;

if (!existsSync(path)) {
  console.error(`no audit log at ${path} -- nothing to migrate`);
  process.exit(1);
}

const before = readAll(path);
console.log(`${path}: ${before.length} records`);

const alreadyChained = before.length > 0 && typeof before[before.length - 1].hash === 'string' && typeof before[before.length - 1].seq === 'number';
if (alreadyChained) {
  console.log('already in chained format -- verifying, not re-migrating');
  const result = await verify(path, nodeDigestHex);
  console.log(result.valid ? 'VALID' : `BROKEN at record ${result.brokenAt}: ${result.reason}`);
  process.exit(result.valid ? 0 : 1);
}

const backup = `${path}.legacy-bak`;
copyFileSync(path, backup);
console.log(`backed up original to ${backup}`);

const count = migrateFile(path);
console.log(`migrated ${count} records to chained format`);

const result = await verify(path, nodeDigestHex);
if (result.valid) {
  console.log('VALID -- migrated chain verifies end to end');
  process.exit(0);
} else {
  console.error(`BROKEN at record ${result.brokenAt}: ${result.reason}`);
  console.error(`original preserved at ${backup}`);
  process.exit(1);
}
