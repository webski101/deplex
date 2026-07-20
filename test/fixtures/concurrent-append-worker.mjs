// Worker process for test/auditlog.test.mjs's concurrent-writer regression
// test. Deliberately a separate OS process (not a function called
// in-process) -- the bug this proves fixed (docs/FAILURE-MODES.md's
// "concurrent-writer seq collision" entry) only reproduces across
// genuinely independent processes; a same-process test can't exercise it,
// since JS's single-threaded execution already prevents self-interleaving.
//
// Usage: node concurrent-append-worker.mjs <path> <count>

import { append } from '../../src/auditlog.mjs';

const [, , path, countStr] = process.argv;
const count = Number(countStr);

for (let i = 0; i < count; i++) {
  append(path, 'EVENT', { worker: process.pid, i });
}
