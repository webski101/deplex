// One-shot diagnostic: how long does a HEALTHY execute_transfer actually
// take? Every KeeperHub timeout observed (four, across two nights, see
// docs/KEEPERHUB-NOTES.md) landed on an action-submitting call
// (execute_transfer / execute_contract_call), never on a read/handshake --
// which are fast (initialize 252ms, tools/list 47ms). This measures the
// write path directly to settle whether it's "just slower than 20s
// sometimes" (a client-timeout-too-tight config issue) vs. genuinely hung.
//
// THE KEY TRICK: this deliberately runs with a HIGH request timeout
// (TIME_TEST_TIMEOUT_MS, default 90000) -- because measuring with the
// normal 20000ms cap would abort a slow-but-healthy call at exactly the
// boundary and produce yet another useless timeout instead of the actual
// completion time. You cannot measure past a timeout you leave in place.
//
// Harmless by construction: a tiny native transfer to SAFE_ADDRESS (your
// own safe wallet -- funds don't leave your control), amount configurable
// via TIME_TEST_AMOUNT_WEI (default 1000 wei = 0.000000000000001 ETH,
// negligible), gas is sponsored server-side. Reuses the exact
// executeTransfer path responder.mjs's EVACUATE uses, so the timing
// reflects the real code, not a synthetic call.
//
// Usage: node scripts/time-execute-transfer.mjs
// Needs: KEEPERHUB_API_KEY, SAFE_ADDRESS (or pass a recipient as argv[2]).
//        CHAIN_ID optional (defaults Sepolia).

import { KeeperHubClient, executeTransfer, pollExecution } from '../src/keeperhub.mjs';
import { loadConfig } from '../src/config.mjs';

const cfg = loadConfig();
if (!cfg.keeperHub.apiKey) {
  console.error('KEEPERHUB_API_KEY is not set');
  process.exit(1);
}

const recipient = process.argv[2] || cfg.safeAddress;
if (!recipient) {
  console.error('no recipient: set SAFE_ADDRESS or pass one as the first argument');
  console.error('(kept to your own safe wallet on purpose -- this is a diagnostic, not a real transfer)');
  process.exit(1);
}

const amountWei = process.env.TIME_TEST_AMOUNT_WEI || '1000';
const timeoutMs = Number(process.env.TIME_TEST_TIMEOUT_MS || 90000);

// Force debug timing on (per-call ms line) and the high timeout, regardless
// of the ambient env -- the whole point of this script.
const client = new KeeperHubClient({ ...cfg.keeperHub, requestTimeoutMs: timeoutMs, debug: true });

console.log(`Timing a healthy execute_transfer (native, ${amountWei} wei -> ${recipient})`);
console.log(`request timeout raised to ${timeoutMs}ms for this measurement (normal default is ${cfg.keeperHub.requestTimeoutMs}ms)\n`);

let exitCode = 0;
try {
  const submitStart = Date.now();
  const submitted = await executeTransfer(client, {
    chain: cfg.chainId,
    to: recipient,
    amount: amountWei,
  });
  const submitMs = Date.now() - submitStart;
  console.log(`\nexecute_transfer submit call: ${submitMs}ms  (status: ${submitted.status ?? 'n/a'}, executionId: ${submitted.executionId ?? 'none'})`);

  if (submitted.executionId) {
    const pollStart = Date.now();
    const final = await pollExecution(client, submitted.executionId, {
      intervalMs: cfg.keeperHub.pollIntervalMs,
      timeoutMs: cfg.keeperHub.pollTimeoutMs,
    });
    console.log(`poll-to-terminal: ${Date.now() - pollStart}ms  (final status: ${final.status}, txHash: ${final.txHash ?? 'none'})`);
    if (!final.txHash) exitCode = 1;
  }

  console.log(`\n--- interpretation ---`);
  console.log(`if the submit call above is comfortably under 20000ms: the timeouts were transient, not structural.`);
  console.log(`if it's in the high teens or over 20000ms but still SUCCEEDED here: execution is legitimately slower`);
  console.log(`than reads, and the fix is a higher KEEPERHUB_REQUEST_TIMEOUT_MS for execution calls -- not a KeeperHub bug.`);
} catch (err) {
  console.error(`\nexecute_transfer FAILED after the ${timeoutMs}ms window: ${err.message}`);
  console.error(`(even the raised timeout didn't let it complete -- this argues for genuinely hung, not merely slow)`);
  exitCode = 1;
} finally {
  await client.closeSession();
}
process.exit(exitCode);
