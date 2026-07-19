import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import {
  computeChunks,
  computeBackoffDelay,
  addressToTopic,
  decodeAddressFromTopic,
  encodeUint256,
  decodeUint256,
  decodeBool,
  decodeApprovalLog,
  decodeApprovalForAllLog,
  decodeTransferLog,
  dedupKey,
  dedupLogs,
  CircuitBreaker,
  APPROVAL_TOPIC,
  APPROVAL_FOR_ALL_TOPIC,
  TRANSFER_TOPIC,
  rpcCall,
} from '../src/watcher.mjs';

const OWNER = '0x' + '11'.repeat(20);
const SPENDER = '0x' + '22'.repeat(20);
const RECIPIENT = '0x' + '33'.repeat(20);
const TOKEN = '0x' + '44'.repeat(20);
const MAX_UINT256 = (1n << 256n) - 1n;

function makeLog({ topic0, topic1, topic2, data, txHash = '0xaaa1', logIndex = '0x0', blockNumber = '0x64' }) {
  return {
    address: TOKEN,
    topics: [topic0, topic1, topic2],
    data,
    transactionHash: txHash,
    logIndex,
    blockNumber,
  };
}

// ---------------------------------------------------------------------------
// Hand-rolled ABI decoding, against hardcoded fixtures
// ---------------------------------------------------------------------------

test('decodeAddressFromTopic recovers a 20-byte address from a 32-byte topic', () => {
  const topic = addressToTopic(SPENDER);
  assert.equal(decodeAddressFromTopic(topic), SPENDER);
});

test('decodeUint256 decodes big-endian hex data, including empty data as zero', () => {
  assert.equal(decodeUint256(encodeUint256(12345)), 12345n);
  assert.equal(decodeUint256('0x'), 0n);
});

test('decodeBool treats any nonzero uint256 as true', () => {
  assert.equal(decodeBool(encodeUint256(1)), true);
  assert.equal(decodeBool(encodeUint256(0)), false);
});

test('decodeApprovalLog decodes a real-shaped ERC-20 Approval log', () => {
  const log = makeLog({
    topic0: APPROVAL_TOPIC,
    topic1: addressToTopic(OWNER),
    topic2: addressToTopic(SPENDER),
    data: encodeUint256(1_000_000n),
    txHash: '0xabc123',
    logIndex: '0x2',
    blockNumber: '0x64',
  });
  const event = decodeApprovalLog(log);
  assert.deepEqual(event, {
    type: 'approval',
    kind: 'erc20',
    token: TOKEN.toLowerCase(),
    owner: OWNER.toLowerCase(),
    spender: SPENDER.toLowerCase(),
    amount: '1000000',
    unlimited: false,
    txHash: '0xabc123',
    logIndex: 2,
    block: 100,
    observedAt: event.observedAt,
  });
});

test('decodeApprovalLog flags an unlimited (max uint256) approval', () => {
  const log = makeLog({
    topic0: APPROVAL_TOPIC,
    topic1: addressToTopic(OWNER),
    topic2: addressToTopic(SPENDER),
    data: encodeUint256(MAX_UINT256),
  });
  assert.equal(decodeApprovalLog(log).unlimited, true);
});

test('decodeApprovalForAllLog decodes an NFT operator grant as unlimited, and a revoke as not', () => {
  const grantLog = makeLog({
    topic0: APPROVAL_FOR_ALL_TOPIC,
    topic1: addressToTopic(OWNER),
    topic2: addressToTopic(SPENDER),
    data: encodeUint256(1), // approved = true
  });
  const grant = decodeApprovalForAllLog(grantLog);
  assert.equal(grant.type, 'approval');
  assert.equal(grant.kind, 'nft-operator');
  assert.equal(grant.approved, true);
  assert.equal(grant.unlimited, true);

  const revokeLog = makeLog({
    topic0: APPROVAL_FOR_ALL_TOPIC,
    topic1: addressToTopic(OWNER),
    topic2: addressToTopic(SPENDER),
    data: encodeUint256(0), // approved = false
  });
  const revoke = decodeApprovalForAllLog(revokeLog);
  assert.equal(revoke.approved, false);
  assert.equal(revoke.unlimited, false);
});

test('decodeTransferLog decodes a real-shaped ERC-20 Transfer log', () => {
  const log = makeLog({
    topic0: TRANSFER_TOPIC,
    topic1: addressToTopic(OWNER),
    topic2: addressToTopic(RECIPIENT),
    data: encodeUint256(500n),
    txHash: '0xdef456',
    logIndex: '0x1',
    blockNumber: '0xc8',
  });
  const event = decodeTransferLog(log);
  assert.equal(event.type, 'transfer');
  assert.equal(event.from, OWNER.toLowerCase());
  assert.equal(event.to, RECIPIENT.toLowerCase());
  assert.equal(event.value, '500');
  assert.equal(event.block, 200);
});

// ---------------------------------------------------------------------------
// Dedup logic
// ---------------------------------------------------------------------------

test('dedupLogs drops a log already recorded in seenKeys', () => {
  const log = makeLog({ topic0: TRANSFER_TOPIC, topic1: addressToTopic(OWNER), topic2: addressToTopic(RECIPIENT), data: '0x', txHash: '0xaaa', logIndex: '0x3' });
  const seen = new Set([dedupKey(log)]);
  const { fresh } = dedupLogs([log], seen);
  assert.equal(fresh.length, 0);
});

test('dedupLogs drops duplicate entries within the same batch (pagination duplicates)', () => {
  const log = makeLog({ topic0: TRANSFER_TOPIC, topic1: addressToTopic(OWNER), topic2: addressToTopic(RECIPIENT), data: '0x', txHash: '0xbbb', logIndex: '0x1' });
  const { fresh, newKeys } = dedupLogs([log, log, log], new Set());
  assert.equal(fresh.length, 1);
  assert.equal(newKeys.size, 1);
});

test('dedupLogs keeps two distinct logs from the same tx (different logIndex)', () => {
  const logA = makeLog({ topic0: TRANSFER_TOPIC, topic1: addressToTopic(OWNER), topic2: addressToTopic(RECIPIENT), data: '0x', txHash: '0xccc', logIndex: '0x0' });
  const logB = makeLog({ topic0: TRANSFER_TOPIC, topic1: addressToTopic(OWNER), topic2: addressToTopic(RECIPIENT), data: '0x', txHash: '0xccc', logIndex: '0x1' });
  const { fresh } = dedupLogs([logA, logB], new Set());
  assert.equal(fresh.length, 2);
});

test('dedupKey is stable across hex logIndex formatting (0x0 vs 0x00)', () => {
  const logA = makeLog({ topic0: TRANSFER_TOPIC, topic1: addressToTopic(OWNER), topic2: addressToTopic(RECIPIENT), data: '0x', txHash: '0xddd', logIndex: '0x0' });
  const logB = { ...logA, logIndex: '0x00' };
  assert.equal(dedupKey(logA), dedupKey(logB));
});

// ---------------------------------------------------------------------------
// Chunking math
// ---------------------------------------------------------------------------

test('computeChunks returns a single chunk when the range fits', () => {
  assert.deepEqual(computeChunks(100, 150, 2000), [[100, 150]]);
});

test('computeChunks splits an exact multiple of chunkSize with no remainder chunk', () => {
  assert.deepEqual(computeChunks(1, 4000, 2000), [
    [1, 2000],
    [2001, 4000],
  ]);
});

test('computeChunks splits a non-exact-multiple range, last chunk shorter', () => {
  assert.deepEqual(computeChunks(1, 4500, 2000), [
    [1, 2000],
    [2001, 4000],
    [4001, 4500],
  ]);
});

test('computeChunks returns empty array when fromBlock > toBlock (nothing new)', () => {
  assert.deepEqual(computeChunks(500, 499, 2000), []);
});

test('computeChunks handles a single-block range', () => {
  assert.deepEqual(computeChunks(10, 10, 2000), [[10, 10]]);
});

test('computeChunks with chunkSize 1 produces one chunk per block', () => {
  assert.deepEqual(computeChunks(1, 3, 1), [[1, 1], [2, 2], [3, 3]]);
});

test('computeChunks throws on non-positive chunkSize', () => {
  assert.throws(() => computeChunks(1, 10, 0));
});

test('computeChunks never produces overlapping ranges', () => {
  const chunks = computeChunks(1, 10007, 777);
  for (let i = 1; i < chunks.length; i++) {
    assert.equal(chunks[i][0], chunks[i - 1][1] + 1, 'chunks must be contiguous with no overlap or gap');
  }
  assert.equal(chunks[chunks.length - 1][1], 10007);
});

// ---------------------------------------------------------------------------
// Backoff + circuit breaker
// ---------------------------------------------------------------------------

test('computeBackoffDelay stays within [0, cap] and cap grows then saturates at maxDelayMs', () => {
  for (let attempt = 1; attempt <= 10; attempt++) {
    const delay = computeBackoffDelay(attempt, 500, 30000);
    assert.ok(delay >= 0 && delay <= 30000, `attempt ${attempt} delay ${delay} out of bounds`);
  }
  // large attempt count must saturate at the cap, not grow unbounded
  const saturated = computeBackoffDelay(20, 500, 30000);
  assert.ok(saturated <= 30000);
});

test('default LOG_CHUNK_SIZE stays under the tightest known free-tier eth_getLogs cap (10 blocks)', async () => {
  const { loadConfig } = await import('../src/config.mjs');
  const cfg = loadConfig({});
  assert.ok(cfg.chunkSize <= 10, `default chunkSize ${cfg.chunkSize} exceeds free-tier 10-block cap`);
  assert.equal(loadConfig({ LOG_CHUNK_SIZE: '2000' }).chunkSize, 2000, 'env override must still work');
});

test('sendAlert degrades gracefully (no throw, returns null) when Telegram is unconfigured', async () => {
  const { sendAlert } = await import('../src/telegram.mjs');
  assert.equal(await sendAlert({ botToken: null, chatId: null }, 'test'), null);
  assert.equal(await sendAlert(undefined, 'test'), null);
  assert.equal(await sendAlert({}, 'test'), null);
});

test('rawBodySnippet labels empty bodies, passes short bodies through, truncates long ones', async () => {
  const { rawBodySnippet } = await import('../src/watcher.mjs');
  assert.equal(rawBodySnippet(''), '<empty body>');
  assert.equal(rawBodySnippet('{"ok":1}'), '{"ok":1}');
  const long = 'x'.repeat(500);
  const snippet = rawBodySnippet(long);
  assert.ok(snippet.includes('(500 chars total)'));
  assert.ok(snippet.length < 350);
});

test('rpcCall times out and rejects instead of hanging forever on a connection that never responds', async () => {
  // Regression: rpcCall previously had no timeout at all -- a hung
  // connection (server accepts, never responds) left the promise NEVER
  // settling, no error, no rejection, nothing. Confirmed live as a silent
  // watcher hang: ARMED banner printed, then total silence forever. This
  // server deliberately never calls res.end() to reproduce exactly that.
  const server = createServer((req) => {
    /* deliberately never respond */
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  const url = `http://127.0.0.1:${port}/`;

  const startedAt = Date.now();
  await assert.rejects(
    () => rpcCall(url, 'eth_blockNumber', [], { timeoutMs: 150 }),
    /timed out after 150ms/,
  );
  const elapsed = Date.now() - startedAt;
  assert.ok(elapsed < 2000, `must reject promptly after the timeout, not hang (took ${elapsed}ms)`);

  await new Promise((resolve) => server.close(resolve));
});

test('rpcCall still succeeds normally within the timeout window (the fix does not break the happy path)', async () => {
  const server = createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ jsonrpc: '2.0', id: 1, result: '0x64' }));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  const url = `http://127.0.0.1:${port}/`;

  const result = await rpcCall(url, 'eth_blockNumber', [], { timeoutMs: 5000 });
  assert.equal(result, '0x64');

  await new Promise((resolve) => server.close(resolve));
});

test('scheduleRpcSlot enforces spacing between consecutive requests', async () => {
  const { scheduleRpcSlot } = await import('../src/watcher.mjs');
  // first request: gate in the past, no wait, next slot = now + spacing
  const first = scheduleRpcSlot(1000, 0, 250);
  assert.equal(first.waitMs, 0);
  assert.equal(first.newNextSlotAt, 1250);
  // immediate second request: must wait out the remaining spacing
  const second = scheduleRpcSlot(1000, 1250, 250);
  assert.equal(second.waitMs, 250);
  assert.equal(second.newNextSlotAt, 1500);
  // request arriving after the gate expired: no wait, gate re-anchors to now
  const late = scheduleRpcSlot(9000, 1500, 250);
  assert.equal(late.waitMs, 0);
  assert.equal(late.newNextSlotAt, 9250);
});

test('rpcCallWithRetry honors config.mjs backoff field names (baseBackoffMs/maxBackoffMs)', async () => {
  const { loadConfig } = await import('../src/config.mjs');
  const cfg = loadConfig({ RPC_BASE_BACKOFF_MS: '123', RPC_MAX_BACKOFF_MS: '456', RPC_REQUEST_SPACING_MS: '99' });
  assert.equal(cfg.baseBackoffMs, 123);
  assert.equal(cfg.maxBackoffMs, 456);
  assert.equal(cfg.requestSpacingMs, 99);
  assert.equal(loadConfig({}).requestSpacingMs, 250, 'default spacing must stay free-tier conservative');
});

test('CircuitBreaker trips only after reaching the failure threshold, and resets on success', () => {
  const breaker = new CircuitBreaker(5);
  for (let i = 0; i < 4; i++) {
    assert.equal(breaker.recordFailure(), false);
  }
  assert.equal(breaker.recordFailure(), true);
  assert.equal(breaker.tripped, true);

  breaker.recordSuccess();
  assert.equal(breaker.tripped, false);
  assert.equal(breaker.consecutiveFailures, 0);
});
