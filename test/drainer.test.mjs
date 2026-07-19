import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { generateAttackerKey, selector, encodeAddressArg, encodeUint256Arg, isNftVectorAvailable, ensureWethBalance, WETH_SEPOLIA } from '../attack/drainer.mjs';
import { KeeperHubClient } from '../src/keeperhub.mjs';

// ---------------------------------------------------------------------------
// Minimal mock MCP server -- same pattern as test/keeperhub.test.mjs, kept
// local/self-contained rather than shared, since this is the one test here
// that needs a real KeeperHub round trip (ensureWethBalance's failure path).
// ---------------------------------------------------------------------------

function startMockServer(responder) {
  return new Promise((resolve) => {
    const server = createServer((req, res) => {
      let body = '';
      req.on('data', (c) => {
        body += c;
      });
      req.on('end', async () => {
        let parsed;
        try {
          parsed = JSON.parse(body);
        } catch {
          parsed = null;
        }
        const { status = 200, headers = {}, payload } = await responder(parsed);
        res.writeHead(status, { 'Content-Type': 'application/json', ...headers });
        res.end(payload !== undefined ? JSON.stringify(payload) : undefined);
      });
    });
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({ server, url: `http://127.0.0.1:${port}/mcp` });
    });
  });
}

function closeServer(server) {
  return new Promise((resolve) => server.close(resolve));
}

// Single mock endpoint serving BOTH protocols ensureWethBalance actually
// talks to: plain eth_call JSON-RPC (getTokenBalance, against cfg.rpcUrl)
// and the MCP handshake/tool-call envelope (against cfg.keeperHub.mcpUrl) --
// distinguished by `method`, since both are just JSON-RPC POSTs.
function withHandshakeAndBalance(toolCallHandler, { balanceHex = '0x0' } = {}) {
  return async (parsed) => {
    if (!parsed) return { status: 400 };
    if (parsed.method === 'eth_call') {
      return { payload: { jsonrpc: '2.0', id: parsed.id, result: balanceHex } };
    }
    if (parsed.method === 'initialize') {
      return {
        payload: { jsonrpc: '2.0', id: parsed.id, result: { protocolVersion: '2024-11-05', capabilities: {}, serverInfo: { name: 'mock' } } },
        headers: { 'Mcp-Session-Id': 'sess-test' },
      };
    }
    if (parsed.method === 'notifications/initialized') return { status: 202 };
    return toolCallHandler(parsed);
  };
}

function makeCfg(url) {
  return {
    rpcUrl: url,
    chainId: '11155111',
    watchedWallet: '0x' + '22'.repeat(20),
    keeperHub: { apiKey: 'k', mcpUrl: url, pollIntervalMs: 1, pollTimeoutMs: 1000 },
  };
}

test('generateAttackerKey produces a fresh, well-formed key + matching address each call', () => {
  const a = generateAttackerKey();
  const b = generateAttackerKey();
  assert.match(a.privateKeyHex, /^0x[0-9a-f]{64}$/);
  assert.match(a.address, /^0x[0-9a-f]{40}$/);
  assert.notEqual(a.privateKeyHex, b.privateKeyHex, 'must be fresh, not reused');
  assert.notEqual(a.address, b.address);
});

test('selector("transferFrom(address,address,uint256)") matches the well-known real-world constant 0x23b872dd', () => {
  // Independent of the abstract keccak256('')/('abc') vectors elsewhere:
  // this is the actual, extremely widely published ERC-20/721 selector,
  // and it's the exact function drainer.mjs's attack calls encode.
  assert.equal(selector('transferFrom(address,address,uint256)'), '0x23b872dd');
});

test('selector("approve(address,uint256)") matches the well-known constant 0x095ea7b3', () => {
  assert.equal(selector('approve(address,uint256)'), '0x095ea7b3');
});

test('selector("allowance(address,address)") matches the well-known constant 0xdd62ed3e', () => {
  // Used by getAllowance() -- the ground-truth check run-demo.mjs now relies
  // on to confirm a revert was actually caused by a revocation, since
  // WETH9 reverts with no reason string at all (confirmed live).
  assert.equal(selector('allowance(address,address)'), '0xdd62ed3e');
});

test('selector("isApprovedForAll(address,address)") matches the well-known constant 0xe985e9c5', () => {
  assert.equal(selector('isApprovedForAll(address,address)'), '0xe985e9c5');
});

test('encodeAddressArg left-pads a 20-byte address to a 32-byte word, lowercased', () => {
  const addr = '0x' + 'Ab'.repeat(20);
  const encoded = encodeAddressArg(addr);
  assert.equal(encoded.length, 64);
  assert.equal(encoded, '000000000000000000000000' + 'ab'.repeat(20));
});

test('encodeUint256Arg encodes MAX_UINT256 and small values to 32-byte words', () => {
  const max = ((1n << 256n) - 1n).toString();
  assert.equal(encodeUint256Arg(max), 'f'.repeat(64));
  assert.equal(encodeUint256Arg(0), '0'.repeat(64));
  assert.equal(encodeUint256Arg(1), '0'.repeat(63) + '1');
});

test('a full transferFrom calldata blob assembles to selector + 3 padded words (4 + 96 = 100 bytes)', () => {
  const from = '0x' + '11'.repeat(20);
  const to = '0x' + '22'.repeat(20);
  const amount = ((1n << 256n) - 1n).toString();
  const data = selector('transferFrom(address,address,uint256)') + encodeAddressArg(from) + encodeAddressArg(to) + encodeUint256Arg(amount);
  assert.equal(data.length, 2 + 8 + 64 * 3); // '0x' + 4-byte selector + 3 words
});

test('isNftVectorAvailable is false without ATTACK_NFT_CONTRACT, true when set', () => {
  assert.equal(isNftVectorAvailable({ attackNftContract: null }), false);
  assert.equal(isNftVectorAvailable({ attackNftContract: '0x' + 'aa'.repeat(20) }), true);
});

test('WETH_SEPOLIA is the correct, checksummed-looking Sepolia WETH address', () => {
  assert.equal(WETH_SEPOLIA.toLowerCase(), '0xfff9976782d46cc05630d1f6ebab18b2324d6b14');
});

// ---------------------------------------------------------------------------
// ensureWethBalance's success check (regression: silently "succeeded" on a
// failed deposit() -- confirmed live when the demo wallet's native ETH ran
// out, ensureWethBalance still reported {wrapped:true} with nothing wrapped)
// ---------------------------------------------------------------------------

function toolResult(obj) {
  return { content: [{ type: 'text', text: JSON.stringify(obj) }] };
}

test('ensureWethBalance throws when deposit() completes with no txHash (matches plantApproval\'s existing check)', async () => {
  const { server, url } = await startMockServer(
    withHandshakeAndBalance((parsed) => {
      if (parsed.method !== 'tools/call') return { status: 500 };
      if (parsed.params.name === 'execute_contract_call') {
        return { payload: { jsonrpc: '2.0', id: parsed.id, result: toolResult({ status: 'submitted', execution_id: 'exec-fail' }) } };
      }
      if (parsed.params.name === 'get_direct_execution_status') {
        // exact shape observed live: a failed deposit, no txHash
        return { payload: { jsonrpc: '2.0', id: parsed.id, result: toolResult({ status: 'failed', tx_hash: null, error: 'Insufficient ETH balance' }) } };
      }
      return { status: 500 };
    }),
  );
  const client = new KeeperHubClient(makeCfg(url).keeperHub);
  await assert.rejects(
    () => ensureWethBalance(client, makeCfg(url)),
    /did not produce a txHash|likely failed/,
  );
  await closeServer(server);
});

test('ensureWethBalance succeeds normally when deposit() actually completes with a txHash', async () => {
  const { server, url } = await startMockServer(
    withHandshakeAndBalance((parsed) => {
      if (parsed.method !== 'tools/call') return { status: 500 };
      if (parsed.params.name === 'execute_contract_call') {
        return { payload: { jsonrpc: '2.0', id: parsed.id, result: toolResult({ status: 'submitted', execution_id: 'exec-ok' }) } };
      }
      if (parsed.params.name === 'get_direct_execution_status') {
        return { payload: { jsonrpc: '2.0', id: parsed.id, result: toolResult({ status: 'completed', tx_hash: '0x' + 'ab'.repeat(32) }) } };
      }
      return { status: 500 };
    }),
  );
  const client = new KeeperHubClient(makeCfg(url).keeperHub);
  const result = await ensureWethBalance(client, makeCfg(url));
  assert.equal(result.wrapped, true);
  assert.equal(result.result.txHash, '0x' + 'ab'.repeat(32));
  await closeServer(server);
});

test('ensureWethBalance skips wrapping entirely when balance is already sufficient (no tool call needed)', async () => {
  const { server, url } = await startMockServer(
    withHandshakeAndBalance(() => ({ status: 500 }), { balanceHex: '0x' + (2_000_000_000_000_000n).toString(16) }),
  );
  const client = new KeeperHubClient(makeCfg(url).keeperHub);
  const result = await ensureWethBalance(client, makeCfg(url));
  assert.equal(result.wrapped, false);
  await closeServer(server);
});
