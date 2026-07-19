import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import {
  KeeperHubClient,
  searchActions,
  executeContractCall,
  executeTransfer,
  getExecution,
  pollExecution,
  isTerminalStatus,
  weiToDecimalString,
} from '../src/keeperhub.mjs';

// ---------------------------------------------------------------------------
// Mock MCP server -- no live network calls anywhere in this file.
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
        const { status = 200, headers = {}, payload, raw, contentType = 'application/json' } = await responder(parsed, req);
        res.writeHead(status, { 'Content-Type': contentType, ...headers });
        if (raw !== undefined) res.end(raw);
        else if (payload !== undefined) res.end(JSON.stringify(payload));
        else res.end();
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

function initOk(parsed) {
  return {
    payload: {
      jsonrpc: '2.0',
      id: parsed.id,
      result: { protocolVersion: '2024-11-05', capabilities: {}, serverInfo: { name: 'mock' } },
    },
    headers: { 'Mcp-Session-Id': 'sess-abc' },
  };
}

function ok(parsed, result) {
  return { payload: { jsonrpc: '2.0', id: parsed.id, result } };
}

function withHandshake(extra, { onInit } = {}) {
  return async (parsed, req) => {
    if (!parsed) return { status: 400 };
    if (parsed.method === 'initialize') {
      if (onInit) onInit();
      return initOk(parsed);
    }
    if (parsed.method === 'notifications/initialized') return { status: 202 };
    return extra(parsed, req);
  };
}

function textResult(obj) {
  return { content: [{ type: 'text', text: JSON.stringify(obj) }] };
}

// ---------------------------------------------------------------------------
// Session handshake
// ---------------------------------------------------------------------------

test('rpcRequest times out and rejects instead of hanging forever on a connection that never responds', async () => {
  // Same gap watcher.mjs's rpcCall had: no timeout meant a hung connection
  // to the MCP endpoint left every KeeperHub call NEVER settling -- silently
  // blocking responder.mjs's execution flow forever, no error, nothing.
  const server = createServer((req) => {
    /* deliberately never respond */
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  const client = new KeeperHubClient({ apiKey: 'k', mcpUrl: `http://127.0.0.1:${port}/`, requestTimeoutMs: 150 });

  const startedAt = Date.now();
  await assert.rejects(() => client.rpcRequest('initialize', {}), /timed out after 150ms/);
  const elapsed = Date.now() - startedAt;
  assert.ok(elapsed < 2000, `must reject promptly after the timeout, not hang (took ${elapsed}ms)`);

  await new Promise((resolve) => server.close(resolve));
});

test('ensureSession performs initialize + notifications/initialized and captures Mcp-Session-Id for later calls', async () => {
  const seen = [];
  const { server, url } = await startMockServer(async (parsed, req) => {
    seen.push({ method: parsed?.method, session: req.headers['mcp-session-id'] || null });
    if (parsed.method === 'initialize') return initOk(parsed);
    if (parsed.method === 'notifications/initialized') return { status: 202 };
    if (parsed.method === 'tools/list') return ok(parsed, { tools: [{ name: 'search_protocol_actions' }] });
    return { status: 500 };
  });

  const client = new KeeperHubClient({ apiKey: 'kh_test', mcpUrl: url });
  const tools = await client.listTools();

  assert.equal(tools.length, 1);
  assert.equal(client.sessionId, 'sess-abc');
  assert.deepEqual(
    seen.map((s) => s.method),
    ['initialize', 'notifications/initialized', 'tools/list'],
  );
  assert.equal(seen[0].session, null, 'initialize must not send a session header yet');
  assert.equal(seen[1].session, 'sess-abc', 'notifications/initialized must carry the session from initialize');
  assert.equal(seen[2].session, 'sess-abc', 'tools/list must carry the session too');

  await closeServer(server);
});

test('parallel callers awaiting ensureSession share one in-flight initialize', async () => {
  let initCount = 0;
  const { server, url } = await startMockServer(
    withHandshake((parsed) => (parsed.method === 'tools/list' ? ok(parsed, { tools: [] }) : { status: 500 }), {
      onInit: () => {
        initCount++;
      },
    }),
  );
  const client = new KeeperHubClient({ apiKey: 'k', mcpUrl: url });
  await Promise.all([client.listTools(), client.listTools(), client.listTools()]);
  assert.equal(initCount, 1);
  await closeServer(server);
});

// ---------------------------------------------------------------------------
// callTool response unwrapping
// ---------------------------------------------------------------------------

test('callTool prefers structuredContent when present', async () => {
  const { server, url } = await startMockServer(
    withHandshake((parsed) =>
      ok(parsed, { structuredContent: { score: 42 }, content: [{ type: 'text', text: 'ignored' }] }),
    ),
  );
  const client = new KeeperHubClient({ apiKey: 'k', mcpUrl: url });
  const result = await client.callTool('some_tool', { a: 1 });
  assert.deepEqual(result, { score: 42 });
  await closeServer(server);
});

test('callTool JSON-parses a text content block when no structuredContent is present', async () => {
  const { server, url } = await startMockServer(withHandshake((parsed) => ok(parsed, textResult({ ok: true }))));
  const client = new KeeperHubClient({ apiKey: 'k', mcpUrl: url });
  const result = await client.callTool('some_tool', {});
  assert.deepEqual(result, { ok: true });
  await closeServer(server);
});

test('callTool falls back to the raw text when the content block is not JSON', async () => {
  const { server, url } = await startMockServer(
    withHandshake((parsed) => ok(parsed, { content: [{ type: 'text', text: 'plain string result' }] })),
  );
  const client = new KeeperHubClient({ apiKey: 'k', mcpUrl: url });
  const result = await client.callTool('some_tool', {});
  assert.equal(result, 'plain string result');
  await closeServer(server);
});

test('callTool throws when the tool result has isError:true, message includes the content text', async () => {
  const { server, url } = await startMockServer(
    withHandshake((parsed) =>
      ok(parsed, { isError: true, content: [{ type: 'text', text: 'revert: insufficient allowance' }] }),
    ),
  );
  const client = new KeeperHubClient({ apiKey: 'k', mcpUrl: url });
  await assert.rejects(() => client.callTool('execute_contract_call', {}), /revert: insufficient allowance/);
  await closeServer(server);
});

test('parses an SSE-shaped response (text/event-stream) the same as a plain JSON body', async () => {
  const { server, url } = await startMockServer(
    withHandshake((parsed) => {
      const payload = { jsonrpc: '2.0', id: parsed.id, result: textResult({ viaSse: true }) };
      return { raw: `data: ${JSON.stringify(payload)}\n\n`, contentType: 'text/event-stream' };
    }),
  );
  const client = new KeeperHubClient({ apiKey: 'k', mcpUrl: url });
  const result = await client.callTool('x', {});
  assert.deepEqual(result, { viaSse: true });
  await closeServer(server);
});

test('a malformed 2xx JSON body throws a clear error quoting the raw body', async () => {
  const { server, url } = await startMockServer(withHandshake(() => ({ raw: 'not json at all' })));
  const client = new KeeperHubClient({ apiKey: 'k', mcpUrl: url });
  await assert.rejects(() => client.listTools(), /invalid JSON-RPC response|not json at all/);
  await closeServer(server);
});

// ---------------------------------------------------------------------------
// Session-expiry retry
// ---------------------------------------------------------------------------

test('a 401 on a tool call triggers exactly one re-init and one retry, then succeeds', async () => {
  let initCount = 0;
  let toolCallAttempt = 0;
  const { server, url } = await startMockServer(
    withHandshake(
      (parsed) => {
        toolCallAttempt++;
        if (toolCallAttempt === 1) {
          return { status: 401, payload: { jsonrpc: '2.0', id: parsed.id, error: { message: 'session expired' } } };
        }
        return ok(parsed, textResult({ recovered: true }));
      },
      {
        onInit: () => {
          initCount++;
        },
      },
    ),
  );
  const client = new KeeperHubClient({ apiKey: 'k', mcpUrl: url });
  const result = await client.callTool('get_direct_execution_status', { executionId: 'x' });
  assert.deepEqual(result, { recovered: true });
  assert.equal(initCount, 2, 'must re-init exactly once after a session-expired error');
  assert.equal(toolCallAttempt, 2);
  await closeServer(server);
});

test('a non-session error (e.g. bad HTTP 400 validation error) does not trigger re-init or retry', async () => {
  let initCount = 0;
  let toolCallAttempt = 0;
  const { server, url } = await startMockServer(
    withHandshake(
      (parsed) => {
        toolCallAttempt++;
        return { status: 400, payload: { jsonrpc: '2.0', id: parsed.id, error: { message: 'invalid contractAddress' } } };
      },
      {
        onInit: () => {
          initCount++;
        },
      },
    ),
  );
  const client = new KeeperHubClient({ apiKey: 'k', mcpUrl: url });
  await assert.rejects(() => client.callTool('execute_contract_call', {}), /invalid contractAddress|HTTP 400/);
  assert.equal(initCount, 1);
  assert.equal(toolCallAttempt, 1);
  await closeServer(server);
});

// ---------------------------------------------------------------------------
// High-level wrappers: verify exact request shape sent to KeeperHub
// ---------------------------------------------------------------------------

test('executeContractCall sends the confirmed live schema: chain_id/contract_address/function_name/function_args(JSON string)/abi/idempotency_key', async () => {
  let captured;
  const { server, url } = await startMockServer(
    withHandshake((parsed) => {
      captured = parsed.params;
      return ok(parsed, textResult({ status: 'submitted', execution_id: 'exec-1' }));
    }),
  );
  const client = new KeeperHubClient({ apiKey: 'k', mcpUrl: url });
  const abiFragment = {
    name: 'approve',
    type: 'function',
    inputs: [
      { name: 'spender', type: 'address' },
      { name: 'amount', type: 'uint256' },
    ],
  };
  const result = await executeContractCall(client, {
    chain: '11155111',
    to: '0xToken',
    abiFragment,
    args: ['0xSpender', '0'],
    idempotencyKey: 'incident-1:REVOKE:t:s',
  });

  assert.equal(captured.name, 'execute_contract_call');
  assert.equal(captured.arguments.chain_id, '11155111');
  assert.equal(captured.arguments.contract_address, '0xToken');
  assert.equal(captured.arguments.function_name, 'approve');
  // live schema: function_args is a JSON-STRINGIFIED array, never a raw array
  assert.equal(typeof captured.arguments.function_args, 'string');
  assert.deepEqual(JSON.parse(captured.arguments.function_args), ['0xSpender', '0']);
  // live schema rejects a raw array here too ("abi expected a string, got an
  // array") -- same JSON-stringification requirement as function_args
  assert.equal(typeof captured.arguments.abi, 'string');
  assert.deepEqual(JSON.parse(captured.arguments.abi), [abiFragment]);
  assert.equal(captured.arguments.idempotency_key, 'incident-1:REVOKE:t:s');
  // confirmed dead: the static-docs names must not appear on the wire
  assert.equal(captured.arguments.network, undefined);
  assert.equal(captured.arguments.contractAddress, undefined);
  assert.equal(captured.arguments.abiFunction, undefined);
  assert.equal(captured.arguments.args, undefined);
  assert.equal(result.executionId, 'exec-1');
  assert.equal(result.status, 'submitted');

  await closeServer(server);
});

test('executeContractCall converts value (wei -> decimal ETH) for payable calls, omits it otherwise', async () => {
  // Confirmed live: value is a decimal-ETH string like amount, NOT wei. A
  // payable deposit() with value:"1000000000000000" (0.001 ETH in wei) was
  // read as 10^15 whole ETH and failed "insufficient balance" against a
  // wallet holding 0.098 ETH. Callers pass wei (codebase-consistent);
  // conversion happens here.
  const capturedArgsList = [];
  const { server, url } = await startMockServer(
    withHandshake((parsed) => {
      capturedArgsList.push(parsed.params.arguments);
      return ok(parsed, textResult({ status: 'submitted', execution_id: 'exec-1' }));
    }),
  );
  const client = new KeeperHubClient({ apiKey: 'k', mcpUrl: url });
  const depositAbi = { name: 'deposit', type: 'function', stateMutability: 'payable', inputs: [] };
  await executeContractCall(client, { chain: '11155111', to: '0xW', abiFragment: depositAbi, value: '1000000000000000' });
  await executeContractCall(client, { chain: '11155111', to: '0xT', abiFragment: { name: 'approve', type: 'function', inputs: [] } });

  assert.equal(capturedArgsList[0].value, '0.001', 'value must be the decimal-ETH string, not the raw wei integer');
  assert.ok(!('value' in capturedArgsList[1]), 'non-payable calls must omit value entirely');
  await closeServer(server);
});

test('executeContractCall omits idempotency_key when none is provided', async () => {
  let captured;
  const { server, url } = await startMockServer(
    withHandshake((parsed) => {
      captured = parsed.params;
      return ok(parsed, textResult({ status: 'submitted', execution_id: 'exec-1' }));
    }),
  );
  const client = new KeeperHubClient({ apiKey: 'k', mcpUrl: url });
  await executeContractCall(client, {
    chain: '1',
    to: '0xT',
    abiFragment: { name: 'approve', type: 'function', inputs: [] },
  });
  assert.ok(!('idempotency_key' in captured.arguments));
  await closeServer(server);
});

test('weiToDecimalString converts wei to the human-readable decimal string execute_transfer actually expects', () => {
  // Confirmed live: a raw wei integer got read as that many whole tokens
  // ("Need: 1000000000000000.0") and rejected -- the field is decimal, not wei.
  assert.equal(weiToDecimalString(1_000_000_000_000_000n), '0.001');
  assert.equal(weiToDecimalString(1_000_000_000_000_000_000n), '1'); // exactly 1 ETH, no trailing ".0"
  assert.equal(weiToDecimalString(0n), '0');
  assert.equal(weiToDecimalString(1n), '0.000000000000000001'); // 1 wei
  assert.equal(weiToDecimalString(1_500_000_000_000_000_000n), '1.5');
  // 6-decimal token (USDC-shaped): 1_000_000 raw units == 1.0 token
  assert.equal(weiToDecimalString(1_000_000n, 6), '1');
  assert.equal(weiToDecimalString(1_500_000n, 6), '1.5');
});

test('executeTransfer sends chain_id/to_address/amount (converted from wei to decimal), token_address only for ERC-20, idempotency_key when given', async () => {
  const capturedArgsList = [];
  const { server, url } = await startMockServer(
    withHandshake((parsed) => {
      capturedArgsList.push(parsed.params.arguments);
      return ok(parsed, textResult({ status: 'submitted', execution_id: 'exec-2' }));
    }),
  );
  const client = new KeeperHubClient({ apiKey: 'k', mcpUrl: url });

  await executeTransfer(client, {
    chain: '11155111',
    token: '0xToken',
    to: '0xRecipient',
    amount: '1000000000000000000', // 1 ETH-equivalent, in wei
    idempotencyKey: 'incident-1:EVACUATE:token:0xToken',
  });
  await executeTransfer(client, { chain: '11155111', to: '0xRecipient', amount: '500000' /* wei */ });
  await executeTransfer(client, { chain: '11155111', token: '0xUsdcLike', to: '0xRecipient', amount: '2500000', decimals: 6 });

  const [erc20Leg, nativeLeg, sixDecimalLeg] = capturedArgsList;
  assert.equal(erc20Leg.chain_id, '11155111');
  assert.equal(erc20Leg.to_address, '0xRecipient');
  assert.equal(erc20Leg.amount, '1', 'must be the decimal string, not the raw wei integer');
  assert.equal(erc20Leg.token_address, '0xToken');
  assert.equal(erc20Leg.idempotency_key, 'incident-1:EVACUATE:token:0xToken');
  assert.equal(erc20Leg.recipientAddress, undefined, 'static-docs name must not appear on the wire');
  assert.equal(nativeLeg.amount, '0.0000000000005');
  assert.ok(!('token_address' in nativeLeg), 'native transfer must omit token_address entirely');
  assert.ok(!('idempotency_key' in nativeLeg));
  assert.equal(sixDecimalLeg.amount, '2.5', 'non-18-decimals must be honored, not hardcoded');

  await closeServer(server);
});

test('searchActions calls search_protocol_actions with a query field', async () => {
  let captured;
  const { server, url } = await startMockServer(
    withHandshake((parsed) => {
      captured = parsed.params;
      return ok(parsed, textResult([{ actionType: 'aave-v3/supply' }]));
    }),
  );
  const client = new KeeperHubClient({ apiKey: 'k', mcpUrl: url });
  const result = await searchActions(client, 'lending');
  assert.equal(captured.name, 'search_protocol_actions');
  assert.equal(captured.arguments.query, 'lending');
  assert.deepEqual(result, [{ actionType: 'aave-v3/supply' }]);
  await closeServer(server);
});

// ---------------------------------------------------------------------------
// Execution status + polling
// ---------------------------------------------------------------------------

test('getExecution calls get_direct_execution_status with execution_id and normalizes snake_case response fields', async () => {
  let captured;
  const { server, url } = await startMockServer(
    withHandshake((parsed) => {
      captured = parsed.params;
      return ok(
        parsed,
        textResult({
          status: 'confirmed',
          tx_hash: '0xabc',
          explorer_url: 'https://sepolia.etherscan.io/tx/0xabc',
          gas_used: '21000',
          execution_id: 'exec-1',
        }),
      );
    }),
  );
  const client = new KeeperHubClient({ apiKey: 'k', mcpUrl: url });
  const status = await getExecution(client, 'exec-1');
  assert.equal(captured.name, 'get_direct_execution_status');
  assert.equal(captured.arguments.execution_id, 'exec-1');
  assert.equal(captured.arguments.executionId, undefined, 'camelCase param must not appear on the wire');
  assert.equal(status.status, 'confirmed');
  assert.equal(status.txHash, '0xabc');
  assert.equal(status.explorerUrl, 'https://sepolia.etherscan.io/tx/0xabc');
  assert.equal(status.gasUsed, '21000');
  assert.equal(status.executionId, 'exec-1');
  await closeServer(server);
});

test('pollExecution polls until a non-pending status is returned', async () => {
  let callCount = 0;
  const { server, url } = await startMockServer(
    withHandshake((parsed) => {
      callCount++;
      const status = callCount < 3 ? 'pending' : 'confirmed';
      return ok(parsed, textResult({ status, txHash: callCount < 3 ? null : '0xdone' }));
    }),
  );
  const client = new KeeperHubClient({ apiKey: 'k', mcpUrl: url });
  const result = await pollExecution(client, 'exec-1', { intervalMs: 5, timeoutMs: 5000 });
  assert.equal(result.status, 'confirmed');
  assert.equal(result.txHash, '0xdone');
  assert.equal(callCount, 3);
  await closeServer(server);
});

test('pollExecution throws once timeoutMs elapses while status stays pending', async () => {
  const { server, url } = await startMockServer(withHandshake((parsed) => ok(parsed, textResult({ status: 'pending' }))));
  const client = new KeeperHubClient({ apiKey: 'k', mcpUrl: url });
  await assert.rejects(
    () => pollExecution(client, 'exec-1', { intervalMs: 5, timeoutMs: 30 }),
    /did not reach terminal status/,
  );
  await closeServer(server);
});

test('isTerminalStatus: known-pending strings are non-terminal; everything else (incl. unrecognized) is terminal', () => {
  assert.equal(isTerminalStatus('pending'), false);
  assert.equal(isTerminalStatus('PROCESSING'), false);
  assert.equal(isTerminalStatus('queued'), false);
  assert.equal(isTerminalStatus('confirmed'), true);
  assert.equal(isTerminalStatus('failed'), true);
  assert.equal(isTerminalStatus('some-unrecognized-status'), true);
  assert.equal(isTerminalStatus(null), false);
  assert.equal(isTerminalStatus(undefined), false);
});
