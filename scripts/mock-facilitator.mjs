// Zero-dependency local x402 facilitator stub, for diagnosis and offline demos.
//
// It speaks the confirmed v1 wire shape (see docs/X402-NOTES.md): POST
// /verify and POST /settle, request body { x402Version, paymentPayload,
// paymentRequirements }, and it ALWAYS approves. It does NOT touch any real
// chain or move any real funds -- the "transaction" it returns is a fixed
// placeholder. Its only purpose is to remove x402.org (or any remote
// facilitator) from the loop so the client<->intel-agent path can be
// exercised in isolation.
//
// Diagnostic use: if a live purchase hangs against the real facilitator but
// completes against this one (point the agent at it via
// FACILITATOR_URL=http://127.0.0.1:4090), the hang is in the agent's
// OUTBOUND call to the real facilitator, not the client->agent transport.
//
// Bind is 127.0.0.1 explicit (not "localhost") to avoid the Windows
// dual-stack ::1-vs-127.0.0.1 resolution ambiguity entirely.

import { createServer } from 'node:http';

const PORT = Number(process.env.MOCK_FACILITATOR_PORT) || 4090;

function readBody(req) {
  return new Promise((resolve) => {
    let raw = '';
    req.on('data', (c) => (raw += c));
    req.on('end', () => {
      try {
        resolve(JSON.parse(raw));
      } catch {
        resolve({});
      }
    });
  });
}

function log(msg) {
  console.log(`[mock-facilitator] ${new Date().toISOString()} ${msg}`);
}

const server = createServer(async (req, res) => {
  if (req.method === 'GET' && req.url === '/supported') {
    log('GET /supported');
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ kinds: [{ x402Version: 1, scheme: 'exact', network: 'base-sepolia' }] }));
    return;
  }

  if (req.method === 'POST' && (req.url === '/verify' || req.url === '/settle')) {
    const body = await readBody(req);
    const payer = body?.paymentPayload?.payload?.authorization?.from ?? '0xmockpayer';
    const network = body?.paymentRequirements?.network ?? 'base-sepolia';
    if (req.url === '/verify') {
      log(`POST /verify -> isValid:true payer=${payer}`);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ isValid: true, payer }));
    } else {
      log(`POST /settle -> success:true payer=${payer}`);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, transaction: '0xMOCK_NO_REAL_SETTLEMENT', network, payer }));
    }
    return;
  }

  log(`404 ${req.method} ${req.url}`);
  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'not found' }));
});

server.listen(PORT, '127.0.0.1', () => {
  log(`listening on http://127.0.0.1:${PORT} -- ALWAYS approves, NO real settlement. Point the agent here with FACILITATOR_URL=http://127.0.0.1:${PORT}`);
});
