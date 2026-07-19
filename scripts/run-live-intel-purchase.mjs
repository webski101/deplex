// One-shot live test of the x402 intel-purchase flow (src/intel.mjs's
// getRiskScore) against a REAL running intel-agent/server.mjs and a REAL
// facilitator. Not a test file -- a manual runbook tool, prints a clear
// PURCHASED / FAILED-CLOSED / FREE verdict so a genuinely settled payment is
// unmistakable from every failure mode.
//
// Usage: node --env-file=.env.intel-payer scripts/run-live-intel-purchase.mjs <address-to-score>

import { randomUUID } from 'node:crypto';
import { getRiskScore } from '../src/intel.mjs';
import { loadConfig } from '../src/config.mjs';

const address = process.argv[2];
if (!address) {
  console.error('usage: node scripts/run-live-intel-purchase.mjs <address-to-score>');
  process.exit(1);
}

const cfg = loadConfig();
const missing = [];
if (!cfg.intelAgent.url) missing.push('INTEL_AGENT_URL');
if (!cfg.intelAgent.payerPrivateKey) missing.push('INTEL_PAYER_PRIVATE_KEY');
if (!cfg.intelAgent.publicKeyPem) missing.push('INTEL_AGENT_PUBLIC_KEY or INTEL_AGENT_PUBLIC_KEY_FILE');
if (!cfg.maxIntelSpend) missing.push('MAX_INTEL_SPEND (unset or 0 -- the budget cap would block any purchase)');
if (missing.length) {
  console.error(`Missing required config: ${missing.join(', ')}`);
  process.exit(1);
}

const incidentId = randomUUID();
console.log(`Scoring ${address} via ${cfg.intelAgent.url} (incident ${incidentId}, budget cap ${cfg.maxIntelSpend} atomic units)...`);

const result = await getRiskScore(address, { cfg, incidentId });

console.log('');
// Discriminate on Array.isArray(result.reasons), NOT on the truthiness of
// result.failClosedReason -- getRiskScore's two return shapes are
// {risk, reasons: [...], purchased} (success, reasons always an array) vs
// {risk, failClosedReason, purchased: false} (fail-closed, no reasons key
// at all). A truthiness check on failClosedReason is wrong whenever the
// underlying error's .message is falsy (e.g. "" -- confirmed to happen in
// practice, though the exact native cause wasn't pinned down; see
// FAILURE-MODES.md), silently misreporting a fail-closed result as success.
if (result.purchased) {
  console.log('=== PURCHASED -- a real x402 payment settled ===');
  console.log(`  risk score: ${result.risk}`);
  console.log(`  reasons:    ${JSON.stringify(result.reasons)}`);
  console.log(`  incident:   ${incidentId}`);
  console.log(`  see ${cfg.auditLogPath} for the INTEL_PURCHASE record (amount, asset, settlement details)`);
} else if (Array.isArray(result.reasons)) {
  console.log('=== OK, no payment required -- server returned the score for free ===');
  console.log(`  risk score: ${result.risk}`);
  console.log(`  reasons:    ${JSON.stringify(result.reasons)}`);
} else {
  console.log('=== FAILED CLOSED -- risk defaulted to 100 (worst case) ===');
  console.log(`  reason: ${result.failClosedReason || '(no message -- see the INTEL_PURCHASE audit record and the intel-agent server log for this timestamp)'}`);
  process.exitCode = 1;
}
