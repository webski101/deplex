// Deplex incident-room dashboard -- vanilla JS, ES modules, no build step,
// no framework. Tries the local live endpoints first (watcher.mjs's own
// state/audit files, served by scripts/dashboard-server.mjs); falls back to
// the baked demo-data/ snapshot (real captured Phase 3/5/6 history) when
// those aren't reachable, e.g. on a static Vercel deploy.

import { verifyChain, webCryptoDigestHex } from './lib/auditchain.mjs';
import { compile, INCIDENT_STATES } from './lib/policy.mjs';

// Three real, independently-verified incidents from tonight's and earlier
// sessions' actual runs (see README's Verified Onchain section) -- pinned
// here purely so the timeline panel can flag them, not because the data
// itself is treated any differently from any other incident found.
const FEATURED_INCIDENTS = {
  '7328f6bc-ccda-40bd-a7a9-106fddcee9f0': 'Phase 3 milestone (hand-executed)',
  '0607fea4-af69-4593-84f6-75ce8975d77e': 'Phase 6 scripted attack/defense race',
  '5004c325-18da-45ad-a644-00d50c6f70fe': 'Phase 5 x402 intel purchase (real settlement)',
};

const $ = (id) => document.getElementById(id);

function fmtTime(ts) {
  try {
    return new Date(ts).toISOString().replace('T', ' ').replace('Z', '');
  } catch {
    return ts;
  }
}

function short(hexOrId, head = 10, tail = 6) {
  if (typeof hexOrId !== 'string' || hexOrId.length <= head + tail + 1) return hexOrId;
  return `${hexOrId.slice(0, head)}…${hexOrId.slice(-tail)}`;
}

// ---------------------------------------------------------------------------
// Data loading: live endpoints first, demo data as fallback
// ---------------------------------------------------------------------------

async function tryLoadLive() {
  const [stateRes, auditRes] = await Promise.all([
    fetch('/state', { cache: 'no-store' }),
    fetch('/audit.jsonl', { cache: 'no-store' }),
  ]);
  if (!stateRes.ok || !auditRes.ok) throw new Error('live endpoints not reachable');
  const walletState = await stateRes.json();
  const auditText = await auditRes.text();
  const records = auditText
    .split('\n')
    .filter((l) => l.trim().length)
    .map((l) => JSON.parse(l));
  return { walletState, records, mode: 'LIVE' };
}

async function loadDemo() {
  const [stateRes, auditRes] = await Promise.all([fetch('./demo-data/state.json'), fetch('./demo-data/audit.json')]);
  const walletState = await stateRes.json();
  const records = await auditRes.json();
  return { walletState, records, mode: 'DEMO' };
}

async function loadPolicyText() {
  const res = await fetch('./demo-data/policy.txt');
  return res.text();
}

// ---------------------------------------------------------------------------
// Panel 1: wallet status
// ---------------------------------------------------------------------------

// Scans from the END, not the start: the real audit log has two distinct
// addresses across its history (an early-testing wallet, then the one
// actually used for Phase 3/5/6) -- confirmed directly against the data,
// not assumed. "Current wallet status" means the most recent one, not
// whichever happened to be watched first.
function findWatchedWallet(records) {
  for (let i = records.length - 1; i >= 0; i--) {
    const ev = records[i].payload?.event;
    if (ev?.owner) return ev.owner;
    if (ev?.from) return ev.from;
  }
  return null;
}

function inferEnforcementMode(records) {
  for (let i = records.length - 1; i >= 0; i--) {
    if (records[i].type === 'EXECUTION_RESULT') {
      return records[i].payload.status === 'DRY_RUN' ? 'DRY_RUN' : 'ARMED';
    }
  }
  return 'MONITORING (no executions yet)';
}

function renderWalletStatus(records, walletState) {
  $('w-address').textContent = findWatchedWallet(records) ?? 'unknown';
  $('w-enforcement').textContent = inferEnforcementMode(records);
  $('w-block').textContent = walletState.lastScannedBlock ?? '--';
  $('w-approvals').textContent = Object.keys(walletState.activeApprovals ?? {}).length;
  $('w-incident-id').textContent = walletState.currentIncidentId ?? '(none)';

  const stepper = $('stepper');
  stepper.innerHTML = '';
  const currentState = walletState.incident?.stateName ?? 'IDLE';
  const currentIdx = INCIDENT_STATES.indexOf(currentState);
  INCIDENT_STATES.forEach((s, i) => {
    const div = document.createElement('div');
    div.className = 'step';
    if (i === currentIdx) div.classList.add('step-active');
    else if (i < currentIdx) div.classList.add('step-passed');
    div.textContent = s;
    stepper.appendChild(div);
  });
}

// ---------------------------------------------------------------------------
// Panel 2: live audit feed
// ---------------------------------------------------------------------------

function summarize(record) {
  const p = record.payload;
  switch (record.type) {
    case 'OBSERVATION':
      return p.fromBlock === p.toBlock
        ? `block ${p.fromBlock} scanned (${p.approvalCount ?? 0} approval, ${p.transferCount ?? 0} transfer event(s))`
        : `blocks ${p.fromBlock}-${p.toBlock} scanned (${p.approvalCount ?? 0} approval, ${p.transferCount ?? 0} transfer event(s))`;
    case 'EVENT':
      return `${p.event?.type ?? p.type ?? 'event'} detected: ${short(p.spender ?? p.event?.spender ?? p.to ?? '', 8, 4)}`;
    case 'DECISION':
      return p.triggered?.length
        ? `${p.triggered.length} rule(s) fired -> ${p.nextState}`
        : `no rule matched (${p.reason ?? ''})`;
    case 'EXECUTION_INTENT':
      return `${p.actionType} intent: ${p.target?.key ?? ''}`;
    case 'EXECUTION_SUBMITTED':
      return `${p.actionType} submitted (exec ${short(p.executionId ?? '', 6, 4)})`;
    case 'EXECUTION_RESULT':
      return `${p.actionType} ${p.status} tx=${short(p.txHash ?? '(none)', 8, 4)}`;
    case 'RESET':
      return `incident reset (${p.kind})`;
    case 'WATCHER_ERROR':
      return `error: ${p.message}`;
    case 'INTEL_PURCHASE':
      return p.failed ? `intel purchase FAILED: ${p.error ?? ''}` : `intel purchase: score=${p.score} tx=${short(p.transaction ?? '(none)', 8, 4)}`;
    default:
      return JSON.stringify(p).slice(0, 80);
  }
}

const FEED_LIMIT = 150;

function renderFeed(records) {
  const list = $('feed-list');
  list.innerHTML = '';
  const shown = records.slice(-FEED_LIMIT);
  $('feed-count').textContent = `(showing last ${shown.length} of ${records.length})`;
  for (const r of shown) {
    const line = document.createElement('div');
    line.className = 'feed-line';
    line.innerHTML = `<span class="feed-seq">#${r.seq}</span><span class="feed-type feed-type-${r.type}">${r.type}</span><span class="feed-summary">${escapeHtml(summarize(r))}</span>`;
    line.title = fmtTime(r.ts);
    list.appendChild(line);
  }
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// ---------------------------------------------------------------------------
// Panel 3: incident timeline
// ---------------------------------------------------------------------------

function groupByIncident(records) {
  const groups = new Map();
  for (const r of records) {
    const id = r.payload?.incidentId;
    if (!id) continue;
    if (!groups.has(id)) groups.set(id, []);
    groups.get(id).push(r);
  }
  return groups;
}

function explorerLink(record) {
  const p = record.payload;
  if (p.network === 'base-sepolia' && p.transaction) {
    return `https://sepolia.basescan.org/tx/${p.transaction}`;
  }
  const tx = p.txHash ?? p.raw?.transactionHash;
  if (tx) return `https://sepolia.etherscan.io/tx/${tx}`;
  return null;
}

function renderIncidentTrail(records) {
  const detail = $('incident-detail');
  detail.innerHTML = '';
  for (const r of records) {
    const div = document.createElement('div');
    div.className = 'trail-record';
    const link = explorerLink(r);
    const linkHtml = link ? ` — <a href="${link}" target="_blank" rel="noopener">view tx ↗</a>` : '';
    div.innerHTML = `<span class="trail-type">${r.type}</span><span class="trail-ts">${fmtTime(r.ts)}</span><div class="trail-detail">${escapeHtml(summarize(r))}${linkHtml}</div>`;
    detail.appendChild(div);
  }
}

function renderIncidentList(records) {
  const groups = groupByIncident(records);
  const entries = [...groups.entries()].sort((a, b) => {
    const aLast = a[1][a[1].length - 1].ts;
    const bLast = b[1][b[1].length - 1].ts;
    return aLast < bLast ? 1 : -1;
  });

  const listEl = $('incident-list');
  listEl.innerHTML = '';
  for (const [incidentId, incRecords] of entries) {
    const item = document.createElement('div');
    item.className = 'incident-item';
    const featured = FEATURED_INCIDENTS[incidentId];
    const lastState = incRecords[incRecords.length - 1].payload.nextState ?? incRecords[incRecords.length - 1].payload.stateName ?? '';
    item.innerHTML = `${featured ? `<div class="incident-featured">★ ${escapeHtml(featured)}</div>` : ''}<div class="incident-id">${incidentId}</div><div class="small dim">${incRecords.length} record(s)${lastState ? ' · ' + lastState : ''}</div>`;
    item.addEventListener('click', () => {
      for (const el of listEl.querySelectorAll('.incident-item')) el.classList.remove('selected');
      item.classList.add('selected');
      renderIncidentTrail(incRecords);
    });
    listEl.appendChild(item);
    if (featured && !listEl.dataset.autoSelected) {
      listEl.dataset.autoSelected = '1';
      item.click();
    }
  }
}

// ---------------------------------------------------------------------------
// Panel 4: chain verify
// ---------------------------------------------------------------------------

let currentRecords = [];
let tamperedRecords = null;

async function runVerify(records, label) {
  const resultEl = $('verify-result');
  const metaEl = $('verify-meta');
  resultEl.className = 'verify-result verify-running';
  resultEl.textContent = `VERIFYING ${records.length} RECORDS...`;
  metaEl.textContent = '';

  const startedAt = performance.now();
  const result = await verifyChain(records, webCryptoDigestHex);
  const elapsedMs = (performance.now() - startedAt).toFixed(1);

  if (result.valid) {
    resultEl.className = 'verify-result verify-valid';
    resultEl.textContent = `✓ CHAIN VALID -- ${records.length} records, genesis to head, zero breaks`;
  } else {
    resultEl.className = 'verify-result verify-broken';
    resultEl.textContent = `✗ CHAIN BROKEN at record #${result.brokenAt}: ${result.reason}`;
  }
  metaEl.textContent = `${label} · verified via crypto.subtle (WebCrypto) in ${elapsedMs}ms`;
}

function wireVerifyButtons() {
  $('btn-verify').addEventListener('click', () => runVerify(tamperedRecords ?? currentRecords, tamperedRecords ? 'tampered copy' : 'full chain'));

  $('btn-tamper').addEventListener('click', () => {
    // Deep-ish copy: mutate one field on one record so the ORIGINAL data
    // (and the incident/feed panels reading it) is never touched -- this
    // only ever operates on a scratch copy.
    tamperedRecords = currentRecords.map((r) => ({ ...r, payload: { ...r.payload } }));
    const victimIdx = Math.floor(tamperedRecords.length / 2);
    const victim = tamperedRecords[victimIdx];
    // Mutate whatever the first primitive-looking field is, so this works
    // regardless of a record's exact shape.
    const key = Object.keys(victim.payload).find((k) => ['string', 'number', 'boolean'].includes(typeof victim.payload[k]));
    if (key) victim.payload[key] = `TAMPERED_${String(victim.payload[key])}`;
    else victim.payload._tampered = true;

    $('btn-untamper').disabled = false;
    runVerify(tamperedRecords, `tampered copy (record #${victimIdx} mutated)`);
  });

  $('btn-untamper').addEventListener('click', () => {
    tamperedRecords = null;
    $('btn-untamper').disabled = true;
    runVerify(currentRecords, 'full chain (restored)');
  });
}

// ---------------------------------------------------------------------------
// Panel 5: policy view
// ---------------------------------------------------------------------------

function renderPolicy(policyText) {
  $('policy-text').textContent = policyText;
  const { rules, errors } = compile(policyText);
  const lines = policyText.split(/\r\n|\r|\n/);

  const summary = $('policy-summary');
  summary.innerHTML = '';

  const statusLine = document.createElement('div');
  statusLine.className = 'small';
  statusLine.innerHTML = errors.length
    ? `<span style="color:var(--red)">✗ ${errors.length} compile error(s)</span>`
    : `<span style="color:var(--green-bright)">✓ compiled clean -- ${rules.length} rule(s), zero errors</span>`;
  summary.appendChild(statusLine);

  for (const rule of rules) {
    const div = document.createElement('div');
    div.className = 'policy-rule';
    div.innerHTML = `<div class="policy-rule-name">${escapeHtml(rule.name)}</div><div class="policy-rule-meta">${rule.action.type} (tier ${rule.action.tier}) · priority ${rule.priority} · line ${rule.line}</div>`;
    summary.appendChild(div);
  }
  for (const err of errors) {
    const div = document.createElement('div');
    div.className = 'policy-rule';
    div.innerHTML = `<div style="color:var(--red)">line ${err.line}: ${escapeHtml(err.message)}</div>`;
    summary.appendChild(div);
  }
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

function setModeBadge(mode) {
  const badge = $('mode-badge');
  badge.textContent = `MODE: ${mode}`;
  badge.className = `badge ${mode === 'LIVE' ? 'badge-live' : 'badge-demo'}`;
  $('footer-source').textContent = mode === 'LIVE' ? '/state + /audit.jsonl (local watcher)' : 'baked demo-data/ (real captured history)';
}

function startClock() {
  const el = $('clock');
  const tick = () => (el.textContent = new Date().toISOString().replace('T', ' ').slice(0, 19));
  tick();
  setInterval(tick, 1000);
}

async function boot() {
  startClock();
  wireVerifyButtons();

  let data;
  try {
    data = await tryLoadLive();
  } catch {
    data = await loadDemo();
  }
  setModeBadge(data.mode);
  currentRecords = data.records;

  renderWalletStatus(data.records, data.walletState);
  renderFeed(data.records);
  renderIncidentList(data.records);

  const policyText = await loadPolicyText();
  renderPolicy(policyText);

  // Auto-run verification once on load -- see the chain-verify panel.
  runVerify(currentRecords, 'full chain');

  // In LIVE mode, poll for new records so the feed/wallet panels stay
  // current with the running watcher; DEMO mode is a static snapshot.
  if (data.mode === 'LIVE') {
    setInterval(async () => {
      try {
        const fresh = await tryLoadLive();
        currentRecords = fresh.records;
        renderWalletStatus(fresh.records, fresh.walletState);
        renderFeed(fresh.records);
        renderIncidentList(fresh.records);
      } catch {
        // transient poll failure -- keep showing the last good data
      }
    }, 5000);
  }
}

boot();
