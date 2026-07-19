// Operator reset: clear the open incident so lower-tier rules re-arm.
// Usage:  node scripts/reset-incident.mjs     (same env as the watcher)
//
// STOP THE WATCHER FIRST. It holds state in memory and saves after every
// cycle -- a save from a live watcher would clobber this reset.
//
// Appends a RESET record to the audit chain (operator actions are part of
// the incident record, not exempt from it), then persists the cleared state.

import { loadConfig } from '../src/config.mjs';
import { loadState, saveState } from '../src/watcher.mjs';
import { resetCurrentIncident } from '../src/responder.mjs';

const cfg = loadConfig();
const state = loadState(cfg.stateFilePath);

if (!state) {
  console.error(`no state file at ${cfg.stateFilePath} -- nothing to reset`);
  process.exit(1);
}

console.log('before:', JSON.stringify({ incident: state.incident, currentIncidentId: state.currentIncidentId }));

if (!state.incident && !state.currentIncidentId) {
  console.log('no open incident -- nothing to reset');
  process.exit(0);
}

resetCurrentIncident({ cfg, walletState: state });
saveState(cfg.stateFilePath, state);

console.log('after: ', JSON.stringify({ incident: state.incident, currentIncidentId: state.currentIncidentId }));
console.log('RESET record appended to audit log. Restart the watcher to resume.');
