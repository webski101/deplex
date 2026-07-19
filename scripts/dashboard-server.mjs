// Local dev server for dashboard/ (Phase 7). Serves the static dashboard
// files AND two read-only live-data endpoints reading the SAME files
// watcher.mjs itself writes:
//   GET /state        -> deplex-state.json, as JSON
//   GET /audit.jsonl   -> deplex-audit.jsonl, raw text (same NDJSON shape
//                         auditlog.mjs writes -- one JSON record per line)
//
// Deliberately a SEPARATE process from watcher.mjs, not folded into it: the
// watcher is a safety-critical detection/response loop, and this is a
// read-only dashboard convenience -- same reasoning as intel-agent/server.mjs
// being its own process rather than living inside watcher.mjs. It reads the
// same on-disk files watcher.mjs writes, so no IPC or coupling is needed;
// restarting/killing this server has zero effect on enforcement.
//
// dashboard/ itself has no server-side dependency on this file: it's a
// self-contained static site (dashboard/lib/ holds its own synced copies of
// the two portable src/ modules it needs) that also works served from
// Vercel with no live endpoints at all -- app.mjs falls back to
// dashboard/demo-data/*.json when /state and /audit.jsonl aren't reachable.

import { createServer } from 'node:http';
import { readFileSync, existsSync, statSync } from 'node:fs';
import { join, extname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const REPO_ROOT = join(fileURLToPath(new URL('.', import.meta.url)), '..');
const DASHBOARD_DIR = join(REPO_ROOT, 'dashboard');
const PORT = Number(process.env.DASHBOARD_PORT) || 4022;
// Anchored to this script's own location, not process.cwd() -- so
// `node scripts/dashboard-server.mjs` finds the real files regardless of
// which directory it's actually invoked from (confirmed necessary: a
// relative-path invocation from outside the repo root resolved these to the
// wrong place entirely). Still fully overridable via env for a non-default
// STATE_FILE/AUDIT_LOG_FILE, matching watcher.mjs's own config.
const STATE_FILE = process.env.STATE_FILE || join(REPO_ROOT, 'deplex-state.json');
const AUDIT_LOG_FILE = process.env.AUDIT_LOG_FILE || join(REPO_ROOT, 'deplex-audit.jsonl');

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8',
};

function serveStatic(req, res) {
  const urlPath = req.url === '/' ? '/index.html' : req.url.split('?')[0];
  // Reject any path escaping DASHBOARD_DIR (e.g. "/../src/config.mjs") --
  // this server is meant to expose exactly dashboard/'s own contents, not
  // the rest of the repo.
  const safePath = join(DASHBOARD_DIR, urlPath.replace(/\.\./g, ''));
  if (!safePath.startsWith(DASHBOARD_DIR) || !existsSync(safePath) || statSync(safePath).isDirectory()) {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('not found');
    return;
  }
  const contentType = MIME_TYPES[extname(safePath)] || 'application/octet-stream';
  res.writeHead(200, { 'Content-Type': contentType });
  res.end(readFileSync(safePath));
}

const server = createServer((req, res) => {
  if (req.method !== 'GET') {
    res.writeHead(405, { 'Content-Type': 'text/plain' });
    res.end('method not allowed');
    return;
  }

  if (req.url === '/state') {
    if (!existsSync(STATE_FILE)) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: `${STATE_FILE} not found -- has the watcher run yet?` }));
      return;
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(readFileSync(STATE_FILE, 'utf8'));
    return;
  }

  if (req.url === '/audit.jsonl') {
    if (!existsSync(AUDIT_LOG_FILE)) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end(`${AUDIT_LOG_FILE} not found -- has the watcher run yet?`);
      return;
    }
    res.writeHead(200, { 'Content-Type': 'application/x-ndjson; charset=utf-8' });
    res.end(readFileSync(AUDIT_LOG_FILE, 'utf8'));
    return;
  }

  serveStatic(req, res);
});

// pathToFileURL, not `new URL(argv[1], 'file:')' -- the latter breaks this
// exact guard on Windows for a relative invocation (confirmed and fixed in
// intel-agent/server.mjs earlier tonight; see FAILURE-MODES.md). Applying
// the same fix here from the start rather than reintroducing it.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  server.listen(PORT, '127.0.0.1', () => {
    console.log(`[dashboard] serving dashboard/ on http://127.0.0.1:${PORT}, reading ${STATE_FILE} + ${AUDIT_LOG_FILE}`);
  });
}
