// Wires botsecrets.mjs's /setkey-stored values into the actual running
// service: only names on ALLOWED_CONFIG_KEYS are ever treated as real
// config, an accepted value is written into the systemd EnvironmentFile
// (with a backup taken first), and the service is restarted and
// health-checked -- automatically rolling back to the previous config if it
// doesn't come back healthy. See docs/BOT-SECRETS.md for the full design
// and its security stakes: a single Telegram message from the allowlisted
// chat can now change live production config and restart the service.
//
// Self-restart caveat (see docs/BOT-SECRETS.md "why a detached helper"):
// this module's restartService()/waitForHealthy() are safe to call from
// ANY process, but calling them from deplex.service's OWN running process
// is not -- `systemctl restart deplex` tears down deplex.service's whole
// cgroup partway through, which (with the default KillMode=control-group)
// kills every child process in it, including a child we spawned to wait
// for and verify that very restart. launchDetachedApply() below exists
// specifically to run the verify/rollback/notify step in a separate
// systemd-managed scope that survives the restart -- see
// scripts/apply-live-config-update.mjs, which is what it launches.

import { readFileSync, writeFileSync, existsSync, copyFileSync } from 'node:fs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

const execFileAsync = promisify(execFile);

const DEFAULT_HELPER_SCRIPT = fileURLToPath(
  new URL('../scripts/apply-live-config-update.mjs', import.meta.url),
);

// Fixed on purpose -- an operator who wants to add a new controllable key
// edits this list and redeploys, rather than /setkey silently accepting
// (and looking like it worked for) anything typed after it.
export const ALLOWED_CONFIG_KEYS = [
  'RPC_URL',
  'WATCHED_WALLET',
  'KEEPERHUB_API_KEY',
  'SAFE_ADDRESS',
  'DEPLEX_TELEGRAM_BOT_TOKEN',
  'DEPLEX_TELEGRAM_CHAT_ID',
];

export function isAllowedConfigKey(name) {
  return ALLOWED_CONFIG_KEYS.includes(name);
}

// A value containing a newline would inject an extra, unintended line into
// the env file (renderUpdatedEnvFile writes `${key}=${value}` verbatim) --
// reject it outright rather than trying to escape/quote it, since nothing
// else in this project's env files uses quoting and adding it only here
// would be an inconsistent, easy-to-miss special case.
export function isValidConfigValue(value) {
  return typeof value === 'string' && value.length > 0 && !/[\r\n]/.test(value);
}

// ---------------------------------------------------------------------------
// Env file update (backup -> replace-or-append -> write)
// ---------------------------------------------------------------------------

// Replaces the first `KEY=...` line matching `key` exactly (a lookup for
// `RPC_URL` must not match an existing `RPC_URL_FOO=` line), preserving
// every other line and its position. Appends a new line at the end if no
// existing line matches.
export function renderUpdatedEnvFile(content, key, value) {
  const lines = content.length ? content.split('\n') : [];
  // A trailing newline in the original content produces a trailing empty
  // element here (`"A=1\n".split('\n')` -> `['A=1', '']`) -- drop it now,
  // regardless of whether we end up replacing or appending below, since
  // the final `+ '\n'` always restores exactly one trailing newline.
  if (lines.length && lines[lines.length - 1] === '') lines.pop();

  const re = new RegExp(`^${key}=`);
  let found = false;
  const updated = lines.map((line) => {
    if (re.test(line)) {
      found = true;
      return `${key}=${value}`;
    }
    return line;
  });
  if (!found) {
    updated.push(`${key}=${value}`);
  }
  return updated.join('\n') + '\n';
}

export function backupEnvFile(path, backupPath = `${path}.bak`) {
  if (existsSync(path)) {
    copyFileSync(path, backupPath);
  }
}

export function updateEnvFile(path, key, value, backupPath = `${path}.bak`) {
  const content = existsSync(path) ? readFileSync(path, 'utf8') : '';
  backupEnvFile(path, backupPath);
  writeFileSync(path, renderUpdatedEnvFile(content, key, value));
}

export function restoreEnvFileBackup(path, backupPath = `${path}.bak`) {
  if (!existsSync(backupPath)) {
    throw new Error(`no backup found at ${backupPath} -- cannot roll back`);
  }
  copyFileSync(backupPath, path);
}

// ---------------------------------------------------------------------------
// systemd control -- execFn injectable so tests never touch a real
// systemctl/systemd-run binary (this project runs its test suite on Windows
// dev machines as well as the Linux VPS).
// ---------------------------------------------------------------------------

const defaultExecFn = (cmd, args) => execFileAsync(cmd, args);

export async function restartService(serviceName, { execFn = defaultExecFn } = {}) {
  await execFn('systemctl', ['restart', serviceName]);
}

export async function isServiceActive(serviceName, { execFn = defaultExecFn } = {}) {
  try {
    const { stdout } = await execFn('systemctl', ['is-active', serviceName]);
    return String(stdout).trim() === 'active';
  } catch {
    // `systemctl is-active` exits nonzero (and still prints e.g.
    // "failed"/"inactive"/"activating" to stdout) for anything but a
    // running unit -- that's a normal "not healthy yet" result, not a
    // tool-invocation failure.
    return false;
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function waitForHealthy(
  serviceName,
  { timeoutMs = 15000, intervalMs = 1000, execFn = defaultExecFn, sleepFn = sleep } = {},
) {
  const deadline = Date.now() + timeoutMs;
  // eslint-disable-next-line no-constant-condition
  while (true) {
    if (await isServiceActive(serviceName, { execFn })) return true;
    if (Date.now() >= deadline) return false;
    await sleepFn(intervalMs);
  }
}

// ---------------------------------------------------------------------------
// restart -> health-check -> auto-rollback-if-unhealthy. The one function
// that matters for correctness; everything above is a building block for
// this. Safe to call from ANY process except deplex.service's own -- see
// this module's top comment.
// ---------------------------------------------------------------------------

export async function restartAndVerify(
  serviceName,
  envFilePath,
  { execFn = defaultExecFn, sleepFn = sleep, healthTimeoutMs = 15000, healthIntervalMs = 1000 } = {},
) {
  const backupPath = `${envFilePath}.bak`;
  const healthOpts = { execFn, sleepFn, timeoutMs: healthTimeoutMs, intervalMs: healthIntervalMs };

  try {
    await restartService(serviceName, { execFn });
  } catch (err) {
    return {
      ok: false,
      reason: 'restart-command-failed',
      message: `restart command failed: ${err.message}`,
    };
  }

  const healthy = await waitForHealthy(serviceName, healthOpts);
  if (healthy) {
    return { ok: true, reason: 'healthy', message: 'restarted and healthy' };
  }

  // Unhealthy -- roll back rather than leaving a broken config live.
  try {
    restoreEnvFileBackup(envFilePath, backupPath);
  } catch (err) {
    return {
      ok: false,
      reason: 'unhealthy-rollback-failed',
      rolledBack: false,
      message: `service unhealthy after restart, and automatic rollback ALSO failed (${err.message}) -- manual intervention required immediately`,
    };
  }

  try {
    await restartService(serviceName, { execFn });
  } catch (err) {
    return {
      ok: false,
      reason: 'unhealthy-rollback-restart-failed',
      rolledBack: true,
      rollbackHealthy: false,
      message: `service unhealthy after restart; config was rolled back, but restarting with it ALSO failed (${err.message}) -- manual intervention required, service may be down`,
    };
  }

  const healthyAfterRollback = await waitForHealthy(serviceName, healthOpts);
  return {
    ok: false,
    reason: 'unhealthy-after-restart',
    rolledBack: true,
    rollbackHealthy: healthyAfterRollback,
    message: healthyAfterRollback
      ? 'service was unhealthy after the update; automatically rolled back to the previous config, which is healthy again'
      : "service was unhealthy after the update; rolled back to the previous config, but it still isn't healthy either -- manual intervention required",
  };
}

// ---------------------------------------------------------------------------
// Detached launch -- escapes deplex.service's own cgroup via `systemd-run`
// so the restart+verify+rollback+notify sequence (scripts/apply-live-config-
// update.mjs) survives deplex.service being restarted mid-flight. Returns
// once the transient unit has been submitted, not once it's finished --
// the caller (src/watcher.mjs) can't wait for the outcome anyway, since by
// the time it's known, this process may already be gone.
// ---------------------------------------------------------------------------

export async function launchDetachedApply(
  name,
  { execFn = defaultExecFn, scriptPath = DEFAULT_HELPER_SCRIPT } = {},
) {
  const unitName = `deplex-live-config-${Date.now()}`;
  await execFn('systemd-run', ['--collect', `--unit=${unitName}`, 'node', scriptPath, '--name', name]);
  return { unitName };
}
