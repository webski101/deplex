import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  ALLOWED_CONFIG_KEYS,
  isAllowedConfigKey,
  isValidConfigValue,
  renderUpdatedEnvFile,
  updateEnvFile,
  restoreEnvFileBackup,
  restartService,
  isServiceActive,
  waitForHealthy,
  restartAndVerify,
  launchDetachedApply,
} from '../src/liveconfig.mjs';

let tmpDir;
let envPath;

beforeEach(() => {
  tmpDir = mkdtempSync(join(tmpdir(), 'deplex-liveconfig-'));
  envPath = join(tmpDir, 'deplex.env');
});

afterEach(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

const fastSleep = () => Promise.resolve();

function fakeExec(handler) {
  const calls = [];
  const fn = async (cmd, args) => {
    calls.push({ cmd, args });
    return handler(cmd, args, calls.length);
  };
  fn.calls = calls;
  return fn;
}

// ---------------------------------------------------------------------------
// Allowlist + value validation
// ---------------------------------------------------------------------------

test('isAllowedConfigKey: accepts exactly the fixed allowlist, rejects everything else', () => {
  for (const key of ALLOWED_CONFIG_KEYS) {
    assert.equal(isAllowedConfigKey(key), true);
  }
  assert.equal(isAllowedConfigKey('RANDOM_UNRELATED_KEY'), false);
  assert.equal(isAllowedConfigKey('rpc_url'), false); // case-sensitive on purpose
  assert.equal(isAllowedConfigKey(''), false);
  assert.equal(isAllowedConfigKey(undefined), false);
});

test('isValidConfigValue: rejects empty, rejects newlines/carriage returns, accepts a normal string', () => {
  assert.equal(isValidConfigValue('hello123'), true);
  assert.equal(isValidConfigValue(''), false);
  assert.equal(isValidConfigValue('line1\nline2'), false);
  assert.equal(isValidConfigValue('a\rb'), false);
  assert.equal(isValidConfigValue(undefined), false);
});

// ---------------------------------------------------------------------------
// renderUpdatedEnvFile -- pure
// ---------------------------------------------------------------------------

test('renderUpdatedEnvFile: replaces an existing KEY=value line, preserving other lines and order', () => {
  const content = 'RPC_URL=https://old.example\nWATCHED_WALLET=0xabc\n# a comment\n';
  const out = renderUpdatedEnvFile(content, 'RPC_URL', 'https://new.example');
  assert.equal(out, 'RPC_URL=https://new.example\nWATCHED_WALLET=0xabc\n# a comment\n');
});

test('renderUpdatedEnvFile: does not match a key that is only a prefix of another line', () => {
  const content = 'RPC_URL_FOO=should-not-change\n';
  const out = renderUpdatedEnvFile(content, 'RPC_URL', 'https://new.example');
  assert.equal(out, 'RPC_URL_FOO=should-not-change\nRPC_URL=https://new.example\n');
});

test('renderUpdatedEnvFile: appends a new line when the key is absent, without duplicating trailing newlines', () => {
  const content = 'WATCHED_WALLET=0xabc\n';
  const out = renderUpdatedEnvFile(content, 'RPC_URL', 'https://new.example');
  assert.equal(out, 'WATCHED_WALLET=0xabc\nRPC_URL=https://new.example\n');
});

test('renderUpdatedEnvFile: handles empty starting content', () => {
  const out = renderUpdatedEnvFile('', 'RPC_URL', 'https://new.example');
  assert.equal(out, 'RPC_URL=https://new.example\n');
});

// ---------------------------------------------------------------------------
// updateEnvFile / backup / restore -- real files
// ---------------------------------------------------------------------------

test('updateEnvFile: backs up the previous version exactly before writing the new one', () => {
  writeFileSync(envPath, 'RPC_URL=https://old.example\nSAFE_ADDRESS=0xsafe\n');
  updateEnvFile(envPath, 'RPC_URL', 'https://new.example');

  const backupPath = `${envPath}.bak`;
  assert.ok(existsSync(backupPath));
  assert.equal(readFileSync(backupPath, 'utf8'), 'RPC_URL=https://old.example\nSAFE_ADDRESS=0xsafe\n');
  assert.equal(readFileSync(envPath, 'utf8'), 'RPC_URL=https://new.example\nSAFE_ADDRESS=0xsafe\n');
});

test('updateEnvFile: creates the file with no backup when it did not exist yet', () => {
  updateEnvFile(envPath, 'RPC_URL', 'https://new.example');
  assert.equal(readFileSync(envPath, 'utf8'), 'RPC_URL=https://new.example\n');
  assert.ok(!existsSync(`${envPath}.bak`));
});

test('restoreEnvFileBackup: restores exactly the prior content', () => {
  writeFileSync(envPath, 'RPC_URL=https://old.example\n');
  updateEnvFile(envPath, 'RPC_URL', 'https://new.example');
  restoreEnvFileBackup(envPath);
  assert.equal(readFileSync(envPath, 'utf8'), 'RPC_URL=https://old.example\n');
});

test('restoreEnvFileBackup: throws when no backup exists', () => {
  writeFileSync(envPath, 'RPC_URL=https://old.example\n');
  assert.throws(() => restoreEnvFileBackup(envPath), /no backup found/);
});

// ---------------------------------------------------------------------------
// restartService / isServiceActive / waitForHealthy -- mocked execFn
// ---------------------------------------------------------------------------

test('restartService: invokes systemctl restart <serviceName>', async () => {
  const execFn = fakeExec(() => ({ stdout: '' }));
  await restartService('deplex', { execFn });
  assert.deepEqual(execFn.calls, [{ cmd: 'systemctl', args: ['restart', 'deplex'] }]);
});

test('restartService: propagates a failure from the restart command', async () => {
  const execFn = fakeExec(() => {
    throw new Error('Unit deplex.service not found');
  });
  await assert.rejects(restartService('deplex', { execFn }), /not found/);
});

test('isServiceActive: true when systemctl is-active reports "active"', async () => {
  const execFn = fakeExec(() => ({ stdout: 'active\n' }));
  assert.equal(await isServiceActive('deplex', { execFn }), true);
});

test('isServiceActive: false when the command rejects (systemctl is-active exits nonzero for anything else)', async () => {
  const execFn = fakeExec(() => {
    const err = new Error('Command failed');
    err.stdout = 'inactive\n';
    throw err;
  });
  assert.equal(await isServiceActive('deplex', { execFn }), false);
});

test('isServiceActive: false for unexpected stdout even without a rejection', async () => {
  const execFn = fakeExec(() => ({ stdout: 'activating\n' }));
  assert.equal(await isServiceActive('deplex', { execFn }), false);
});

test('waitForHealthy: returns true as soon as the service reports active', async () => {
  let call = 0;
  const execFn = fakeExec(() => {
    call += 1;
    if (call < 3) throw new Error('not yet');
    return { stdout: 'active\n' };
  });
  const healthy = await waitForHealthy('deplex', { execFn, sleepFn: fastSleep, timeoutMs: 5000, intervalMs: 1 });
  assert.equal(healthy, true);
  assert.equal(call, 3);
});

test('waitForHealthy: returns false once the timeout elapses without ever reporting active', async () => {
  const execFn = fakeExec(() => {
    throw new Error('never healthy');
  });
  const healthy = await waitForHealthy('deplex', { execFn, sleepFn: fastSleep, timeoutMs: 5, intervalMs: 1 });
  assert.equal(healthy, false);
});

// ---------------------------------------------------------------------------
// restartAndVerify -- the orchestration, including auto-rollback
// ---------------------------------------------------------------------------

test('restartAndVerify: success path -- restart succeeds, service reports healthy immediately', async () => {
  const execFn = fakeExec((cmd, args) => {
    if (args[0] === 'restart') return { stdout: '' };
    return { stdout: 'active\n' };
  });
  const result = await restartAndVerify('deplex', envPath, { execFn, sleepFn: fastSleep });
  assert.equal(result.ok, true);
  assert.equal(result.reason, 'healthy');
});

test('restartAndVerify: restart command itself fails -- no rollback attempted, env file untouched', async () => {
  writeFileSync(envPath, 'RPC_URL=https://old.example\n');
  const execFn = fakeExec(() => {
    throw new Error('systemctl: connection refused');
  });
  const result = await restartAndVerify('deplex', envPath, { execFn, sleepFn: fastSleep });
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'restart-command-failed');
  assert.equal(readFileSync(envPath, 'utf8'), 'RPC_URL=https://old.example\n'); // untouched
});

test('restartAndVerify: unhealthy after restart -- rolls back the env file and restarts again into a healthy state', async () => {
  writeFileSync(envPath, 'RPC_URL=https://old.example\n');
  updateEnvFile(envPath, 'RPC_URL', 'https://broken.example'); // simulates the update that already happened, with a .bak taken

  let restartCount = 0;
  const execFn = fakeExec((cmd, args) => {
    if (args[0] === 'restart') {
      restartCount += 1;
      return { stdout: '' };
    }
    // is-active: unhealthy on the first restart (the bad config), healthy after rollback (the second restart)
    if (restartCount === 1) throw new Error('not active yet');
    return { stdout: 'active\n' };
  });

  const result = await restartAndVerify('deplex', envPath, {
    execFn,
    sleepFn: fastSleep,
    healthTimeoutMs: 5,
    healthIntervalMs: 1,
  });

  assert.equal(result.ok, false);
  assert.equal(result.reason, 'unhealthy-after-restart');
  assert.equal(result.rolledBack, true);
  assert.equal(result.rollbackHealthy, true);
  assert.equal(readFileSync(envPath, 'utf8'), 'RPC_URL=https://old.example\n'); // rolled back
  assert.equal(restartCount, 2);
});

test('restartAndVerify: unhealthy after restart, and rollback itself fails (no backup) -- reports it plainly', async () => {
  writeFileSync(envPath, 'RPC_URL=https://broken.example\n'); // no .bak exists for this file
  const execFn = fakeExec((cmd, args) => {
    if (args[0] === 'restart') return { stdout: '' };
    throw new Error('not active');
  });
  const result = await restartAndVerify('deplex', envPath, {
    execFn,
    sleepFn: fastSleep,
    healthTimeoutMs: 5,
    healthIntervalMs: 1,
  });
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'unhealthy-rollback-failed');
  assert.equal(result.rolledBack, false);
});

test('restartAndVerify: unhealthy after restart, rollback succeeds, but restarting with the restored config also fails', async () => {
  writeFileSync(envPath, 'RPC_URL=https://old.example\n');
  updateEnvFile(envPath, 'RPC_URL', 'https://broken.example');

  let restartCount = 0;
  const execFn = fakeExec((cmd, args) => {
    if (args[0] === 'restart') {
      restartCount += 1;
      if (restartCount === 2) throw new Error('second restart also failed');
      return { stdout: '' };
    }
    throw new Error('not active');
  });

  const result = await restartAndVerify('deplex', envPath, {
    execFn,
    sleepFn: fastSleep,
    healthTimeoutMs: 5,
    healthIntervalMs: 1,
  });

  assert.equal(result.ok, false);
  assert.equal(result.reason, 'unhealthy-rollback-restart-failed');
  assert.equal(result.rolledBack, true);
  assert.equal(result.rollbackHealthy, false);
  assert.equal(readFileSync(envPath, 'utf8'), 'RPC_URL=https://old.example\n'); // rollback file write still happened
});

test('restartAndVerify: unhealthy after restart, rollback succeeds and restarts, but is STILL unhealthy', async () => {
  writeFileSync(envPath, 'RPC_URL=https://old.example\n');
  updateEnvFile(envPath, 'RPC_URL', 'https://broken.example');

  const execFn = fakeExec((cmd, args) => {
    if (args[0] === 'restart') return { stdout: '' };
    throw new Error('never comes back healthy, even rolled back');
  });

  const result = await restartAndVerify('deplex', envPath, {
    execFn,
    sleepFn: fastSleep,
    healthTimeoutMs: 5,
    healthIntervalMs: 1,
  });

  assert.equal(result.ok, false);
  assert.equal(result.reason, 'unhealthy-after-restart');
  assert.equal(result.rolledBack, true);
  assert.equal(result.rollbackHealthy, false);
});

// ---------------------------------------------------------------------------
// launchDetachedApply
// ---------------------------------------------------------------------------

test('launchDetachedApply: invokes systemd-run with --collect, a unit name, and the helper script + --name', async () => {
  const execFn = fakeExec(() => ({ stdout: '' }));
  await launchDetachedApply('RPC_URL', { execFn, scriptPath: '/fake/path/apply-live-config-update.mjs' });

  assert.equal(execFn.calls.length, 1);
  const { cmd, args } = execFn.calls[0];
  assert.equal(cmd, 'systemd-run');
  assert.ok(args.includes('--collect'));
  assert.ok(args.some((a) => a.startsWith('--unit=')));
  assert.ok(args.includes('node'));
  assert.ok(args.includes('/fake/path/apply-live-config-update.mjs'));
  assert.ok(args.includes('--name'));
  assert.ok(args.includes('RPC_URL'));
});

test('launchDetachedApply: propagates a failure to launch (e.g. systemd-run missing)', async () => {
  const execFn = fakeExec(() => {
    throw new Error('systemd-run: command not found');
  });
  await assert.rejects(launchDetachedApply('RPC_URL', { execFn }), /command not found/);
});
