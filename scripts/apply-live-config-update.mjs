// Detached helper for src/liveconfig.mjs's live /setkey -> production
// config pipeline. Launched via `systemd-run` (src/liveconfig.mjs's
// launchDetachedApply()) specifically so it survives deplex.service being
// restarted mid-flight -- see that module's top comment and
// docs/BOT-SECRETS.md for why a plain child process of the watcher can't
// safely do this instead (systemd's default KillMode=control-group kills
// every process in deplex.service's cgroup, including a child spawned to
// watch its own restart, partway through that restart).
//
// Usage: node scripts/apply-live-config-update.mjs --name RPC_URL
//
// The value itself is never passed on the command line -- it's already
// durably stored, encrypted, in bot-secrets.enc.json by the time this
// script runs (src/watcher.mjs's onSetKey handler writes it before
// launching this). Reading it back by name instead of via argv keeps the
// plaintext value out of `ps aux`/process listings.

import { loadConfig } from '../src/config.mjs';
import { sendAlert } from '../src/telegram.mjs';
import { restartAndVerify } from '../src/liveconfig.mjs';

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function main() {
  const nameIdx = process.argv.indexOf('--name');
  const name = nameIdx !== -1 ? process.argv[nameIdx + 1] : null;
  if (!name) {
    console.error('usage: node apply-live-config-update.mjs --name <CONFIG_KEY>');
    process.exit(1);
  }

  const cfg = loadConfig(process.env);

  // Give the parent watcher process's `systemd-run` invocation time to
  // return before the restart below starts tearing its cgroup down.
  await sleep(cfg.liveConfig.detachedStartupDelayMs);

  const result = await restartAndVerify(cfg.liveConfig.serviceName, cfg.liveConfig.envFilePath, {
    healthTimeoutMs: cfg.liveConfig.healthTimeoutMs,
    healthIntervalMs: cfg.liveConfig.healthIntervalMs,
  });

  const prefix = result.ok ? '✅' : '❌';
  const line = `${prefix} ${name}: ${result.message}`;

  try {
    await sendAlert(cfg.telegram, line);
  } catch (err) {
    // If the value that just changed WAS the Telegram bot token/chat id
    // and the new one is wrong, this notification can itself fail --
    // that's exactly the case where a console fallback matters most.
    console.error(`[apply-live-config-update] ${line}`);
    console.error(`[apply-live-config-update] additionally failed to send Telegram notification: ${err.message}`);
  }

  if (!result.ok) process.exitCode = 1;
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
