# Bot secrets — encrypted config over Telegram

How Deplex's Telegram bot receives and stores sensitive config (API keys, tokens) sent to it
as chat messages, without ever writing them to disk in the clear — and, as of the live-config-
control build below, how an allowlisted value actually gets applied to the running production
service. Code: `src/botsecrets.mjs` (encryption/storage), `src/telegram.mjs` (the `/setkey`
command, `pollBotUpdates`), `src/liveconfig.mjs` (allowlist, env-file update/backup/rollback,
restart + health-check), `scripts/apply-live-config-update.mjs` (the detached restart/verify
helper — see "why a detached helper" below), all wired up in `src/watcher.mjs`'s `main()`. Key
generation: `scripts/generate-bot-master-key.mjs`. Tests: `test/botsecrets.test.mjs`,
`test/telegram.test.mjs`, `test/liveconfig.test.mjs`.

## Design

1. **Master key**: `DEPLEX_BOT_MASTER_KEY`, 32 random bytes, hex-encoded (64 hex chars).
   Generated once by `scripts/generate-bot-master-key.mjs` and printed to your terminal —
   never written to any file by that script or by anything else in this codebase. Same
   never-touches-disk standard as every other credential here; see
   `generate-intel-payer-key.mjs`'s own doc comment for the one deliberate exception in this
   project (`INTEL_PAYER_PRIVATE_KEY`, a funded signing key that has to persist across a
   session — a different threat model from a wrapping key for other secrets).
2. **`/setkey <name> <value>`** sent to the bot, from the allowlisted chat only
   (`DEPLEX_TELEGRAM_CHAT_ID`, same allowlist `pollBotUpdates` already enforces for `/panic`),
   is parsed by `parseSetKeyCommand()` in `src/telegram.mjs`.
3. The value is encrypted with **AES-256-GCM** (`node:crypto`, no new dependency), with a fresh
   random 12-byte IV generated per secret — `encryptSecret()` in `src/botsecrets.mjs`.
4. `{ciphertext, iv, authTag}` (all hex strings) plus an `updatedAt` timestamp are saved under
   `<name>` in `bot-secrets.enc.json` (gitignored — added to `.gitignore` in the same change
   that introduced this file, so there was never a window where it could land in a commit).
5. Immediately after saving, the bot calls Telegram's `deleteMessage` on the original message,
   so the raw secret doesn't linger in chat history. This happens **regardless of whether
   storage succeeded** (see the fail-closed section below) — a secret typed into a chat is a
   liability the moment it's sent, independent of whether Deplex managed to store it.
6. Decryption (`decryptSecret()`/`getSecret()`) happens only in memory, only at the point a
   caller actually needs the plaintext (e.g. right before an outbound KeeperHub/RPC call).
   Nothing in this codebase writes a decrypted value back to disk — `getSecret()`'s return
   value is a plain string handed to the caller, full stop.

## Fail-closed startup

`requireMasterKey()` throws if `DEPLEX_BOT_MASTER_KEY` is missing, or present but not exactly
32 bytes of hex. `src/watcher.mjs`'s `main()` calls it once at startup, inside a `try`: if it
throws, `onSetKey` is simply never wired up, and `src/telegram.mjs`'s dispatcher refuses to
store anything a `/setkey` command sends it — it logs a loud, specific
`console.error` (`secret-handling is not armed (DEPLEX_BOT_MASTER_KEY missing/invalid at
startup) -- not stored`) and still deletes the message, but never falls back to writing the
secret in plaintext anywhere. The rest of the watcher (RPC polling, `/panic`, alerts) starts
and runs normally either way — a missing master key disables exactly one feature, not the
whole bot. See `test/telegram.test.mjs`'s "fail-closed" case for the regression test.

This mirrors the standard the rest of the project already holds itself to:
`assertRuntimeConfig()`/`assertResponderConfig()` in `src/config.mjs` refuse to arm
enforcement rather than silently defaulting to something unsafe; this is the same shape
applied to secret storage instead of transaction execution.

## Threat model

**What this protects against:**
- A secret sitting in Telegram's chat history in plaintext indefinitely (deleted immediately
  after capture).
- A secret sitting on disk in plaintext at rest (`bot-secrets.enc.json` holds ciphertext +
  auth tag only — confirmed by `test/botsecrets.test.mjs`'s "never appears anywhere in the
  stored file" test, which greps the raw file for the plaintext string).
- Silent tampering with the encrypted store: GCM's authentication tag means flipping a single
  byte anywhere in the ciphertext, the IV, or the tag itself makes `decryptSecret()` throw
  rather than return corrupted-but-plausible-looking plaintext. Verified directly — three
  separate tamper tests, one per field.
- A missing/misconfigured master key silently degrading to plaintext storage — it doesn't;
  the feature just doesn't start.

**What this explicitly does NOT protect against** (in the same spirit as
`FAILURE-MODES.md`'s "what Deplex does not protect against" section — stated plainly rather
than glossed over):
- **A compromised host.** `DEPLEX_BOT_MASTER_KEY` lives in the process's environment and in
  whatever env file loads it (`.env`, `/root/deplex.env`). Anyone who can read that env file or
  attach to the running process can decrypt everything in `bot-secrets.enc.json`. This is
  encryption *at rest against disk/repo exposure*, not a defense against host compromise —
  no different from any other symmetric-key-in-env-var design.
- **Telegram's own server-side retention.** `deleteMessage` removes the message from the chat
  UI; it does not (and cannot, from Deplex's side) purge whatever Telegram itself retains
  server-side, or anything already cached/forwarded/screenshotted by a client before deletion
  ran. The window is small (deletion happens on the very next poll cycle after the message
  arrives) but it is not zero.
- **Deletion failures.** If `deleteMessage` fails (message already too old per Telegram's own
  48-hour edit/delete window, bot lacks delete rights in a group chat, etc.), the raw secret
  stays visible in chat even though it was still correctly encrypted and stored. This is
  logged loudly (`console.error`, "remove it manually") but not retried — there's no
  particular reason a second attempt would succeed where the first didn't, and retrying a
  `deleteMessage` call is not itself risky, but this codebase doesn't currently loop on it.
- **Master key loss or rotation.** There is no key-wrapping, no key hierarchy, no rotation
  tooling beyond "re-run `/setkey` for everything after generating a new master key." Losing
  `DEPLEX_BOT_MASTER_KEY` makes every stored secret permanently undecryptable — `generate-bot-
  master-key.mjs` says this explicitly when it prints a new key.
- **Anyone with access to the allowlisted chat.** `DEPLEX_TELEGRAM_CHAT_ID` is the only access
  control on who can call `/setkey` — same allowlist `/panic` already relies on. This module
  adds no additional authentication on top of "controls the Telegram chat."

## Live config control — `/setkey` now controls the running service

**Security stakes, stated plainly: a single Telegram message from the allowlisted chat can
now change live production config and restart the service.** `DEPLEX_TELEGRAM_CHAT_ID` is the
entire access-control boundary on this — same as it already was for `/panic`. Anyone who
controls that chat (or compromises the bot token) can rotate `KEEPERHUB_API_KEY`, repoint
`RPC_URL`, or change which wallet is watched, live, on the VPS. Treat the allowlisted chat
with the same care as `/root/deplex.env` itself, because functionally it now has the same
blast radius.

What was previously a follow-up ("push a changed secret into `/root/deplex.env` and
restart/reload") is now built. The pipeline, in full:

1. **Allowlist.** Only names in `ALLOWED_CONFIG_KEYS` (`src/liveconfig.mjs`) are recognized as
   real config: `RPC_URL`, `WATCHED_WALLET`, `KEEPERHUB_API_KEY`, `SAFE_ADDRESS`,
   `DEPLEX_TELEGRAM_BOT_TOKEN`, `DEPLEX_TELEGRAM_CHAT_ID`. `/setkey` for anything else is
   rejected outright — encrypted-stored-but-inert secrets from before this feature (arbitrary
   names) are still possible in principle, but nothing reads them into live config, and
   `isAllowedConfigKey()` refuses to route an unrecognized name through this pipeline at all.
2. **Value validation.** A value containing `\n`/`\r` is rejected (`isValidConfigValue()`) —
   `renderUpdatedEnvFile()` writes `KEY=value` into `/root/deplex.env` verbatim, and an
   embedded newline would inject an extra, attacker-controlled line into that file.
3. **Encrypt + store** (unchanged from the original `/setkey` build) — `setSecret()` into
   `bot-secrets.enc.json`.
4. **Update the env file**: `updateEnvFile()` backs up the current `/root/deplex.env` to
   `/root/deplex.env.bak` first, then replaces the one matching `KEY=` line (or appends if
   absent), leaving every other line untouched.
5. **Restart + health-check + auto-rollback**: `restartAndVerify()` in `src/liveconfig.mjs` —
   `systemctl restart deplex`, then poll `systemctl is-active deplex` up to
   `DEPLEX_HEALTH_TIMEOUT_MS` (default 15s). If it doesn't come back active, `deplex.env` is
   restored from the `.bak` taken in step 4 and the service is restarted again — fail-closed,
   same standard as everywhere else in this project: a bad update reverts itself rather than
   leaving broken config live.
6. **Telegram confirmation**: an interim "⏳ restarting" message, then a final ✅/❌ message
   with the outcome — including whether an automatic rollback happened and whether it worked.

### Why a detached helper, not a straight function call

The obvious implementation — the watcher process itself calls `restartService()`, polls
`isServiceActive()`, then sends the Telegram message — has a real bug: **the watcher process
restarting its own systemd unit can kill the code trying to verify that very restart.**
`systemctl restart deplex` (default `KillMode=control-group`) sends `SIGTERM` to *every*
process in `deplex.service`'s cgroup during the stop phase — including any child process the
watcher spawned to wait for and check on that restart, since a plain child process inherits
its parent's cgroup. The watchdog gets torn down at exactly the moment it would otherwise
report success or failure, and the final Telegram message never arrives regardless of whether
the restart actually succeeded.

The fix: `launchDetachedApply()` runs `systemd-run --collect --unit=<name> node
scripts/apply-live-config-update.mjs --name <KEY>` — `systemd-run` asks systemd (PID 1)
directly to create a **new, independent transient unit** in its own cgroup, outside
`deplex.service`'s. That transient unit survives `deplex.service` being stopped and restarted,
so `scripts/apply-live-config-update.mjs` (a short delay, then `restartAndVerify()`, then
`sendAlert()`) can actually finish and report the real outcome. The helper reads the just-set
value back out of `bot-secrets.enc.json` by name rather than taking it as a `--name`d argument
value on the command line, so the plaintext secret never appears in `ps aux`/process listings
even briefly.

This is the one piece of this feature that depends on systemd specifics (`KillMode=control-
group` is the systemd default, and this assumes it) rather than being purely defensive
programming — worth knowing if `deplex.service`'s unit file is ever changed to
`KillMode=process`, in which case the detached helper becomes unnecessary but still harmless.

### What this does NOT protect against (in addition to the general threat model above)

- **A restart that never lands anywhere** — if `systemd-run` itself isn't available (non-
  systemd host) or fails to launch, `launchDetachedApply()` rejects, the watcher sends a
  failure Telegram message, and the operator is told to restart manually. The env file has
  already been updated at that point (step 4 already ran) — the OLD process keeps running the
  OLD config in memory until an actual restart happens, so there's a window where the on-disk
  config and the running process's config disagree.
- **A rollback that only fixes the file, not necessarily "why."** If a bad `RPC_URL` value
  doesn't cause an obvious restart failure (e.g. it's syntactically valid but points at a dead
  endpoint), `systemctl is-active` can still report `active` — the process is running, it's
  just failing at the RPC layer, which this health check has no visibility into. "Active" is
  a process-liveness check, not an application-health check.
- **Telegram itself being the thing that broke.** If `DEPLEX_TELEGRAM_BOT_TOKEN` or
  `DEPLEX_TELEGRAM_CHAT_ID` is the value being changed and the new one is wrong, the final
  confirmation/failure message may never arrive by Telegram at all — `scripts/apply-live-
  config-update.mjs` falls back to `console.error` (visible via `journalctl -u deplex`) in
  that case, but there's no second delivery channel.

## Doing this live, conservatively

Don't test this against `RPC_URL` or `KEEPERHUB_API_KEY` first. Start with the lowest-risk
possible case: set `DEPLEX_TELEGRAM_CHAT_ID` to **its own current value** — a no-op change
that still exercises every step of the real pipeline (allowlist check, env file backup +
rewrite, real `systemctl restart`, real health poll, real Telegram confirmation) without any
chance of the new value itself being wrong, since it's identical to what's already running.

1. Confirm the current value first: check `/root/deplex.env`'s existing `DEPLEX_TELEGRAM_CHAT_ID=` line, or just recall the chat ID you're already sending `/setkey` from.
2. Send `/setkey DEPLEX_TELEGRAM_CHAT_ID <that same value>` from the allowlisted chat.
3. Watch for the `⏳ ... Restarting the service now` message.
4. Wait for the final `✅`/`❌` message (should take a few seconds — the detached helper's
   own startup delay plus however long the restart actually takes).
5. Separately, on the VPS, confirm independently rather than trusting the message alone:
   `systemctl status deplex` (should show active, recent start time) and
   `journalctl -u deplex -n 50` (should show a clean startup, no crash loop).
6. Check `/root/deplex.env.bak` exists and matches what the file looked like before — that's
   your rollback safety net for the *next* update, not this one.

Only once that full round-trip is confirmed clean should you try a value that actually
changes behavior (e.g. `SAFE_ADDRESS`, or eventually `RPC_URL`/`KEEPERHUB_API_KEY`) — and for
those, watch `journalctl -u deplex` during the restart window regardless of what the Telegram
message says, since (per the health-check limitation above) "healthy" only means "the process
came up," not "the new value is actually good."

## Environment variables

| Var | Default | Purpose |
|---|---|---|
| `DEPLEX_BOT_MASTER_KEY` | none (required to arm `/setkey`) | AES-256-GCM master key, 32 bytes hex-encoded. Generate with `node scripts/generate-bot-master-key.mjs`. |
| `BOT_SECRETS_FILE` | `./bot-secrets.enc.json` | Path to the encrypted store. Gitignored. |
| `DEPLEX_ENV_FILE` | `/root/deplex.env` | The systemd `EnvironmentFile` that live-config updates write to. |
| `DEPLEX_SERVICE_NAME` | `deplex` | systemd unit name restarted after a successful update. |
| `DEPLEX_HEALTH_TIMEOUT_MS` | `15000` | How long to poll `systemctl is-active` before declaring the restart unhealthy. |
| `DEPLEX_HEALTH_INTERVAL_MS` | `1000` | Delay between health-check polls. |
| `DEPLEX_DETACHED_STARTUP_DELAY_MS` | `1500` | How long `scripts/apply-live-config-update.mjs` waits before restarting, giving the parent's `systemd-run` call time to safely return first. |

## Usage

```
node scripts/generate-bot-master-key.mjs
# copy the printed DEPLEX_BOT_MASTER_KEY=... line into your env

DEPLEX_BOT_MASTER_KEY=<...> DEPLEX_TELEGRAM_BOT_TOKEN=<...> DEPLEX_TELEGRAM_CHAT_ID=<...> \
  node src/watcher.mjs
```

Then, from the allowlisted chat, send:

```
/setkey KEEPERHUB_API_KEY kh_live_your_real_key
```

The bot stores it encrypted in `bot-secrets.enc.json` and deletes your message. Read it back
in code via:

```js
import { requireMasterKey, getSecret } from './src/botsecrets.mjs';
const masterKey = requireMasterKey(); // throws if not configured
const apiKey = getSecret('./bot-secrets.enc.json', masterKey, 'KEEPERHUB_API_KEY');
// use apiKey immediately; never assign it anywhere that gets serialized to disk
```
