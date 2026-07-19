# Bot secrets — encrypted config over Telegram

How Deplex's Telegram bot receives and stores sensitive config (API keys, tokens) sent to it
as chat messages, without ever writing them to disk in the clear. Code: `src/botsecrets.mjs`
(encryption/storage), `src/telegram.mjs` (the `/setkey` command, `pollBotUpdates`), wired up in
`src/watcher.mjs`'s `main()`. Key generation: `scripts/generate-bot-master-key.mjs`. Tests:
`test/botsecrets.test.mjs`, `test/telegram.test.mjs`.

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

## Follow-up, deliberately not built here

Deplex now also runs as a systemd service on a VPS, with its config in `/root/deplex.env`
loaded via `EnvironmentFile=`. The natural next step — having `/setkey` push a changed secret
into that running service's env file and restart/reload it — is real, useful, and **not part
of this build**. This phase is scoped to the encrypt/store/delete-message mechanism itself,
tested locally, same as every other feature in this project. Wiring it to a live systemd unit
introduces a different, larger set of concerns (file-write permissions on `/root/deplex.env`,
what "reload" means for a running watcher process, what happens to in-flight incident state
across a restart) that deserve their own design pass rather than being folded in here.

## Environment variables

| Var | Default | Purpose |
|---|---|---|
| `DEPLEX_BOT_MASTER_KEY` | none (required to arm `/setkey`) | AES-256-GCM master key, 32 bytes hex-encoded. Generate with `node scripts/generate-bot-master-key.mjs`. |
| `BOT_SECRETS_FILE` | `./bot-secrets.enc.json` | Path to the encrypted store. Gitignored. |

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
