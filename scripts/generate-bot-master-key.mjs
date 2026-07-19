// Generates Deplex's Telegram-bot secret-encryption master key
// (DEPLEX_BOT_MASTER_KEY) -- the AES-256-GCM key src/botsecrets.mjs uses to
// encrypt values received via the bot's /setkey command before they touch
// disk. See docs/BOT-SECRETS.md for the full design.
//
// Deliberately UNLIKE generate-intel-payer-key.mjs's pattern in one way:
// this key is never written to any file by this script, or by any other
// Deplex code -- src/botsecrets.mjs's requireMasterKey() reads it straight
// from process.env.DEPLEX_BOT_MASTER_KEY and nothing else does. Printed once
// here so you can copy it into your own env file / systemd EnvironmentFile /
// shell export yourself. Run this yourself, in your own terminal -- don't
// ask an agent session to run it and relay the output.

import { randomBytes } from 'node:crypto';

const key = randomBytes(32).toString('hex');

console.log(`Generated a fresh DEPLEX_BOT_MASTER_KEY (not written to any file):`);
console.log(``);
console.log(`  DEPLEX_BOT_MASTER_KEY=${key}`);
console.log(``);
console.log(`Set this as an environment variable yourself -- e.g. add the line above to`);
console.log(`.env (already gitignored) for local runs, or to /root/deplex.env for the`);
console.log(`systemd service (see docs/BOT-SECRETS.md's note on why that wiring isn't`);
console.log(`automated yet). Losing this key makes every secret already stored in`);
console.log(`bot-secrets.enc.json permanently undecryptable -- back it up somewhere`);
console.log(`safe (a password manager, not a repo).`);
console.log(``);
console.log(`Re-run this script any time you want to rotate keys -- but note rotating`);
console.log(`invalidates every secret already stored under the old key; you'd need to`);
console.log(`re-run /setkey for each one afterward.`);
