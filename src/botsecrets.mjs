// AES-256-GCM store for secrets the Telegram bot receives via /setkey (API
// keys, tokens) -- see src/telegram.mjs for the command handling and
// docs/BOT-SECRETS.md for the full design/threat model.
//
// Master key: DEPLEX_BOT_MASTER_KEY, 32 random bytes hex-encoded, read
// straight from process.env only -- never written to any file by this
// module or by scripts/generate-bot-master-key.mjs. Same "never touches
// disk" standard as every other credential in this project (see
// generate-intel-payer-key.mjs's own doc comment for the one deliberate
// exception, INTEL_PAYER_PRIVATE_KEY, which needs to persist across a
// session and is a different threat model -- a funded signing key, not a
// wrapping key for other secrets).
//
// Fail-closed: requireMasterKey() throws loudly on a missing or malformed
// key rather than ever falling back to storing secrets in plaintext. Callers
// (src/watcher.mjs) are expected to call it once at startup and simply not
// wire up the /setkey handler if it throws -- the rest of Deplex still runs.

import { randomBytes, createCipheriv, createDecipheriv } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync, chmodSync } from 'node:fs';

const ALGO = 'aes-256-gcm';
const IV_LENGTH = 12; // GCM-recommended nonce length
const KEY_LENGTH = 32; // AES-256
const KEY_HEX_LENGTH = KEY_LENGTH * 2;

export const DEFAULT_STORE_PATH = './bot-secrets.enc.json';

export function requireMasterKey(env = process.env) {
  const hex = env.DEPLEX_BOT_MASTER_KEY;
  if (!hex) {
    throw new Error(
      'DEPLEX_BOT_MASTER_KEY is not set -- refusing to start secret-handling. ' +
        'Run scripts/generate-bot-master-key.mjs and set the printed value as an env var.',
    );
  }
  if (!/^[0-9a-fA-F]+$/.test(hex) || hex.length !== KEY_HEX_LENGTH) {
    throw new Error(
      `DEPLEX_BOT_MASTER_KEY must be exactly ${KEY_LENGTH} random bytes, hex-encoded ` +
        `(${KEY_HEX_LENGTH} hex chars) -- got ${hex.length} char(s). ` +
        'Refusing to start secret-handling with a malformed key.',
    );
  }
  return Buffer.from(hex, 'hex');
}

export function encryptSecret(masterKey, plaintext) {
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGO, masterKey, iv);
  const ciphertext = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
  return {
    ciphertext: ciphertext.toString('hex'),
    iv: iv.toString('hex'),
    authTag: cipher.getAuthTag().toString('hex'),
  };
}

// GCM's auth tag makes a single flipped bit anywhere in ciphertext or
// authTag throw here rather than silently returning corrupted plaintext --
// decipher.final() is where that check happens.
export function decryptSecret(masterKey, record) {
  const decipher = createDecipheriv(ALGO, masterKey, Buffer.from(record.iv, 'hex'));
  decipher.setAuthTag(Buffer.from(record.authTag, 'hex'));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(record.ciphertext, 'hex')),
    decipher.final(),
  ]);
  return plaintext.toString('utf8');
}

export function loadStore(path = DEFAULT_STORE_PATH) {
  if (!existsSync(path)) return {};
  return JSON.parse(readFileSync(path, 'utf8'));
}

function saveStore(path, store) {
  writeFileSync(path, JSON.stringify(store, null, 2));
  try {
    chmodSync(path, 0o600); // best-effort; Windows/NTFS won't fully honor this
  } catch {
    // chmod not meaningful on this filesystem -- fine, ignore
  }
}

// Encrypts `plaintext` and persists it under `name`. The plaintext itself is
// never written anywhere -- only the return value of encryptSecret() touches
// disk.
export function setSecret(path, masterKey, name, plaintext) {
  const store = loadStore(path);
  store[name] = { ...encryptSecret(masterKey, plaintext), updatedAt: new Date().toISOString() };
  saveStore(path, store);
  return store[name];
}

// Decrypts only in-memory, only at the point of use -- the return value must
// never be written back to disk by any caller.
export function getSecret(path, masterKey, name) {
  const store = loadStore(path);
  const record = store[name];
  if (!record) return null;
  return decryptSecret(masterKey, record);
}

export function listSecretNames(path = DEFAULT_STORE_PATH) {
  return Object.keys(loadStore(path));
}
