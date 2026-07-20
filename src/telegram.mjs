// alerts + manual panic trigger

import https from 'node:https';
import { ALLOWED_CONFIG_KEYS } from './liveconfig.mjs';

const API_HOST = 'api.telegram.org';

// parse_mode: 'HTML' treats bare < and & as markup; unescaped addresses/amounts
// containing them (or accidental angle brackets) break message delivery.
export function escapeHtml(text) {
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function apiRequest(botToken, method, payload) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify(payload);
    const req = https.request(
      {
        hostname: API_HOST,
        path: `/bot${botToken}/${method}`,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body),
        },
      },
      (res) => {
        let data = '';
        res.on('data', (chunk) => {
          data += chunk;
        });
        res.on('end', () => {
          try {
            const parsed = JSON.parse(data);
            if (!parsed.ok) {
              reject(new Error(`Telegram API error: ${parsed.description || 'unknown error'}`));
            } else {
              resolve(parsed.result);
            }
          } catch (err) {
            reject(new Error(`invalid Telegram API response: ${err.message}`));
          }
        });
      },
    );
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

export async function sendAlert(cfg, text, apiRequestFn = apiRequest) {
  if (!cfg?.botToken || !cfg?.chatId) {
    console.log(`[telegram disabled] ${text}`);
    return null;
  }
  return apiRequestFn(cfg.botToken, 'sendMessage', {
    chat_id: cfg.chatId,
    text: escapeHtml(text),
    parse_mode: 'HTML',
  });
}

const HELP_RE = /^\/help(?:@\S+)?\s*$/i;

export function isHelpCommand(text) {
  return HELP_RE.test(String(text ?? '').trim());
}

// Pulls ALLOWED_CONFIG_KEYS straight from liveconfig.mjs rather than
// hardcoding a second copy here -- if that list ever changes, this text
// changes with it instead of silently going stale.
export function buildHelpText() {
  return [
    'Deplex bot commands:',
    '',
    '/panic',
    'Triggers an emergency EVACUATE right now -- sweeps all tracked funds to SAFE_ADDRESS. Use this if you believe the wallet is actively being drained and want Deplex to act immediately, without waiting for its own detection loop.',
    '',
    '/setkey <NAME> <VALUE>',
    "Securely updates a piece of Deplex's live configuration. The message containing the value is deleted automatically right after it's read, and the value is stored encrypted at rest -- but using this restarts the live service, so only send it when you actually mean to change something.",
    '',
    `Allowed names: ${ALLOWED_CONFIG_KEYS.join(', ')}`,
    '',
    'Security note: only messages from this allowlisted chat are ever acted on -- which also means anyone with access to this chat can control the live service. Treat access to this bot/chat itself like a real credential.',
  ].join('\n');
}

export function deleteMessage(cfg, messageId, apiRequestFn = apiRequest) {
  return apiRequestFn(cfg.botToken, 'deleteMessage', { chat_id: cfg.chatId, message_id: messageId });
}

// Matches `/setkey <name> <value>` -- name is a single token (env-var-like:
// letters/digits/._-), value is everything after it verbatim (a token,
// bot secret, or anything with no leading/trailing whitespace stripped
// beyond the message's own trim). Returns null for anything else, including
// a bare `/setkey` with no args -- that's a usage mistake, not a secret, so
// it's left alone (no message to delete, nothing was stored).
const SETKEY_RE = /^\/setkey(?:@\S+)?\s+(\S+)\s+([\s\S]+)$/i;

export function parseSetKeyCommand(text) {
  const match = SETKEY_RE.exec(String(text ?? '').trim());
  if (!match) return null;
  return { name: match[1], value: match[2] };
}

// Single long-poll loop dispatching to both /panic and /setkey -- Telegram's
// getUpdates rejects/interferes with two concurrent long-polls on the same
// bot token, so this can't be two independent listeners each tracking their
// own offset; it has to be one loop, one offset, fanning out per update.
export async function pollBotUpdates(
  cfg,
  { onPanic, onSetKey } = {},
  { offset = 0, timeoutSec = 30, apiRequestFn = apiRequest } = {},
) {
  const updates = await apiRequestFn(cfg.botToken, 'getUpdates', {
    offset,
    timeout: timeoutSec,
    allowed_updates: ['message'],
  });

  let nextOffset = offset;
  for (const update of updates) {
    nextOffset = update.update_id + 1;
    const msg = update.message;
    if (!msg || !msg.text) continue;
    const chatId = String(msg.chat?.id ?? '');
    if (chatId !== String(cfg.chatId)) continue; // only the allowlisted chat can trigger anything
    const text = msg.text.trim();

    if (text.toLowerCase().startsWith('/panic')) {
      if (onPanic) {
        try {
          await onPanic({ type: 'panic', chatId, observedAt: new Date().toISOString() });
        } catch (err) {
          console.error(`[telegram] /panic handler failed: ${err.message}`);
        }
      }
      continue;
    }

    if (isHelpCommand(text)) {
      try {
        await sendAlert(cfg, buildHelpText(), apiRequestFn);
      } catch (err) {
        console.error(`[telegram] failed to send /help reply: ${err.message}`);
      }
      continue;
    }

    const setKey = parseSetKeyCommand(text);
    if (setKey) {
      if (onSetKey) {
        try {
          await onSetKey(setKey);
        } catch (err) {
          console.error(`[telegram] /setkey handler failed for "${setKey.name}": ${err.message}`);
        }
      } else {
        // Fail-closed (docs/BOT-SECRETS.md): DEPLEX_BOT_MASTER_KEY was
        // missing at startup, so no onSetKey handler was ever wired up --
        // never silently fall back to storing this in plaintext. Still
        // fall through to delete the message below: a raw secret was just
        // typed into this chat regardless of whether we could store it.
        console.error(
          `[telegram] received /setkey for "${setKey.name}" but secret-handling is not armed ` +
            '(DEPLEX_BOT_MASTER_KEY missing/invalid at startup) -- not stored.',
        );
      }
      // Best-effort cleanup either way -- get the raw secret out of chat
      // history even if it couldn't be stored.
      try {
        await deleteMessage(cfg, msg.message_id, apiRequestFn);
      } catch (err) {
        console.error(
          `[telegram] failed to delete message ${msg.message_id} containing a raw secret -- remove it manually: ${err.message}`,
        );
      }
    }
  }
  return nextOffset;
}

export async function startBotListener(cfg, handlers) {
  let offset = 0;
  // eslint-disable-next-line no-constant-condition
  while (true) {
    try {
      offset = await pollBotUpdates(cfg, handlers, { offset });
    } catch (err) {
      console.error(`[telegram] bot listener error: ${err.message}`);
      await new Promise((resolve) => setTimeout(resolve, 5000));
    }
  }
}
