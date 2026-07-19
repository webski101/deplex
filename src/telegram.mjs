// alerts + manual panic trigger

import https from 'node:https';

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

export async function sendAlert(cfg, text) {
  if (!cfg?.botToken || !cfg?.chatId) {
    console.log(`[telegram disabled] ${text}`);
    return null;
  }
  return apiRequest(cfg.botToken, 'sendMessage', {
    chat_id: cfg.chatId,
    text: escapeHtml(text),
    parse_mode: 'HTML',
  });
}

export async function pollPanicCommand(cfg, onPanic, { offset = 0, timeoutSec = 30 } = {}) {
  const updates = await apiRequest(cfg.botToken, 'getUpdates', {
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
    if (chatId !== String(cfg.chatId)) continue; // only the allowlisted chat can trigger panic
    if (msg.text.trim().toLowerCase().startsWith('/panic')) {
      onPanic({ type: 'panic', chatId, observedAt: new Date().toISOString() });
    }
  }
  return nextOffset;
}

export async function startPanicListener(cfg, onPanic) {
  let offset = 0;
  // eslint-disable-next-line no-constant-condition
  while (true) {
    try {
      offset = await pollPanicCommand(cfg, onPanic, { offset });
    } catch (err) {
      console.error(`[telegram] panic listener error: ${err.message}`);
      await new Promise((resolve) => setTimeout(resolve, 5000));
    }
  }
}
