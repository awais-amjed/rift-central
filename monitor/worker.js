// The central monitor: checks api.joinrift.app every minute and the backups
// every hour, and writes to the owner when either changes — a post in a Rift
// channel through a webhook, and an email.
//
// It runs on Cloudflare so that it is somewhere else. On 9 Oct 2026 the VPS
// lost its network for seven and a half hours while staying up, and a check
// running on it would have run the whole time and told nobody.
//
// Both ways out, because neither is enough alone: a Rift server wakes a phone
// through central's push relay, so with central down the post arrives
// silently, and only the email reaches a pocket.
import { DurableObject } from "cloudflare:workers";
import { EmailMessage } from "cloudflare:email";
import { stepBackups, stepCentral, words } from "./watch.mjs";

/** What is checked, each the cheapest call that proves its service answers. */
const CHECKS = [
  ["auth", "/auth/v1/health"],
  // An RPC rather than PostgREST's root, which it serves from its cache with
  // the database gone.
  ["database", "/rest/v1/rpc/is_handle_available?p_handle=monitor"],
  ["storage", "/storage/v1/status"],
  ["realtime", "/realtime/v1/api/ping"],
  ["functions", "/functions/v1/push_send"],
];

const ANSWER_WITHIN_MS = 10_000;

/** Once an hour, well after the backup at seven past has uploaded. */
const BACKUP_CRON = "30 * * * *";

/** The hourly dumps (stack/backup.sh): folder names readable, file names not. */
const DUMPS = "db/hourly/";

export default {
  async scheduled(event, env) {
    const watch = env.WATCH.get(env.WATCH.idFromName("central"));
    await watch.run(event.scheduledTime, event.cron === BACKUP_CRON);
  },
};

/**
 * Remembers between runs. One object, so every run reads what the last one
 * wrote: KV is eventually consistent, and a run in another location reading
 * a minute-old count would double an alert or miss one.
 */
export class Watch extends DurableObject {
  async run(now, backupsOnly) {
    const env = this.env;
    const store = this.ctx.storage;
    const zone = env.TIME_ZONE;
    const alerts = [];

    if (!(await store.get("started")) && env.RIFT_WEBHOOK_URL && env.ALERT_TO) {
      // The first run with both ways out set says so, which proves they work.
      // Not before: a deploy runs before its secrets are put.
      alerts.push({ kind: "started" });
      await store.put("started", true);
    }

    if (backupsOnly) {
      const backups = stepBackups(
        await store.get("backups"),
        await newestDump(env),
        now,
      );
      await store.put("backups", backups.state);
      if (backups.alert) alerts.push(backups.alert);
    } else {
      const failed = await checkCentral(env);
      const central = stepCentral(await store.get("central"), failed, now);
      await store.put("central", central.state);
      if (central.alert) alerts.push(central.alert);
    }

    for (const alert of alerts) {
      const message = words(alert, now, zone);
      console.log(`[monitor] ${message.text}`);
      await Promise.all([post(env, message), email(env, message)]);
    }
  }
}

// ── Looking ───────────────────────────────────────────────

/** What did not answer, as "storage: 502"; empty when everything did. */
async function checkCentral(env) {
  const results = await Promise.all(
    CHECKS.map(async ([name, path]) => {
      try {
        const response = await fetch(env.CENTRAL_URL + path, {
          headers: { apikey: env.CENTRAL_KEY },
          signal: AbortSignal.timeout(ANSWER_WITHIN_MS),
        });
        await response.body?.cancel();
        return response.ok ? null : `${name}: ${response.status}`;
      } catch (e) {
        return e.name === "TimeoutError"
          ? `${name}: no answer in ${ANSWER_WITHIN_MS / 1000} s`
          : `${name}: ${e.message}`;
      }
    }),
  );
  return results.filter(Boolean);
}

/** When the newest hourly dump was uploaded, null for none, an Error if unreadable. */
async function newestDump(env) {
  try {
    let newest = null;
    let cursor;
    do {
      const page = await env.BACKUPS.list({ prefix: DUMPS, cursor });
      for (const object of page.objects) {
        const at = object.uploaded.getTime();
        if (newest == null || at > newest) newest = at;
      }
      cursor = page.truncated ? page.cursor : undefined;
    } while (cursor);
    return newest;
  } catch (e) {
    return e instanceof Error ? e : new Error(String(e));
  }
}

// ── Telling ───────────────────────────────────────────────

/** A post in the owner's channel. The webhook's URL is its secret. */
async function post(env, { text }) {
  if (!env.RIFT_WEBHOOK_URL) return;
  try {
    const response = await fetch(env.RIFT_WEBHOOK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
      signal: AbortSignal.timeout(ANSWER_WITHIN_MS),
    });
    const reply = await response.json().catch(() => ({}));
    if (!reply.success) {
      console.error(`[monitor] webhook refused: ${reply.error ?? response.status}`);
    }
  } catch (e) {
    console.error(`[monitor] webhook unreachable: ${e.message}`);
  }
}

/**
 * An email through Cloudflare Email Routing, which sends only to an address
 * verified on the account, from one on a zone it routes for.
 */
async function email(env, { subject, text }) {
  if (!env.ALERT_TO) return;
  const raw = [
    `From: Rift monitor <${env.ALERT_FROM}>`,
    `To: ${env.ALERT_TO}`,
    `Subject: ${subject}`,
    `Date: ${new Date().toUTCString()}`,
    `Message-ID: <${crypto.randomUUID()}@${env.ALERT_FROM.split("@")[1]}>`,
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=utf-8",
    "Content-Transfer-Encoding: 8bit",
    "",
    text,
    "",
  ].join("\r\n");
  try {
    await env.EMAIL.send(new EmailMessage(env.ALERT_FROM, env.ALERT_TO, raw));
  } catch (e) {
    console.error(`[monitor] email not sent: ${e.message}`);
  }
}
