// What the monitor decides, apart from how it finds out or tells anyone:
// given what it remembered and what it just saw, what it remembers now and
// what, if anything, it says. Plain functions, so `node --test` runs them.
//
// It says something only when the answer changes. A single failed check is a
// container restarting during a deploy, or a packet lost on the way; three in
// a row, a minute apart, is central down. Coming back needs two good checks
// in a row, so a machine that answers every other minute is reported down
// once rather than every few minutes.

export const DOWN_AFTER = 3;
export const UP_AFTER = 2;

/** A dump is uploaded every hour; one older than this means one was missed. */
export const BACKUP_STALE_MS = 2 * 60 * 60 * 1000;

/**
 * One check of central. [failed] lists what did not answer, as
 * `"storage: 502"`; empty when everything did.
 */
export function stepCentral(state, failed, now) {
  const s = {
    down: false,
    fails: 0,
    oks: 0,
    firstFail: null,
    firstOk: null,
    downSince: null,
    ...state,
  };
  if (failed.length) {
    s.oks = 0;
    s.firstOk = null;
    s.fails += 1;
    if (s.fails === 1) s.firstFail = now;
    if (!s.down && s.fails >= DOWN_AFTER) {
      s.down = true;
      s.downSince = s.firstFail;
      return { state: s, alert: { kind: "down", since: s.downSince, failed } };
    }
    return { state: s, alert: null };
  }
  s.fails = 0;
  s.firstFail = null;
  s.oks += 1;
  if (s.oks === 1) s.firstOk = now;
  if (s.down && s.oks >= UP_AFTER) {
    const alert = { kind: "up", since: s.downSince, until: s.firstOk };
    s.down = false;
    s.downSince = null;
    return { state: s, alert };
  }
  return { state: s, alert: null };
}

/**
 * One look at the backups. [newest] is when the newest hourly dump was
 * uploaded (ms), null when there is none, or an Error when the bucket could
 * not be read. Says so once when they stop, and once when they start again.
 */
export function stepBackups(state, newest, now) {
  const s = { stale: false, ...state };
  const fresh = typeof newest === "number" && now - newest <= BACKUP_STALE_MS;
  if (!fresh && !s.stale) {
    s.stale = true;
    return { state: s, alert: { kind: "backups-stale", newest } };
  }
  if (fresh && s.stale) {
    s.stale = false;
    return { state: s, alert: { kind: "backups-ok", newest } };
  }
  return { state: s, alert: null };
}

/**
 * The day's count for the daily post: checks run, checks that failed, and
 * outages declared, since [since].
 */
export function tally(state, failed, alert, now) {
  const t = { since: now, checks: 0, failed: 0, outages: 0, ...state };
  t.checks += 1;
  if (failed.length) t.failed += 1;
  if (alert?.kind === "down") t.outages += 1;
  return t;
}

// ── Words ─────────────────────────────────────────────────

/** "2:02 PM" in [timeZone]. */
export function clock(ms, timeZone) {
  return new Intl.DateTimeFormat("en-US", {
    timeZone,
    hour: "numeric",
    minute: "2-digit",
  }).format(new Date(ms));
}

/** "34 min", "2 h 5 min", "3 days 4 h". */
export function span(ms) {
  const minutes = Math.max(1, Math.round(ms / 60000));
  if (minutes < 60) return `${minutes} min`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) {
    const rest = minutes % 60;
    return rest ? `${hours} h ${rest} min` : `${hours} h`;
  }
  const days = Math.floor(hours / 24);
  const rest = hours % 24;
  return rest ? `${days} days ${rest} h` : `${days} days`;
}

/** An alert as a subject line and a body, the same words on every channel. */
export function words(alert, now, timeZone) {
  const at = (ms) => clock(ms, timeZone);
  switch (alert.kind) {
    case "down":
      return {
        subject: "Central is down",
        text:
          `Central is down: api.joinrift.app hasn't answered since ` +
          `${at(alert.since)}.\n${alert.failed.join("\n")}`,
      };
    case "up":
      return {
        subject: "Central is working again",
        text:
          `Central is working again. It was down for ` +
          `${span(alert.until - alert.since)} (${at(alert.since)} to ` +
          `${at(alert.until)}).`,
      };
    case "backups-stale":
      return {
        subject: "Central's backups have stopped",
        text:
          alert.newest instanceof Error
            ? `Backups: the monitor can't read the backup bucket ` +
              `(${alert.newest.message}).`
            : alert.newest == null
              ? "Backups: there are no hourly backups in R2."
              : `Backups: the newest one in R2 is ` +
                `${span(now - alert.newest)} old. The hourly backup hasn't ` +
                `uploaded since ${at(alert.newest)}.`,
      };
    case "backups-ok":
      return {
        subject: "Central's backups are running again",
        text:
          `Backups are running again: the newest one in R2 was uploaded at ` +
          `${at(alert.newest)}.`,
      };
    case "daily": {
      const { tally: t, central, newest } = alert;
      const lines = [
        central?.down
          ? `Daily check: central is down, since ${at(central.downSince)}.`
          : "Daily check: central is up.",
      ];
      if (t) {
        const checks = t.checks.toLocaleString("en-US");
        const outages =
          t.outages === 0
            ? "no outage"
            : t.outages === 1
              ? "1 outage"
              : `${t.outages} outages`;
        lines.push(
          t.failed === 0
            ? `All ${checks} checks in the last ${span(now - t.since)} passed.`
            : `${t.failed.toLocaleString("en-US")} of ${checks} checks in the ` +
                `last ${span(now - t.since)} failed (${outages}).`,
        );
      }
      lines.push(
        newest instanceof Error
          ? `Backups: can't read the bucket (${newest.message}).`
          : newest == null
            ? "Backups: none in R2."
            : `Newest backup: ${at(newest)} (${span(now - newest)} ago).`,
      );
      return { subject: "Central daily check", text: lines.join("\n") };
    }
    case "started":
      return {
        subject: "Central monitor is on",
        text:
          "Central monitor is on. It checks api.joinrift.app every minute " +
          "and the backups every hour, and writes here when either changes.",
      };
  }
  throw new Error(`no words for ${alert.kind}`);
}
