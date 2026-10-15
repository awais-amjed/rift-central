// node --test monitor/
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  BACKUP_STALE_MS,
  span,
  stepBackups,
  stepCentral,
  words,
} from "./watch.mjs";

const MIN = 60_000;
const T0 = Date.UTC(2026, 9, 9, 8, 46); // 1:46 PM in Karachi

/** Runs one check a minute; returns each run's alert. */
function run(results, state = undefined) {
  const alerts = [];
  results.forEach((failed, i) => {
    const r = stepCentral(state, failed, T0 + i * MIN);
    state = r.state;
    alerts.push(r.alert);
  });
  return { alerts, state };
}

const bad = ["auth: 502"];

test("one or two failed checks say nothing", () => {
  const { alerts } = run([bad, bad, [], bad, []]);
  assert.deepEqual(alerts, [null, null, null, null, null]);
});

test("three in a row is down, from the first of them", () => {
  const { alerts } = run([[], bad, bad, bad, bad, bad]);
  assert.deepEqual(alerts.slice(0, 3), [null, null, null]);
  assert.deepEqual(alerts[3], { kind: "down", since: T0 + MIN, failed: bad });
  // Said once, not every minute it stays down.
  assert.deepEqual(alerts.slice(4), [null, null]);
});

test("back after two good checks in a row, timed from the first", () => {
  const { alerts } = run([bad, bad, bad, [], bad, [], [], []]);
  assert.equal(alerts[2].kind, "down");
  // One good check between failures is not back.
  assert.deepEqual(alerts.slice(3, 6), [null, null, null]);
  assert.deepEqual(alerts[6], { kind: "up", since: T0, until: T0 + 5 * MIN });
  assert.equal(alerts[7], null);
});

test("a machine answering every other minute is down once", () => {
  const flapping = [bad, bad, bad, [], bad, [], bad, [], bad];
  const { alerts } = run(flapping);
  assert.equal(alerts.filter(Boolean).length, 1);
});

test("backups: stale once, fresh again once", () => {
  const now = T0;
  let r = stepBackups(undefined, now - 50 * MIN, now);
  assert.equal(r.alert, null);
  r = stepBackups(r.state, now - BACKUP_STALE_MS - MIN, now);
  assert.equal(r.alert.kind, "backups-stale");
  r = stepBackups(r.state, now - BACKUP_STALE_MS - 61 * MIN, now + 60 * MIN);
  assert.equal(r.alert, null);
  r = stepBackups(r.state, now + 40 * MIN, now + 2 * 60 * MIN);
  assert.equal(r.alert.kind, "backups-ok");
});

test("backups: none, or an unreadable bucket, is stale", () => {
  assert.equal(stepBackups(undefined, null, T0).alert.kind, "backups-stale");
  const unreadable = stepBackups(undefined, new Error("403"), T0).alert;
  assert.match(words(unreadable, T0, "UTC").text, /can't read the backup bucket \(403\)/);
});

test("the words", () => {
  const down = words(
    { kind: "down", since: T0, failed: ["auth: 502", "storage: no answer in 10 s"] },
    T0,
    "Asia/Karachi",
  );
  assert.equal(down.subject, "Central is down");
  assert.equal(
    down.text,
    "Central is down: api.joinrift.app hasn't answered since 1:46 PM.\n" +
      "auth: 502\nstorage: no answer in 10 s",
  );
  const up = words(
    { kind: "up", since: T0, until: T0 + 34 * MIN },
    T0,
    "Asia/Karachi",
  );
  assert.equal(
    up.text,
    "Central is working again. It was down for 34 min (1:46 PM to 2:20 PM).",
  );
});

test("spans", () => {
  assert.equal(span(20_000), "1 min");
  assert.equal(span(34 * MIN), "34 min");
  assert.equal(span(125 * MIN), "2 h 5 min");
  assert.equal(span(7.5 * 60 * MIN), "7 h 30 min");
  assert.equal(span(76 * 60 * MIN), "3 days 4 h");
});
