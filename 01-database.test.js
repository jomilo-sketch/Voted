"use strict";

const { freshEnv } = require("./helpers");
const dir = freshEnv();

const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const path = require("path");

const d = require("../db");
const now = d.nowIso();

test("schema is created and the key fingerprint is recorded", () => {
  const tables = d.all("SELECT name FROM sqlite_master WHERE type = 'table'").map((row) => row.name);

  [
    "election", "offices", "candidates", "students", "turnout", "ballots", "ballot_selections",
    "receipts", "audit_log", "sessions", "rate_limits", "admins", "result_reports"
  ].forEach((name) => assert.ok(tables.includes(name), `missing table ${name}`));

  assert.ok(d.getMeta("key_fingerprint"));
});

test("item 1: the database itself refuses a matric that is not digits only", () => {
  const rejected = ["matric 152637", "BOU/15/2637", "12", "15 2637", "152637a", "", "٣٤٥٦٧٨", "1234567890123456"];

  rejected.forEach((bad) => {
    assert.throws(
      () => d.run("INSERT INTO students (matric, addedAt) VALUES (?, ?)", bad, now),
      undefined,
      `should reject ${JSON.stringify(bad)}`
    );
  });

  ["152637", "1257", "173637"].forEach((good) => {
    d.run("INSERT INTO students (matric, addedAt) VALUES (?, ?)", good, now);
  });

  assert.strictEqual(d.get("SELECT COUNT(*) AS n FROM students").n, 3);
});

test("audit_log is append-only at the database level", () => {
  d.run(
    "INSERT INTO audit_log (occurredAt, actor, category, message, prevHash, hash) VALUES (?, ?, ?, ?, ?, ?)",
    now, "system", "test", "message", "0".repeat(64), "a".repeat(64)
  );

  assert.throws(() => d.run("UPDATE audit_log SET message = ?", "changed"), /append-only/);
  assert.throws(() => d.run("DELETE FROM audit_log"), /append-only/);
});

test("transactions roll back, nest with savepoints, and reject async callbacks", () => {
  assert.throws(
    () => d.tx(() => {
      d.run("INSERT INTO students (matric, addedAt) VALUES (?, ?)", "9999", now);
      throw new Error("boom");
    }),
    /boom/
  );
  assert.strictEqual(d.get("SELECT COUNT(*) AS n FROM students WHERE matric = ?", "9999").n, 0);

  d.tx(() => {
    d.run("INSERT INTO students (matric, addedAt) VALUES (?, ?)", "8888", now);

    try {
      d.tx(() => {
        d.run("INSERT INTO students (matric, addedAt) VALUES (?, ?)", "7777", now);
        throw new Error("inner failure");
      });
    } catch (error) {
      /* the inner savepoint is rolled back; the outer transaction continues */
    }
  });

  assert.strictEqual(d.get("SELECT COUNT(*) AS n FROM students WHERE matric = ?", "8888").n, 1);
  assert.strictEqual(d.get("SELECT COUNT(*) AS n FROM students WHERE matric = ?", "7777").n, 0);

  assert.throws(() => d.tx(async () => {}), /synchronous/);
  d.run("INSERT INTO students (matric, addedAt) VALUES (?, ?)", "6666", now); // still usable
});

test("ballots are immutable, and a live election cannot be wound back", () => {
  d.run("INSERT INTO election (id, electionName, schoolName, updatedAt) VALUES (1, ?, ?, ?)", "E", "S", now);

  d.run("INSERT INTO ballots (ballotId) VALUES (?)", "b1");
  d.run("DELETE FROM ballots"); // rehearsal mode: allowed

  d.run("INSERT INTO ballots (ballotId) VALUES (?)", "b2");
  assert.throws(() => d.run("UPDATE ballots SET ballotId = ?", "zz"), /cannot be modified/);

  d.run("UPDATE election SET mode = 'live'");
  assert.throws(() => d.run("DELETE FROM ballots"), /live election/);
  assert.throws(() => d.run("UPDATE election SET mode = 'rehearsal'"), /switched back/);

  d.run("UPDATE election SET status = 'closed'");
  assert.throws(() => d.run("UPDATE election SET status = 'active'"), /reopened/);
});

test("integrity check passes and the data directory is private", () => {
  assert.ok(d.integrityCheck().ok);

  const keyMode = fs.statSync(path.join(dir, "keys", "master.key")).mode & 0o777;
  assert.strictEqual(keyMode, 0o600);
});
