"use strict";

const { freshEnv } = require("./helpers");
freshEnv();

const test = require("node:test");
const assert = require("node:assert");

const d = require("../db");
const config = require("../config");
const sessions = require("../sessions");
const ratelimit = require("../ratelimit");
const audit = require("../audit");

test("sessions are stored hashed, expire, rotate and revoke", () => {
  const { token, session } = sessions.create({ kind: "voter", subject: "152637", stage: "login" });

  const row = d.get("SELECT tokenHash FROM sessions");
  assert.notStrictEqual(row.tokenHash, token, "raw token is never stored");
  assert.strictEqual(row.tokenHash, sessions.hashToken(token));

  assert.ok(sessions.lookup(token, "voter"));
  assert.strictEqual(sessions.lookup(token, "admin"), null, "a voter token is not an admin token");
  assert.strictEqual(sessions.lookup("nonsense", "voter"), null);

  // idle expiry
  d.run("UPDATE sessions SET idleExpiresAt = ? WHERE tokenHash = ?", Date.now() - 1, session.tokenHash);
  assert.strictEqual(sessions.lookup(token, "voter"), null, "idle-expired session is dead");
  d.run("UPDATE sessions SET idleExpiresAt = ? WHERE tokenHash = ?", Date.now() + 60_000, session.tokenHash);

  // absolute expiry cannot be extended by activity
  d.run("UPDATE sessions SET absoluteExpiresAt = ?, lastActiveAt = 0 WHERE tokenHash = ?", Date.now() + 5_000, session.tokenHash);
  const touched = sessions.touch(sessions.lookup(token, "voter"));
  assert.ok(touched.idleExpiresAt <= Date.now() + 5_000, "idle deadline never passes the absolute deadline");

  // rotation: new token works, old one is dead
  d.run("UPDATE sessions SET absoluteExpiresAt = ? WHERE tokenHash = ?", Date.now() + 3600_000, session.tokenHash);
  const rotated = sessions.rotate(sessions.lookup(token, "voter"), { stage: "rules" });
  assert.strictEqual(sessions.lookup(token, "voter"), null, "old token invalid after rotation");
  assert.strictEqual(sessions.lookup(rotated.token, "voter").stage, "rules");

  sessions.revokeToken(rotated.token, "logout");
  assert.strictEqual(sessions.lookup(rotated.token, "voter"), null, "logout invalidates the token");
});

test("sessions survive a 'restart' because they live in the database", () => {
  const { token } = sessions.create({ kind: "admin", subject: "7", stage: "full" });

  // Simulate restart: nothing in memory is consulted by lookup().
  assert.ok(sessions.lookup(token, "admin"));
  assert.strictEqual(sessions.activeCounts().admin, 1);
});

test("revokeAllFor ends every session for a subject except the one kept", () => {
  const a = sessions.create({ kind: "admin", subject: "9", stage: "full" });
  const b = sessions.create({ kind: "admin", subject: "9", stage: "full" });

  sessions.revokeAllFor("admin", "9", "password-changed", a.session.tokenHash);
  assert.ok(sessions.lookup(a.token, "admin"));
  assert.strictEqual(sessions.lookup(b.token, "admin"), null);
});

test("voter sessions are deleted the moment they end; admin sessions are kept as a record", () => {
  const voter = sessions.create({ kind: "voter", subject: "1111", stage: "login" });
  const admin = sessions.create({ kind: "admin", subject: "5", stage: "full" });

  sessions.revokeToken(voter.token, "done");
  sessions.revokeToken(admin.token, "done");

  assert.strictEqual(d.get("SELECT COUNT(*) AS n FROM sessions WHERE subject = '1111'").n, 0, "no matric left behind");
  assert.strictEqual(d.get("SELECT COUNT(*) AS n FROM sessions WHERE tokenHash = ?", admin.session.tokenHash).n, 1);

  // an expired-but-never-ended voter session is swept an hour after it lapsed
  const lapsed = sessions.create({ kind: "voter", subject: "2222", stage: "login" });
  d.run("UPDATE sessions SET idleExpiresAt = ? WHERE tokenHash = ?", Date.now() - 2 * 3600_000, lapsed.session.tokenHash);
  sessions.sweep();
  assert.strictEqual(d.get("SELECT COUNT(*) AS n FROM sessions WHERE subject = '2222'").n, 0);

  // admin history is only purged after 30 days
  d.run("UPDATE sessions SET revokedAt = ? WHERE tokenHash = ?", Date.now() - 2 * 3600_000, admin.session.tokenHash);
  sessions.sweep();
  assert.strictEqual(d.get("SELECT COUNT(*) AS n FROM sessions WHERE tokenHash = ?", admin.session.tokenHash).n, 1);
  d.run("UPDATE sessions SET revokedAt = ? WHERE tokenHash = ?", Date.now() - 31 * 24 * 3600_000, admin.session.tokenHash);
  sessions.sweep();
  assert.strictEqual(d.get("SELECT COUNT(*) AS n FROM sessions WHERE tokenHash = ?", admin.session.tokenHash).n, 0);
});

test("cookie attributes: HttpOnly, SameSite=Strict, Secure when configured", () => {
  const headers = {};
  const res = {
    getHeader: (name) => headers[name],
    setHeader: (name, value) => { headers[name] = value; }
  };

  sessions.setSessionCookie(res, config.VOTER_COOKIE, "abc", { absoluteExpiresAt: Date.now() + 600_000 });
  const cookie = headers["Set-Cookie"][0];

  assert.ok(cookie.startsWith(`${config.VOTER_COOKIE}=abc;`));
  assert.ok(cookie.includes("HttpOnly"));
  assert.ok(cookie.includes("SameSite=Strict"));
  assert.ok(cookie.includes("Path=/"));
  assert.ok(/Max-Age=\d+/.test(cookie));
  assert.strictEqual(cookie.includes("Secure"), config.COOKIE_SECURE);

  sessions.clearSessionCookie(res, config.VOTER_COOKIE);
  assert.ok(headers["Set-Cookie"][1].includes("Max-Age=0"));

  assert.deepStrictEqual(sessions.parseCookies("a=1; b=two%20words; a=ignored"), { a: "1", b: "two words" });
});

test("rate limit: allows the limit, blocks the next attempt, persists in the database", () => {
  const rule = config.RATE.voterLoginMatric;

  for (let i = 0; i < rule.limit; i += 1) {
    assert.ok(ratelimit.take("voterLoginMatric", "v-test").allowed, `attempt ${i + 1}`);
  }

  const over = ratelimit.take("voterLoginMatric", "v-test");
  assert.strictEqual(over.allowed, false);
  assert.ok(over.retryAfterSec > 0 && over.justBlocked);

  // a different key is unaffected
  assert.ok(ratelimit.take("voterLoginMatric", "v-other").allowed);

  // the block is in the DB, so it survives a restart
  const row = d.get("SELECT blockedUntil FROM rate_limits WHERE bucket = ?", "voterLoginMatric:v-test");
  assert.ok(row.blockedUntil > Date.now());
  assert.strictEqual(ratelimit.peek("voterLoginMatric", "v-test").allowed, false);

  assert.ok(ratelimit.currentlyBlocked() >= 1);

  // blocking is audited once
  const blocks = d.get("SELECT COUNT(*) AS n FROM audit_log WHERE message LIKE ?", "%tripped%").n;
  assert.strictEqual(blocks, 1);

  ratelimit.reset("voterLoginMatric", "v-test");
  assert.ok(ratelimit.take("voterLoginMatric", "v-test").allowed);
});

test("rate-limit window resets after it passes", () => {
  const rule = config.RATE.problemIp;
  for (let i = 0; i < rule.limit; i += 1) ratelimit.take("problemIp", "2.2.2.2");

  d.run("UPDATE rate_limits SET windowStart = ? WHERE bucket = ?", Date.now() - (rule.windowSec + 1) * 1000, "problemIp:2.2.2.2");
  assert.ok(ratelimit.take("problemIp", "2.2.2.2").allowed, "a fresh window starts counting from zero");
});

test("audit chain, pseudonyms, search and monitored access", () => {
  const tag = audit.voterTag("152637");
  assert.strictEqual(tag, audit.voterTag("152637"));
  assert.notStrictEqual(tag, audit.voterTag("152638"));
  assert.ok(!tag.includes("152637"));

  audit.append("system", "voter", `Voter ${tag} signed in`);
  audit.append("system", "voter", `line one\nline two\u0000 injected`);
  assert.ok(audit.list({ voter: "152637" }).length === 1, "search by matric finds the pseudonymous entry");
  assert.ok(!audit.list({ category: "voter" }).some((row) => /[\n\u0000]/.test(row.message)), "control characters are stripped");

  const cp = audit.checkpoint("test");
  assert.strictEqual(cp.auditId, audit.head().id);

  const admin = { id: 1, email: "a@b.ng", role: "results_officer" };
  const first = audit.recordAccess(admin, "viewed the audit log");
  const second = audit.recordAccess(admin, "viewed the audit log");
  assert.ok(first && second === null, "routine views are throttled");
  assert.ok(audit.recordAccess(admin, "exported the audit log", { always: true }));

  assert.ok(audit.verify().ok);

  // tampering is detected: bypass the trigger as someone with raw file access would
  d.db.exec("DROP TRIGGER trg_audit_no_update");
  d.run("UPDATE audit_log SET message = 'rewritten history' WHERE id = 1");
  const broken = audit.verify();
  assert.strictEqual(broken.ok, false);
  assert.strictEqual(broken.chain.brokenAtId, 1);
});
