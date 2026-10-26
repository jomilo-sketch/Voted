"use strict";

const { freshEnv } = require("./helpers");
freshEnv();

const fs = require("fs");
const test = require("node:test");
const assert = require("node:assert");

const { Client, startServer } = require("./http-client");
const { PASSWORD, freshCode, firstSignIn, signIn, adminToken, sessionOf, expireStepUp, stepUp } = require("./admin-helpers");
const d = require("../db");
const config = require("../config");
const sessions = require("../sessions");

let app;
let base;
let accounts; // by role
let electoral;
let results;
let tech;

test.before(async () => {
  app = await startServer();
  base = app.base;
  accounts = Object.fromEntries(app.startup.createdAdmins.map((account) => [account.role, account]));

  // The per-address ceiling is exercised on its own below; keep it out of the way of the other tests.
  config.RATE.adminLoginIp.limit = 1000;
  config.RATE.adminTotpIp.limit = 1000;
});

test.after(async () => {
  await app.stop();
});

test("starter accounts: one-time passwords, stored only as salted hashes, handed over in a private file", async () => {
  assert.strictEqual(app.startup.createdAdmins.length, 3);
  assert.deepStrictEqual(
    app.startup.createdAdmins.map((account) => account.role).sort(),
    ["electoral_officer", "results_officer", "technical_support"]
  );

  const rows = d.all("SELECT email, passwordHash, mustChangePassword, totpEnabled, totpSecretEnc FROM admins");

  rows.forEach((row) => {
    const temporary = accounts[d.get("SELECT role FROM admins WHERE email = ?", row.email).role].temporaryPassword;

    assert.ok(!row.passwordHash.includes(temporary), "no plaintext password in the database");
    assert.match(row.passwordHash, /^scrypt\$/, "a modern memory-hard salted hash");
    assert.strictEqual(row.mustChangePassword, 1);
    assert.strictEqual(row.totpEnabled, 0);
  });

  assert.strictEqual(new Set(rows.map((row) => row.passwordHash.split("$")[4])).size, 3, "every hash has its own salt");

  const stat = fs.statSync(config.CREDENTIALS_FILE);
  assert.strictEqual(stat.mode & 0o077, 0, "the hand-over file is readable by its owner only");
});

test("nothing is available without signing in", async () => {
  const client = new Client(base);

  assert.deepStrictEqual((await client.get("/api/admin/session")).json, { signedIn: false });

  for (const path of ["/api/admin/dashboard", "/api/admin/students", "/api/admin/results", "/api/admin/audit", "/api/admin/ops/health", "/api/admin/admins", "/api/admin/security"]) {
    const response = await client.get(path);

    assert.strictEqual(response.status, 401, path);
    assert.strictEqual(response.json.code, "unauthenticated");
  }

  assert.strictEqual((await client.get("/api/admin/students/export.csv")).status, 401);
  assert.strictEqual((await client.get("/api/admin/ops/backups/x")).status, 401);
});

test("wrong and unknown accounts get the same answer, so nobody can find out who is an administrator", async () => {
  const client = new Client(base);

  const unknown = await client.post("/api/admin/login", { email: "nobody@bouesti.ng", password: "Whatever-123-xyz" });
  const wrong = await client.post("/api/admin/login", { email: accounts.electoral_officer.email, password: "Whatever-123-xyz" });

  assert.strictEqual(unknown.status, 401);
  assert.strictEqual(wrong.status, 401);
  assert.strictEqual(unknown.json.error, wrong.json.error);
  assert.strictEqual(unknown.json.code, "login-failed");
  assert.strictEqual(client.jar.size, 0);
});

test("first sign-in staircase: temporary password → own password → 2FA → recovery codes → dashboard", async () => {
  const account = accounts.electoral_officer;
  const client = new Client(base);

  const login = await client.post("/api/admin/login", { email: account.email, password: account.temporaryPassword });
  assert.strictEqual(login.json.next, "change-password");

  // the cookie is HttpOnly + SameSite=Strict, and nothing is available yet
  assert.match(login.setCookies[0], /HttpOnly/i);
  assert.match(login.setCookies[0], /SameSite=Strict/i);

  const early = await client.get("/api/admin/dashboard");
  assert.strictEqual(early.status, 403);
  assert.strictEqual(early.json.code, "wrong-stage");

  assert.strictEqual((await client.get("/api/admin/session")).json.next, "change-password");

  // weak passwords are refused with reasons
  for (const weak of ["short", "alllowercaseletters", "Electoral-Officer-1", account.temporaryPassword]) {
    const refused = await client.post("/api/admin/setup/password", { newPassword: weak });
    assert.strictEqual(refused.status, 400, weak);
    assert.ok(refused.json.error, "a reason is given");
  }

  const chosen = await client.post("/api/admin/setup/password", { newPassword: PASSWORD });
  assert.strictEqual(chosen.json.next, "enroll");

  // still not signed in fully
  assert.strictEqual((await client.get("/api/admin/dashboard")).status, 403);

  const setup = await client.post("/api/admin/setup/totp/start", {});
  assert.match(setup.json.uri, /^otpauth:\/\/totp\//);
  assert.ok(setup.json.secret.length >= 16);

  const wrong = await client.post("/api/admin/setup/totp/confirm", { code: "000000" });
  assert.strictEqual(wrong.status, 400);

  const confirmed = await client.post("/api/admin/setup/totp/confirm", { code: freshCode(setup.json.secret, account.email) });
  assert.strictEqual(confirmed.status, 200);
  assert.strictEqual(confirmed.json.next, "dashboard");
  assert.strictEqual(confirmed.json.recoveryCodes.length, 8);
  assert.strictEqual(new Set(confirmed.json.recoveryCodes).size, 8);

  const session = await client.get("/api/admin/session");
  assert.strictEqual(session.json.stage, "full");
  assert.strictEqual(session.json.admin.role, "electoral_officer");
  assert.ok(session.json.admin.permissions.includes("election.manage"));
  assert.ok(!session.json.admin.permissions.includes("ops.manage"), "least privilege");
  assert.ok(session.json.session.idleMinutes > 0 && session.json.session.stepUpValidForSec > 0);

  assert.strictEqual((await client.get("/api/admin/dashboard")).status, 200);

  // the one-time password cannot be used again
  const reused = await new Client(base).post("/api/admin/login", { email: account.email, password: account.temporaryPassword });
  assert.strictEqual(reused.status, 401);

  // secrets are stored encrypted, recovery codes only as hashes
  const row = d.get("SELECT totpSecretEnc FROM admins WHERE email = ?", account.email);
  assert.ok(!row.totpSecretEnc.includes(setup.json.secret.replace(/\s/g, "")));
  const stored = d.all("SELECT * FROM admin_recovery_codes").map((record) => JSON.stringify(record)).join("");
  confirmed.json.recoveryCodes.forEach((code) => assert.ok(!stored.includes(code.replace(/-/g, "")), "recovery codes are not stored in the clear"));

  electoral = { client, email: account.email, password: PASSWORD, secret: setup.json.secret, recoveryCodes: confirmed.json.recoveryCodes };
});

test("later sign-ins need the 6-digit code; a used code cannot be replayed", async () => {
  const client = new Client(base);

  const login = await client.post("/api/admin/login", { email: electoral.email, password: electoral.password });
  assert.strictEqual(login.json.next, "totp");
  assert.strictEqual((await client.get("/api/admin/dashboard")).status, 403, "password alone is not enough");

  const wrong = await client.post("/api/admin/totp", { code: "123456" });
  assert.strictEqual(wrong.status, 401);
  assert.strictEqual(wrong.json.code, "bad-code");

  const code = freshCode(electoral.secret, electoral.email);
  const good = await client.post("/api/admin/totp", { code });
  assert.strictEqual(good.status, 200);
  assert.strictEqual((await client.get("/api/admin/dashboard")).status, 200);

  // someone who saw the code over a shoulder cannot use it a second time
  const other = new Client(base);
  await other.post("/api/admin/login", { email: electoral.email, password: electoral.password });

  const replay = await other.post("/api/admin/totp", { code });
  assert.strictEqual(replay.status, 401, "the same code is refused twice");
});

test("a recovery code signs in once and then stops working", async () => {
  const [first, second] = electoral.recoveryCodes;
  const client = new Client(base);

  await client.post("/api/admin/login", { email: electoral.email, password: electoral.password });

  const used = await client.post("/api/admin/totp", { code: first });
  assert.strictEqual(used.status, 200);
  assert.match(used.json.warning, /recovery code/i);

  const again = new Client(base);
  await again.post("/api/admin/login", { email: electoral.email, password: electoral.password });
  assert.strictEqual((await again.post("/api/admin/totp", { code: first })).status, 401, "each recovery code works once");

  const other = new Client(base);
  await other.post("/api/admin/login", { email: electoral.email, password: electoral.password });
  assert.strictEqual((await other.post("/api/admin/totp", { code: second })).status, 200, "the next one still works");
});

test("sessions live in the database, are hashed, expire, and can be ended", async () => {
  const client = await signIn(base, electoral);
  const token = adminToken(client);
  const hash = sessions.hashToken(token);

  const row = d.get("SELECT tokenHash, kind, stage FROM sessions WHERE tokenHash = ?", hash);
  assert.ok(row, "the session is stored (so it survives a server restart)");
  assert.strictEqual(row.stage, "full");
  assert.strictEqual(d.get("SELECT COUNT(*) AS n FROM sessions WHERE tokenHash = ?", token).n, 0, "the raw token is never stored");

  // idle expiry
  d.run("UPDATE sessions SET idleExpiresAt = ? WHERE tokenHash = ?", Date.now() - 1000, hash);
  const idle = await client.get("/api/admin/dashboard");
  assert.strictEqual(idle.status, 401);
  assert.strictEqual(client.jar.size, 0, "the expired cookie is cleared");

  // absolute expiry cannot be extended by activity
  const second = await signIn(base, electoral);
  const secondHash = sessions.hashToken(adminToken(second));

  d.run("UPDATE sessions SET absoluteExpiresAt = ? WHERE tokenHash = ?", Date.now() - 1000, secondHash);
  assert.strictEqual((await second.get("/api/admin/dashboard")).status, 401);

  // logout invalidates the token itself, not just the browser's copy
  const third = await signIn(base, electoral);
  const cookie = third.cookieHeader();

  assert.strictEqual((await third.post("/api/admin/logout")).status, 200);
  assert.strictEqual((await new Client(base).get("/api/admin/dashboard", { cookie })).status, 401);

  // polling does not keep an idle session alive, but real activity does
  const fourth = await signIn(base, electoral);
  const fourthHash = sessions.hashToken(adminToken(fourth));

  d.run("UPDATE sessions SET lastActiveAt = 0, idleExpiresAt = ? WHERE tokenHash = ?", Date.now() + 120_000, fourthHash);
  await fourth.get("/api/admin/dashboard"); // passive
  assert.ok(d.get("SELECT idleExpiresAt FROM sessions WHERE tokenHash = ?", fourthHash).idleExpiresAt <= Date.now() + 121_000, "a passive refresh does not extend the session");

  await fourth.post("/api/admin/keepalive", {});
  assert.ok(d.get("SELECT idleExpiresAt FROM sessions WHERE tokenHash = ?", fourthHash).idleExpiresAt > Date.now() + 60_000 * 5, "a real action extends it");
});

test("changing the password signs out every other session; sign out everywhere ends them all", async () => {
  const a = await signIn(base, electoral);
  const b = await signIn(base, electoral);
  const newPassword = `${PASSWORD}-2`;

  const wrongCurrent = await a.post("/api/admin/password", { currentPassword: "not-my-password", newPassword });
  assert.strictEqual(wrongCurrent.status, 400);

  const changed = await a.post("/api/admin/password", { currentPassword: electoral.password, newPassword });
  assert.strictEqual(changed.status, 200, JSON.stringify(changed.json));

  assert.strictEqual((await a.get("/api/admin/dashboard")).status, 200, "this session continues");
  assert.strictEqual((await b.get("/api/admin/dashboard")).status, 401, "the other session is ended");

  assert.strictEqual((await new Client(base).post("/api/admin/login", { email: electoral.email, password: electoral.password })).status, 401, "the old password is dead");

  electoral.password = newPassword;

  const c = await signIn(base, electoral);
  const everywhere = await c.post("/api/admin/logout-all", {});
  assert.strictEqual(everywhere.status, 200);
  assert.strictEqual((await c.get("/api/admin/dashboard")).status, 401);
});

test("an account is locked after repeated wrong passwords, is not helped by the right one, and an officer can unlock it", async () => {
  // results officer finishes first sign-in so there is something to lock
  results = await firstSignIn(base, accounts.results_officer);

  // the previous test signed the electoral officer out everywhere, so start a fresh session
  const officer = await signIn(base, electoral);

  const attacker = new Client(base);

  for (let attempt = 0; attempt < config.ADMIN_MAX_FAILED; attempt += 1) {
    const response = await attacker.post("/api/admin/login", { email: results.email, password: `Guess-${attempt}-Wrong-Pw` });
    assert.strictEqual(response.status, 401);
  }

  const lockedRight = await attacker.post("/api/admin/login", { email: results.email, password: results.password });
  assert.strictEqual(lockedRight.status, 401, "locked: even the correct password is refused");
  assert.strictEqual(lockedRight.json.code, "login-failed", "and the answer does not say it is locked");

  const view = await officer.get("/api/admin/admins");
  const target = view.json.admins.find((admin) => admin.email === results.email);
  assert.strictEqual(target.locked, true);

  // sensitive: needs a fresh code
  expireStepUp(officer);
  const needsCode = await officer.post(`/api/admin/admins/${target.id}/unlock`, {});
  assert.strictEqual(needsCode.status, 403);
  assert.strictEqual(needsCode.json.code, "step-up-required");

  await stepUp(officer, electoral);
  assert.strictEqual((await officer.post(`/api/admin/admins/${target.id}/unlock`, {})).status, 200);

  const after = await signIn(base, results);
  assert.strictEqual((await after.get("/api/admin/dashboard")).status, 200);

  const history = await officer.get(`/api/admin/admins/${target.id}/history`);
  assert.ok(history.json.history.some((entry) => /fail|lock/i.test(entry.outcome)), "failures are in the sign-in history");
});

test("rate limits: per-account and per-address, with Retry-After", async () => {
  const email = "guesser@bouesti.ng";
  let tripped = null;

  for (let attempt = 0; attempt < config.RATE.adminLoginEmail.limit + 2; attempt += 1) {
    const response = await new Client(base).post("/api/admin/login", { email, password: `Wrong-${attempt}-Password!` });

    if (response.status === 429) {
      tripped = response;
      break;
    }
  }

  assert.ok(tripped, "repeated attempts at one account are throttled");
  assert.ok(Number(tripped.headers.get("retry-after")) > 0);

  // the per-address ceiling
  const original = config.RATE.adminLoginIp.limit;
  config.RATE.adminLoginIp.limit = 2;

  try {
    const results3 = [];

    for (let attempt = 0; attempt < 4; attempt += 1) {
      results3.push((await new Client(base).post("/api/admin/login", { email: `other${attempt}@bouesti.ng`, password: "Wrong-Password-1!" })).status);
    }

    assert.ok(results3.includes(429), `an address that keeps trying is throttled (${results3.join(",")})`);
  } finally {
    config.RATE.adminLoginIp.limit = original;
    d.run("DELETE FROM rate_limits WHERE bucket LIKE 'adminLoginIp:%'");
  }
});

test("role-based access: each role reaches only what its duties need", async () => {
  tech = await firstSignIn(base, accounts.technical_support);
  const resultsClient = await signIn(base, results);
  const electoralClient = await signIn(base, electoral);

  const clients = { electoral: electoralClient, results: resultsClient, tech: tech.client };

  const matrix = [
    ["GET", "/api/admin/dashboard", undefined, { electoral: 200, results: 200, tech: 200 }],
    ["GET", "/api/admin/election", undefined, { electoral: 200, results: 200, tech: 200 }],
    ["GET", "/api/admin/students", undefined, { electoral: 200, results: 403, tech: 403 }],
    ["GET", "/api/admin/statistics", undefined, { electoral: 200, results: 200, tech: 200 }],
    ["GET", "/api/admin/results", undefined, { electoral: 200, results: 200, tech: 403 }],
    ["GET", "/api/admin/admins", undefined, { electoral: 200, results: 403, tech: 403 }],
    ["GET", "/api/admin/audit", undefined, { electoral: 200, results: 200, tech: 200 }],
    ["GET", "/api/admin/ops/health", undefined, { electoral: 200, results: 200, tech: 200 }],
    ["GET", "/api/admin/ops/readiness", undefined, { electoral: 200, results: 200, tech: 200 }],
    ["GET", "/api/admin/ops/backups", undefined, { electoral: 200, results: 200, tech: 200 }],
    ["POST", "/api/admin/ops/backup", {}, { electoral: 403, results: 403, tech: 200 }],
    ["POST", "/api/admin/ops/drill", {}, { electoral: 403, results: 403, tech: 200 }],
    ["POST", "/api/admin/ops/test-mail", { to: "x@y.zz" }, { electoral: 403, results: 403 }],
    ["GET", "/api/admin/student-reports", undefined, { electoral: 200, results: 403, tech: 200 }],
    ["GET", "/api/admin/incidents", undefined, { electoral: 200, results: 200, tech: 200 }],
    ["POST", "/api/admin/announcements", { message: "Hello students" }, { electoral: 200, results: 403, tech: 403 }],
    ["PUT", "/api/admin/election", { electionName: "BOUESTI SUG Election 2026" }, { electoral: 200, results: 403, tech: 403 }],
    ["PUT", "/api/admin/settings", { schoolName: "Bamidele Olumilua University of Education, Science and Technology" }, { electoral: 200, results: 403, tech: 403 }],
    ["POST", "/api/admin/offices", { office: "Test", candidate: "Someone" }, { results: 403, tech: 403 }],
    ["POST", "/api/admin/results/prepare", { note: "" }, { electoral: 403, tech: 403 }],
    ["POST", "/api/admin/go-live", { phrase: "GO LIVE" }, { electoral: 409, results: 403, tech: 403 }]
  ];

  for (const [method, path, body, expected] of matrix) {
    for (const [who, status] of Object.entries(expected)) {
      const response = await clients[who].request(method, path, { body });

      assert.strictEqual(response.status, status, `${who} ${method} ${path}: expected ${status}, got ${response.status} ${JSON.stringify(response.json)}`);
    }
  }

  // refusals are recorded for the Electoral Officer to see
  const denials = d.all("SELECT message FROM audit_log WHERE category = 'security' AND message LIKE 'Permission denied%'");
  assert.ok(denials.length > 0, "permission-denied attempts appear in the audit log");
});

test("sensitive actions need a fresh 2FA code, which then unlocks them for a few minutes", async () => {
  const client = await signIn(base, electoral);

  // signing in counts as a confirmation
  const lines = ["300001, Ada Obi, ada.obi@bouesti.edu.ng"];
  assert.strictEqual((await client.post("/api/admin/students/import", { lines })).status, 200);

  expireStepUp(client);

  const blocked = await client.post("/api/admin/students/import", { lines: ["300002, Bayo Ade, bayo.ade@bouesti.edu.ng"] });
  assert.strictEqual(blocked.status, 403);
  assert.strictEqual(blocked.json.code, "step-up-required");
  assert.strictEqual(d.get("SELECT COUNT(*) AS n FROM students WHERE matric = '300002'").n, 0, "nothing happened");

  assert.strictEqual((await client.post("/api/admin/stepup", { code: "000000" })).status, 401);

  await stepUp(client, electoral);
  assert.strictEqual((await client.post("/api/admin/students/import", { lines: ["300002, Bayo Ade, bayo.ade@bouesti.edu.ng"] })).status, 200);

  // other things need no code
  expireStepUp(client);
  assert.strictEqual((await client.get("/api/admin/students")).status, 200);
});

test("administrators are managed with lifecycle controls: create, role, disable, reset password, reset 2FA", async () => {
  const boss = await signIn(base, electoral);
  await stepUp(boss, electoral);

  // create
  const created = await boss.post("/api/admin/admins", { email: "deputy@bouesti.ng", displayName: "Deputy Officer", role: "results_officer" });
  assert.strictEqual(created.status, 200, JSON.stringify(created.json));
  assert.ok(created.json.temporaryPassword.length >= 14);

  assert.strictEqual((await boss.post("/api/admin/admins", { email: "deputy@bouesti.ng", displayName: "Again", role: "results_officer" })).status, 400, "no duplicates");
  assert.strictEqual((await boss.post("/api/admin/admins", { email: "x@bouesti.ng", displayName: "X Y", role: "superuser" })).status, 400, "unknown roles are refused");

  const deputy = await firstSignIn(base, { email: "deputy@bouesti.ng", temporaryPassword: created.json.temporaryPassword });
  assert.strictEqual((await deputy.client.get("/api/admin/results")).status, 200);
  assert.strictEqual((await deputy.client.get("/api/admin/students")).status, 403);

  const list = (await boss.get("/api/admin/admins")).json;
  const deputyRow = list.admins.find((admin) => admin.email === "deputy@bouesti.ng");
  const bossRow = list.admins.find((admin) => admin.email === electoral.email);

  // change role: takes effect immediately and ends their sessions
  assert.strictEqual((await boss.post(`/api/admin/admins/${deputyRow.id}/role`, { role: "technical_support" })).status, 200);
  assert.strictEqual((await deputy.client.get("/api/admin/results")).status, 401, "old sessions end when the role changes");

  // you cannot demote or disable yourself (that could leave nobody in charge)
  assert.ok([400, 409].includes((await boss.post(`/api/admin/admins/${bossRow.id}/disable`, { disabled: true })).status));
  assert.ok([400, 409].includes((await boss.post(`/api/admin/admins/${bossRow.id}/role`, { role: "technical_support" })).status));

  // forgotten password: a one-time code, handed over in person
  const reset = await boss.post(`/api/admin/admins/${deputyRow.id}/reset-password`, {});
  assert.strictEqual(reset.status, 200);
  assert.ok(reset.json.code);

  const newPassword = "Another-Strong-Phrase-47!";
  const client = new Client(base);

  assert.strictEqual((await client.post("/api/admin/reset/redeem", { email: "deputy@bouesti.ng", code: "WRONG-CODE-XXXXX", newPassword })).status >= 400, true);
  assert.strictEqual((await client.post("/api/admin/reset/redeem", { email: "deputy@bouesti.ng", code: reset.json.code, newPassword })).status, 200);
  assert.strictEqual((await client.post("/api/admin/reset/redeem", { email: "deputy@bouesti.ng", code: reset.json.code, newPassword: `${newPassword}x` })).status >= 400, true, "a reset code works once");

  deputy.password = newPassword;
  const again = await signIn(base, deputy);
  assert.strictEqual((await again.get("/api/admin/ops/health")).status, 200);

  // lost phone: 2FA is cleared and must be set up again
  assert.strictEqual((await boss.post(`/api/admin/admins/${deputyRow.id}/reset-2fa`, {})).status, 200);
  assert.strictEqual((await again.get("/api/admin/ops/health")).status, 401);

  const relogin = new Client(base);
  const login = await relogin.post("/api/admin/login", { email: "deputy@bouesti.ng", password: newPassword });
  assert.strictEqual(login.json.next, "enroll");

  // disable
  assert.strictEqual((await boss.post(`/api/admin/admins/${deputyRow.id}/disable`, { disabled: true })).status, 200);
  assert.strictEqual((await new Client(base).post("/api/admin/login", { email: "deputy@bouesti.ng", password: newPassword })).status, 401);
  assert.strictEqual((await relogin.get("/api/admin/session")).json.signedIn, false, "an existing pending session dies too");

  // every one of those steps left a trace
  const trail = d.all("SELECT message FROM audit_log WHERE category = 'admin'").map((row) => row.message).join("\n");
  assert.match(trail, /deputy@bouesti\.ng/);
  assert.doesNotMatch(trail, new RegExp(created.json.temporaryPassword.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")), "passwords never reach the log");
  assert.doesNotMatch(trail, new RegExp(reset.json.code.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")), "reset codes never reach the log");
});

test("administrator changes need the browser header, responses are never cached, and bad JSON is a clean 400", async () => {
  const client = await signIn(base, electoral);

  // Reading is harmless (the cookie is SameSite=Strict and other sites cannot read the answer);
  // every request that CHANGES something must carry the header.
  const noHeader = await client.get("/api/admin/dashboard", { csrf: false });
  assert.strictEqual(noHeader.status, 200);

  const post = await client.post("/api/admin/announcements", { message: "Hello" }, { csrf: false });
  assert.strictEqual(post.status, 403);

  const ok = await client.get("/api/admin/dashboard");
  assert.match(ok.headers.get("cache-control"), /no-store/);

  const malformed = await fetch(`${base}/api/admin/announcements`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Requested-With": "bouesti-vote", Cookie: client.cookieHeader() },
    body: "{oops"
  });
  assert.strictEqual(malformed.status, 400);
});
