"use strict";

const { freshEnv } = require("./helpers");
const dir = freshEnv({ ADMIN_MAX_FAILED: 5 });

const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");

const d = require("../db");
const admins = require("../admins");
const sessions = require("../sessions");
const passwords = require("../passwords");
const totp = require("../totp");
const config = require("../config");

let seeded;

test("first start creates three role accounts with private one-time passwords", async () => {
  seeded = await admins.seedInitialAdmins();

  assert.strictEqual(seeded.length, 3);
  assert.deepStrictEqual(seeded.map((a) => a.role).sort(), ["electoral_officer", "results_officer", "technical_support"]);
  assert.strictEqual(await admins.seedInitialAdmins(), null, "seeding twice must do nothing");

  assert.strictEqual(fs.statSync(config.CREDENTIALS_FILE).mode & 0o777, 0o600);

  const row = admins.getByEmail("electoral@bouesti.ng");
  assert.ok(row.passwordHash.startsWith("scrypt$"), "stored as a salted scrypt hash");
  assert.ok(!row.passwordHash.includes(seeded[0].temporaryPassword), "plaintext is never stored");
  assert.ok(row.mustChangePassword);

  const view = admins.publicView(row);
  assert.ok(!("passwordHash" in view) && !("totpSecretEnc" in view), "browser view hides secrets");
});

test("same salt never repeats and verification is exact", async () => {
  const a = await passwords.hashPassword("Correct-Horse-Battery-9");
  const b = await passwords.hashPassword("Correct-Horse-Battery-9");

  assert.notStrictEqual(a, b);
  assert.ok(await passwords.verifyPassword("Correct-Horse-Battery-9", a));
  assert.ok(!(await passwords.verifyPassword("Correct-Horse-Battery-8", a)));
  assert.ok(!(await passwords.verifyPassword("", a)));
  assert.ok(!(await passwords.verifyPassword("anything", "not-a-hash")));
});

test("password policy rejects weak choices", () => {
  const weak = ["short1A!", "passwordpassword1", "Electionofficer2026", "aaaaaaaaaaaaaaaa", "alllowercaseletters"];
  weak.forEach((pw) => assert.ok(passwords.passwordProblems(pw, { email: "x@y.ng" }).length > 0, pw));

  assert.ok(passwords.passwordProblems("tulip-Harbor-47-Quartz", { email: "x@y.ng" }).length === 0);
  assert.ok(passwords.passwordProblems("my_name_is_nobody", { email: "nobody@y.ng" }).length > 0);
});

test("wrong password, unknown e-mail and disabled look identical; lockout after 5 failures", async () => {
  const email = "electoral@bouesti.ng";
  const real = seeded[0].temporaryPassword;

  const unknown = await admins.checkPassword("nobody@bouesti.ng", "whatever", "10.0.0.1");
  const wrong = await admins.checkPassword(email, "wrong-password", "10.0.0.1");
  assert.deepStrictEqual(unknown, { ok: false });
  assert.deepStrictEqual(wrong, { ok: false });

  for (let i = 0; i < 3; i += 1) await admins.checkPassword(email, "wrong-again", "10.0.0.1");

  // fifth failure trips the lock
  await admins.checkPassword(email, "wrong-final", "10.0.0.1");
  assert.ok(admins.getByEmail(email).lockedUntil > Date.now());

  // even the CORRECT password is refused while locked
  const locked = await admins.checkPassword(email, real, "10.0.0.1");
  assert.strictEqual(locked.ok, false);
  assert.strictEqual(locked.locked, true);

  const lockAudit = d.get("SELECT COUNT(*) AS n FROM audit_log WHERE message LIKE ?", "%locked for%").n;
  assert.strictEqual(lockAudit, 1);

  admins.unlock(admins.getByEmail(email).id, "admin:test");
  assert.strictEqual((await admins.checkPassword(email, real, "10.0.0.1")).ok, true);
});

test("two-factor: enrolment, replay protection, recovery codes", async () => {
  const row = admins.getByEmail("electoral@bouesti.ng");
  const setup = admins.beginTotpSetup(row);

  assert.ok(setup.uri.startsWith("otpauth://totp/"));
  assert.strictEqual((await admins.confirmTotpSetup(row, setup.secret, "000000")).ok, false);

  const confirmed = admins.confirmTotpSetup(row, setup.secret, totp.generate(setup.secret));
  assert.ok(confirmed.ok);
  assert.strictEqual(confirmed.recoveryCodes.length, 8);

  const stored = admins.getByEmail(row.email);
  assert.ok(stored.totpEnabled);
  assert.ok(!stored.totpSecretEnc.includes(setup.secret), "2FA secret is encrypted at rest");

  // The enrolment code's step is already used: it must not log anyone in.
  assert.strictEqual(admins.checkSecondFactor(row, totp.generate(setup.secret), "10.0.0.2").ok, false);

  // The NEXT 30-second code is accepted once...
  const next = totp.generate(setup.secret, Date.now() + 30_000);
  assert.strictEqual(admins.checkSecondFactor(row, next, "10.0.0.2").ok, true);
  // ...and never again.
  assert.strictEqual(admins.checkSecondFactor(row, next, "10.0.0.2").ok, false);

  // Recovery codes: single use.
  const recovery = confirmed.recoveryCodes[0];
  assert.strictEqual(admins.checkSecondFactor(row, recovery, "10.0.0.2").ok, true);
  assert.strictEqual(admins.checkSecondFactor(row, recovery, "10.0.0.2").ok, false);
  assert.strictEqual(admins.recoveryCodesLeft(row.id), 7);

  admins.unlock(row.id, "admin:test");
});

test("password reset codes: single use, expiring, policy-checked, revoke sessions", async () => {
  const target = admins.getByEmail("results@bouesti.ng");
  const live = sessions.create({ kind: "admin", subject: target.id, stage: "full" });

  const issued = admins.issueResetCode(target.id, "admin:electoral@bouesti.ng");
  assert.ok(issued.ok && /^[A-Z2-9]{5}-[A-Z2-9]{5}-[A-Z2-9]{5}$/.test(issued.code));

  const stored = d.get("SELECT codeHash FROM password_resets WHERE adminId = ?", target.id);
  assert.ok(!stored.codeHash.includes(issued.code.replace(/-/g, "")), "reset code stored hashed");

  assert.strictEqual((await admins.redeemResetCode(target.email, "AAAAA-BBBBB-CCCCC", "tulip-Harbor-47-Quartz", "1.1.1.1")).ok, false);
  assert.strictEqual((await admins.redeemResetCode(target.email, issued.code, "weak", "1.1.1.1")).ok, false);

  const done = await admins.redeemResetCode(target.email, issued.code, "tulip-Harbor-47-Quartz", "1.1.1.1");
  assert.ok(done.ok);

  assert.strictEqual(sessions.lookup(live.token, "admin"), null, "old sessions are ended");
  assert.strictEqual((await admins.checkPassword(target.email, seeded[1].temporaryPassword, "1.1.1.1")).ok, false);
  assert.strictEqual((await admins.checkPassword(target.email, "tulip-Harbor-47-Quartz", "1.1.1.1")).ok, true);
  assert.strictEqual((await admins.redeemResetCode(target.email, issued.code, "another-Strong-Pass-81", "1.1.1.1")).ok, false, "code is single use");

  // expiry
  const second = admins.issueResetCode(target.id, "cli");
  d.run("UPDATE password_resets SET expiresAt = ? WHERE status = 'pending'", Date.now() - 1000);
  assert.strictEqual((await admins.redeemResetCode(target.email, second.code, "another-Strong-Pass-81", "1.1.1.1")).ok, false);

  assert.ok(admins.listResets().some((r) => r.status === "used"));
});

test("account management guards", async () => {
  const eo = admins.getByEmail("electoral@bouesti.ng");
  const ro = admins.getByEmail("results@bouesti.ng");

  assert.strictEqual(admins.setRole(eo.id, "results_officer", "admin:x", eo.id).ok, false, "not your own role");
  assert.strictEqual(admins.setDisabled(eo.id, true, "admin:x", eo.id).ok, false, "not yourself");
  assert.strictEqual(admins.setDisabled(eo.id, true, "admin:x", ro.id).ok, false, "last Electoral Officer stays");

  const created = await admins.createAdmin(
    { email: "second.eo@bouesti.ng", displayName: "Second EO", role: "electoral_officer" },
    "admin:electoral@bouesti.ng"
  );
  assert.ok(created.ok && created.temporaryPassword);
  assert.strictEqual((await admins.createAdmin({ email: "second.eo@bouesti.ng", displayName: "Dup", role: "results_officer" }, "x")).ok, false);
  assert.strictEqual((await admins.createAdmin({ email: "bad", displayName: "Bad", role: "results_officer" }, "x")).ok, false);
  assert.strictEqual((await admins.createAdmin({ email: "r@b.ng", displayName: "R", role: "superuser" }, "x")).ok, false);

  assert.strictEqual(admins.setDisabled(eo.id, true, "admin:second", created.admin.id).ok, true);

  const attempt = await admins.checkPassword(eo.email, seeded[0].temporaryPassword, "9.9.9.9");
  assert.deepStrictEqual(attempt, { ok: false }, "disabled account cannot sign in");

  assert.strictEqual(admins.resetTwoFactor(eo.id, "admin:second").ok, true);
  assert.strictEqual(admins.getByEmail(eo.email).totpEnabled, 0);
});

test("everything above was recorded in the tamper-evident audit log", () => {
  const audit = require("../audit");
  const result = audit.verify();
  assert.ok(result.ok, JSON.stringify(result));
  assert.ok(result.chain.count > 8);
});
