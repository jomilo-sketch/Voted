/*
  BOUESTI Vote — administrator accounts.

  Stored in the database (admins table) with scrypt-salted password
  hashes. Provides: three roles, lockout after repeated failures, TOTP
  two-factor authentication (with replay protection and recovery codes),
  password-reset records, forced first-use password change, and a login
  history. Routes (routes-admin.js) are thin wrappers around this file.

  Failure messages are deliberately identical for "no such account",
  "wrong password", "disabled" and "locked", so the sign-in form cannot
  be used to discover which e-mail addresses are administrators.
*/

"use strict";

const fs = require("fs");
const d = require("./db");
const config = require("./config");
const keys = require("./keys");
const totp = require("./totp");
const audit = require("./audit");
const sessions = require("./sessions");
const passwords = require("./passwords");
const { permissionsFor, roleLabel, isRole } = require("./permissions");

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const RECOVERY_CODE_COUNT = 8;
const ISSUER = "BOUESTI Vote";

function normaliseEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function normaliseCode(value) {
  return String(value || "").toUpperCase().replace(/[\s-]/g, "");
}

function actorOf(row) {
  return audit.adminActor(row);
}

/* ---------- reading ---------- */

function getById(id) {
  return d.get("SELECT * FROM admins WHERE id = ?", Number(id)) || null;
}

function getByEmail(email) {
  return d.get("SELECT * FROM admins WHERE email = ?", normaliseEmail(email)) || null;
}

/* Everything the browser may see. Never the hash, never the 2FA secret. */
function publicView(row) {
  return {
    id: row.id,
    email: row.email,
    displayName: row.displayName,
    role: row.role,
    roleLabel: roleLabel(row.role),
    permissions: permissionsFor(row.role),
    mustChangePassword: Boolean(row.mustChangePassword),
    totpEnabled: Boolean(row.totpEnabled),
    disabled: Boolean(row.disabled),
    locked: row.lockedUntil > Date.now(),
    lockedUntil: row.lockedUntil > Date.now() ? row.lockedUntil : null,
    lastLoginAt: row.lastLoginAt,
    passwordChangedAt: row.passwordChangedAt,
    createdAt: row.createdAt,
    createdBy: row.createdBy
  };
}

function list() {
  return d.all("SELECT * FROM admins ORDER BY id").map((row) => ({
    ...publicView(row),
    activeSessions: sessions.listActiveFor("admin", row.id).filter((s) => s.stage === "full").length
  }));
}

function recordHistory(adminId, email, ip, outcome, detail = "") {
  d.run(
    "INSERT INTO admin_login_history (adminId, email, at, ip, outcome, detail) VALUES (?, ?, ?, ?, ?, ?)",
    adminId, String(email).slice(0, 160), d.nowIso(), ip || null, outcome, String(detail).slice(0, 200)
  );
}

function loginHistory(adminId, limit = 25) {
  return d.all(
    "SELECT at, ip, outcome, detail FROM admin_login_history WHERE adminId = ? ORDER BY id DESC LIMIT ?",
    Number(adminId), limit
  );
}

function recentFailureCount(sinceMs = 3600_000) {
  const since = new Date(Date.now() - sinceMs).toISOString();
  return d.get(
    `SELECT COUNT(*) AS n FROM admin_login_history
     WHERE at > ? AND outcome IN ('password-failed', '2fa-failed', 'unknown-account', 'locked-out', 'account-locked')`,
    since
  ).n;
}

/* ---------- lockout ---------- */

function registerFailure(row, ip, outcome) {
  const now = Date.now();
  const previous = row.lockedUntil && row.lockedUntil <= now ? 0 : row.failedAttempts;
  const attempts = previous + 1;

  recordHistory(row.id, row.email, ip, outcome);

  if (attempts >= config.ADMIN_MAX_FAILED) {
    d.run(
      "UPDATE admins SET failedAttempts = 0, lockedUntil = ? WHERE id = ?",
      now + config.ADMIN_LOCK_SEC * 1000, row.id
    );

    recordHistory(row.id, row.email, ip, "account-locked", `${attempts} failed attempts`);
    audit.append(
      "system", "security",
      `Account ${row.email} locked for ${Math.round(config.ADMIN_LOCK_SEC / 60)} minutes after ${attempts} failed sign-in attempts`
    );
    return;
  }

  d.run("UPDATE admins SET failedAttempts = ?, lockedUntil = 0 WHERE id = ?", attempts, row.id);
}

/* ---------- step 1: password ---------- */

async function checkPassword(emailInput, password, ip) {
  const email = normaliseEmail(emailInput);
  const row = email ? getByEmail(email) : null;
  const now = Date.now();

  if (!row) {
    await passwords.verifyPassword(String(password || ""), await passwords.dummyHash());
    recordHistory(null, email || "(blank)", ip, "unknown-account");
    return { ok: false };
  }

  if (row.disabled) {
    await passwords.verifyPassword(String(password || ""), await passwords.dummyHash());
    recordHistory(row.id, row.email, ip, "disabled-account");
    audit.append("system", "security", `Sign-in attempt on disabled account ${row.email}`);
    return { ok: false };
  }

  if (row.lockedUntil > now) {
    await passwords.verifyPassword(String(password || ""), await passwords.dummyHash());
    recordHistory(row.id, row.email, ip, "locked-out");
    return { ok: false, locked: true };
  }

  const good = await passwords.verifyPassword(String(password || ""), row.passwordHash);

  if (!good) {
    registerFailure(row, ip, "password-failed");
    return { ok: false };
  }

  if (passwords.needsRehash(row.passwordHash)) {
    d.run("UPDATE admins SET passwordHash = ? WHERE id = ?", await passwords.hashPassword(password), row.id);
  }

  return { ok: true, admin: row };
}

/* ---------- step 2: 2FA code or recovery code ---------- */

function useRecoveryCode(row, input) {
  const hash = keys.sha256Hex(normaliseCode(input));
  const match = d.get(
    "SELECT id FROM admin_recovery_codes WHERE adminId = ? AND codeHash = ? AND usedAt IS NULL",
    row.id, hash
  );

  if (!match) return false;

  d.run("UPDATE admin_recovery_codes SET usedAt = ? WHERE id = ?", d.nowIso(), match.id);

  const left = d.get(
    "SELECT COUNT(*) AS n FROM admin_recovery_codes WHERE adminId = ? AND usedAt IS NULL",
    row.id
  ).n;

  audit.append(actorOf(row), "auth", `Recovery code used to sign in (${left} left)`);
  return true;
}

function checkSecondFactor(row, code, ip) {
  const now = Date.now();
  const fresh = getById(row.id);

  if (!fresh || fresh.disabled) return { ok: false };
  if (fresh.lockedUntil > now) return { ok: false, locked: true };
  if (!fresh.totpEnabled || !fresh.totpSecretEnc) return { ok: false, notEnrolled: true };

  const input = String(code || "").trim();
  const digits = input.replace(/\s/g, "");

  if (/^\d{6}$/.test(digits)) {
    const secret = keys.decryptString(fresh.totpSecretEnc, "totp-enc");
    const step = totp.verify(secret, digits);

    // The step must be newer than the last accepted one: a code that was
    // already used (or shoulder-surfed) cannot be replayed.
    if (step !== null && step > fresh.totpLastStep) {
      d.run("UPDATE admins SET totpLastStep = ? WHERE id = ?", step, fresh.id);
      return { ok: true, admin: fresh };
    }
  } else if (normaliseCode(input).length === 10 && useRecoveryCode(fresh, input)) {
    return { ok: true, admin: fresh, usedRecovery: true };
  }

  registerFailure(fresh, ip, "2fa-failed");
  return { ok: false };
}

function completeLogin(row, ip) {
  d.run(
    "UPDATE admins SET failedAttempts = 0, lockedUntil = 0, lastLoginAt = ? WHERE id = ?",
    d.nowIso(), row.id
  );

  recordHistory(row.id, row.email, ip, "login-success");
  audit.append(actorOf(row), "auth", `${roleLabel(row.role)} signed in`);
}

/* ---------- 2FA enrolment ---------- */

function beginTotpSetup(row) {
  const secret = totp.generateSecret();

  return {
    secret,
    formattedSecret: totp.formatSecret(secret),
    uri: totp.otpauthUri({ secret, account: row.email, issuer: ISSUER })
  };
}

function confirmTotpSetup(row, secret, code) {
  const step = totp.verify(secret, code);
  if (step === null) return { ok: false };

  const recoveryCodes = Array.from({ length: RECOVERY_CODE_COUNT }, () => passwords.generateCode(2, 5));

  d.tx(() => {
    d.run(
      "UPDATE admins SET totpSecretEnc = ?, totpEnabled = 1, totpLastStep = ? WHERE id = ?",
      keys.encryptString(secret, "totp-enc"), step, row.id
    );

    d.run("DELETE FROM admin_recovery_codes WHERE adminId = ?", row.id);

    recoveryCodes.forEach((recovery) => {
      d.run(
        "INSERT INTO admin_recovery_codes (adminId, codeHash) VALUES (?, ?)",
        row.id, keys.sha256Hex(normaliseCode(recovery))
      );
    });

    audit.append(actorOf(row), "auth", "Two-factor authentication enrolled");
  });

  return { ok: true, recoveryCodes };
}

/* Replace the one-time recovery codes (the old ones stop working). The new
   codes are shown to their owner once and stored only as hashes. */
function regenerateRecoveryCodes(row) {
  const recoveryCodes = Array.from({ length: RECOVERY_CODE_COUNT }, () => passwords.generateCode(2, 5));

  d.tx(() => {
    d.run("DELETE FROM admin_recovery_codes WHERE adminId = ?", row.id);

    recoveryCodes.forEach((recovery) => {
      d.run(
        "INSERT INTO admin_recovery_codes (adminId, codeHash) VALUES (?, ?)",
        row.id, keys.sha256Hex(normaliseCode(recovery))
      );
    });

    audit.append(actorOf(row), "auth", "Recovery codes regenerated");
  });

  return recoveryCodes;
}

function recoveryCodesLeft(adminId) {
  return d.get(
    "SELECT COUNT(*) AS n FROM admin_recovery_codes WHERE adminId = ? AND usedAt IS NULL",
    adminId
  ).n;
}

/* ---------- passwords ---------- */

function removeCredentialsFileIfDone() {
  const pending = d.get("SELECT COUNT(*) AS n FROM admins WHERE mustChangePassword = 1").n;
  if (pending > 0 || !fs.existsSync(config.CREDENTIALS_FILE)) return;

  try {
    const size = fs.statSync(config.CREDENTIALS_FILE).size;
    fs.writeFileSync(config.CREDENTIALS_FILE, Buffer.alloc(size, 0));
    fs.unlinkSync(config.CREDENTIALS_FILE);
  } catch (error) {
    /* best effort */
  }
}

async function setPassword(row, newPassword, { by, reason, keepSession = null }) {
  const hash = await passwords.hashPassword(newPassword);

  d.tx(() => {
    d.run(
      `UPDATE admins SET passwordHash = ?, mustChangePassword = 0, passwordChangedAt = ?,
                         failedAttempts = 0, lockedUntil = 0 WHERE id = ?`,
      hash, d.nowIso(), row.id
    );

    sessions.revokeAllFor("admin", row.id, "password-changed", keepSession);
    audit.append(by, "admin", `Password ${reason} for ${row.email}`);
  });

  removeCredentialsFileIfDone();
}

/* A signed-in (or first-use) administrator choosing their own password. */
async function changeOwnPassword(row, currentPassword, newPassword, keepSession = null, { requireCurrent = true } = {}) {
  if (requireCurrent && !(await passwords.verifyPassword(String(currentPassword || ""), row.passwordHash))) {
    return { ok: false, problems: ["The current password is not correct."] };
  }

  const problems = passwords.passwordProblems(newPassword, { email: row.email, displayName: row.displayName });

  if (await passwords.verifyPassword(String(newPassword || ""), row.passwordHash)) {
    problems.push("Choose a password different from the current one.");
  }

  if (problems.length) return { ok: false, problems };

  await setPassword(row, newPassword, { by: actorOf(row), reason: "changed by its owner", keepSession });
  return { ok: true };
}

/* ---------- password-reset records ---------- */

function expireStaleResets() {
  return d.run(
    "UPDATE password_resets SET status = 'expired' WHERE status = 'pending' AND expiresAt < ?",
    Date.now()
  ).changes;
}

/* Issued by an administrator with admins.manage (or by the server CLI).
   The code is shown once, to the issuer, to hand over in person. */
function issueResetCode(targetId, issuedByLabel) {
  const target = getById(targetId);
  if (!target) return { ok: false, error: "Administrator not found." };

  const code = passwords.generateCode(3, 5);
  const now = Date.now();

  d.tx(() => {
    d.run(
      "UPDATE password_resets SET status = 'cancelled' WHERE adminId = ? AND status = 'pending'",
      target.id
    );

    d.run(
      `INSERT INTO password_resets (adminId, codeHash, issuedBy, issuedAt, expiresAt, status)
       VALUES (?, ?, ?, ?, ?, 'pending')`,
      target.id, keys.sha256Hex(normaliseCode(code)), issuedByLabel, now, now + config.RESET_CODE_TTL_SEC * 1000
    );

    audit.append(issuedByLabel, "admin", `Password-reset code issued for ${target.email} (valid ${Math.round(config.RESET_CODE_TTL_SEC / 60)} min)`);
  });

  return { ok: true, code, expiresAt: now + config.RESET_CODE_TTL_SEC * 1000, target: publicView(target) };
}

async function redeemResetCode(emailInput, code, newPassword, ip) {
  const generic = { ok: false, problems: ["That reset code is not valid or has expired."] };
  const row = getByEmail(emailInput);

  expireStaleResets();

  if (!row || row.disabled) {
    await passwords.verifyPassword("x", await passwords.dummyHash());
    return generic;
  }

  const record = d.get(
    `SELECT * FROM password_resets
     WHERE adminId = ? AND status = 'pending' AND codeHash = ? AND expiresAt > ?`,
    row.id, keys.sha256Hex(normaliseCode(code)), Date.now()
  );

  if (!record) {
    recordHistory(row.id, row.email, ip, "reset-failed");
    return generic;
  }

  const problems = passwords.passwordProblems(newPassword, { email: row.email, displayName: row.displayName });
  if (problems.length) return { ok: false, problems };

  await setPassword(row, newPassword, { by: actorOf(row), reason: "reset with a one-time code" });

  d.run("UPDATE password_resets SET status = 'used', usedAt = ? WHERE id = ?", Date.now(), record.id);
  recordHistory(row.id, row.email, ip, "password-reset");

  return { ok: true };
}

function listResets(limit = 30) {
  expireStaleResets();

  return d.all(
    `SELECT r.id, a.email AS adminEmail, r.issuedBy, r.issuedAt, r.expiresAt, r.usedAt, r.status
     FROM password_resets r JOIN admins a ON a.id = r.adminId
     ORDER BY r.id DESC LIMIT ?`,
    limit
  );
}

/* ---------- account management (Electoral Officer) ---------- */

function activeOfficerCount(excludeId = 0) {
  return d.get(
    "SELECT COUNT(*) AS n FROM admins WHERE role = 'electoral_officer' AND disabled = 0 AND id != ?",
    excludeId
  ).n;
}

async function createAdmin({ email, displayName, role }, by) {
  const cleanEmail = normaliseEmail(email);
  const name = String(displayName || "").trim().slice(0, 80);

  if (!EMAIL_PATTERN.test(cleanEmail)) return { ok: false, error: "Enter a valid e-mail address." };
  if (!name) return { ok: false, error: "Enter the administrator's name." };
  if (!isRole(role)) return { ok: false, error: "Choose a valid role." };
  if (getByEmail(cleanEmail)) return { ok: false, error: "An administrator with that e-mail already exists." };

  const temporaryPassword = passwords.generateTemporaryPassword();
  const hash = await passwords.hashPassword(temporaryPassword);

  const id = d.tx(() => {
    const result = d.run(
      `INSERT INTO admins (email, displayName, role, passwordHash, mustChangePassword, createdAt, createdBy)
       VALUES (?, ?, ?, ?, 1, ?, ?)`,
      cleanEmail, name, role, hash, d.nowIso(), by
    );

    audit.append(by, "admin", `Created ${roleLabel(role)} account ${cleanEmail}`);
    return Number(result.lastInsertRowid);
  });

  return { ok: true, admin: publicView(getById(id)), temporaryPassword };
}

function setRole(targetId, role, by, byId) {
  const target = getById(targetId);
  if (!target) return { ok: false, error: "Administrator not found." };
  if (!isRole(role)) return { ok: false, error: "Choose a valid role." };
  if (target.id === byId) return { ok: false, error: "You cannot change your own role." };

  if (target.role === "electoral_officer" && role !== "electoral_officer" && activeOfficerCount(target.id) < 1) {
    return { ok: false, error: "At least one active Electoral Officer must remain." };
  }

  d.tx(() => {
    d.run("UPDATE admins SET role = ? WHERE id = ?", role, target.id);
    sessions.revokeAllFor("admin", target.id, "role-changed");
    audit.append(by, "admin", `Changed role of ${target.email} from ${roleLabel(target.role)} to ${roleLabel(role)}`);
  });

  return { ok: true };
}

function setDisabled(targetId, disabled, by, byId) {
  const target = getById(targetId);
  if (!target) return { ok: false, error: "Administrator not found." };
  if (target.id === byId) return { ok: false, error: "You cannot disable your own account." };

  if (disabled && target.role === "electoral_officer" && activeOfficerCount(target.id) < 1) {
    return { ok: false, error: "At least one active Electoral Officer must remain." };
  }

  d.tx(() => {
    d.run("UPDATE admins SET disabled = ? WHERE id = ?", disabled ? 1 : 0, target.id);
    if (disabled) sessions.revokeAllFor("admin", target.id, "account-disabled");
    audit.append(by, "admin", `${disabled ? "Disabled" : "Re-enabled"} account ${target.email}`);
  });

  return { ok: true };
}

function unlock(targetId, by) {
  const target = getById(targetId);
  if (!target) return { ok: false, error: "Administrator not found." };

  d.run("UPDATE admins SET failedAttempts = 0, lockedUntil = 0 WHERE id = ?", target.id);
  audit.append(by, "admin", `Unlocked account ${target.email}`);
  return { ok: true };
}

/* Lost authenticator phone: wipe 2FA so the administrator must enrol again
   (they still need their password, so this is not a way around 2FA). */
function resetTwoFactor(targetId, by) {
  const target = getById(targetId);
  if (!target) return { ok: false, error: "Administrator not found." };

  d.tx(() => {
    d.run("UPDATE admins SET totpSecretEnc = NULL, totpEnabled = 0, totpLastStep = 0 WHERE id = ?", target.id);
    d.run("DELETE FROM admin_recovery_codes WHERE adminId = ?", target.id);
    sessions.revokeAllFor("admin", target.id, "2fa-reset");
    audit.append(by, "admin", `Two-factor authentication reset for ${target.email}; re-enrolment required`);
  });

  return { ok: true };
}

/* ---------- first start ---------- */

const DEFAULT_ACCOUNTS = [
  { email: "electoral@bouesti.ng", displayName: "Electoral Officer", role: "electoral_officer" },
  { email: "results@bouesti.ng", displayName: "Results Officer", role: "results_officer" },
  { email: "tech@bouesti.ng", displayName: "Technical Support Officer", role: "technical_support" }
];

/* Creates the three starter accounts the first time the server runs. Each
   gets a random one-time password, written ONCE to a private file and the
   console; each must change it, and enrol 2FA, at first sign-in. */
async function seedInitialAdmins() {
  if (d.get("SELECT COUNT(*) AS n FROM admins").n > 0) return null;

  const created = [];

  for (const account of DEFAULT_ACCOUNTS) {
    const temporaryPassword = passwords.generateTemporaryPassword();
    const hash = await passwords.hashPassword(temporaryPassword);

    d.run(
      `INSERT INTO admins (email, displayName, role, passwordHash, mustChangePassword, createdAt, createdBy)
       VALUES (?, ?, ?, ?, 1, ?, 'system')`,
      account.email, account.displayName, account.role, hash, d.nowIso()
    );

    created.push({ ...account, temporaryPassword });
  }

  const lines = [
    "BOUESTI Vote — initial administrator passwords",
    `Created: ${d.nowIso()}`,
    "",
    "Each password works ONCE: at first sign-in you must choose a new password",
    "and enrol two-factor authentication. This file deletes itself when all three",
    "accounts have done so. Do not email or photograph it.",
    "",
    ...created.map((a) => `${a.role.padEnd(18)} ${a.email.padEnd(24)} ${a.temporaryPassword}`),
    ""
  ];

  fs.writeFileSync(config.CREDENTIALS_FILE, lines.join("\n"), { mode: 0o600 });

  audit.append("system", "admin", "Created the three starter administrator accounts (temporary passwords issued)");
  return created;
}

module.exports = {
  EMAIL_PATTERN,
  normaliseEmail,
  getById,
  getByEmail,
  publicView,
  list,
  loginHistory,
  recentFailureCount,
  recordHistory,
  checkPassword,
  checkSecondFactor,
  completeLogin,
  beginTotpSetup,
  confirmTotpSetup,
  recoveryCodesLeft,
  regenerateRecoveryCodes,
  changeOwnPassword,
  issueResetCode,
  redeemResetCode,
  listResets,
  expireStaleResets,
  createAdmin,
  setRole,
  setDisabled,
  unlock,
  resetTwoFactor,
  seedInitialAdmins
};
