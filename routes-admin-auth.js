/*
  BOUESTI Vote — administrator sign-in, account security and account
  management. Mounted at /api/admin (the session is loaded by the parent).

  Sign-in is a short staircase; each step is a different session "stage":

      password OK ──► stage "setup-password"  (first use: choose a password)
                  ──► stage "setup-totp"      (first use: scan the 2FA secret)
                  ──► stage "totp"            (every later sign-in: 6-digit code)
                          │
                          ▼
                     stage "full"  — the dashboard

  Pending stages last five minutes. A fresh token is issued at every step.
*/

"use strict";

const express = require("express");
const config = require("./config");
const keys = require("./keys");
const audit = require("./audit");
const admins = require("./admins");
const election = require("./election");
const sessions = require("./sessions");
const ratelimit = require("./ratelimit");
const { ROLES, can } = require("./permissions");
const { requireAdmin, stepUpSecondsLeft } = require("./middleware");
const { sendFailure, clientError, idParam, text, bool } = require("./http");

const router = express.Router();

const LOGIN_FAILED =
  "That e-mail or password was not accepted. After several wrong attempts an account is locked for " +
  `${Math.round(config.ADMIN_LOCK_SEC / 60)} minutes.`;

const NEXT_BY_STAGE = {
  totp: "totp",
  "setup-password": "change-password",
  "setup-totp": "enroll"
};

function pendingLife() {
  return { idleSec: config.ADMIN_PENDING_SEC, absoluteSec: config.ADMIN_PENDING_SEC };
}

function tooMany(res, limit) {
  res.set("Retry-After", String(limit.retryAfterSec));
  return res.status(429).json({
    error: `Too many attempts. Please wait ${ratelimit.waitText(limit.retryAfterSec)} and try again.`,
    code: "rate-limited",
    retryAfterSec: limit.retryAfterSec
  });
}

function secondsLeft(ms) {
  return Math.max(0, Math.floor(ms / 1000));
}

/* What the sign-in page and the dashboard need to know about the session. */
function describeSession(req) {
  if (!req.adminSession) return { signedIn: false };

  const session = req.adminSession;
  const now = Date.now();

  const base = {
    signedIn: true,
    stage: session.stage,
    email: req.admin.email,
    expiresInSec: secondsLeft(Math.min(session.idleExpiresAt, session.absoluteExpiresAt) - now)
  };

  if (session.stage !== "full") {
    return { ...base, next: NEXT_BY_STAGE[session.stage] || "login", displayName: req.admin.displayName };
  }

  return {
    ...base,
    next: "dashboard",
    admin: admins.publicView(req.admin),
    session: {
      idleExpiresInSec: secondsLeft(session.idleExpiresAt - now),
      absoluteExpiresInSec: secondsLeft(session.absoluteExpiresAt - now),
      stepUpValidForSec: stepUpSecondsLeft(session),
      idleMinutes: Math.round(config.ADMIN_IDLE_SEC / 60)
    }
  };
}

/* Step 2 of 2: the last hurdle passed — swap the pending token for a full one. */
function finishSignIn(req, res, row, extra = {}) {
  const ip = ratelimit.clientIp(req);

  admins.completeLogin(row, ip);

  const upgraded = sessions.rotate(req.adminSession, {
    stage: "full",
    data: { stepUpAt: Date.now() }, // the code just entered also counts as a step-up
    idleSec: config.ADMIN_IDLE_SEC,
    absoluteSec: config.ADMIN_ABSOLUTE_SEC,
    ip,
    userAgent: req.get("user-agent")
  });

  sessions.setSessionCookie(res, config.ADMIN_COOKIE, upgraded.token, upgraded.session);

  res.json({ ok: true, next: "dashboard", ...extra });
}

/* ------------------------------------------------------------------ */
/* Sign-in                                                              */
/* ------------------------------------------------------------------ */

router.get("/session", (req, res) => {
  res.json(describeSession(req));
});

router.post("/login", ratelimit.byIp("adminLoginIp"), async (req, res) => {
  const ip = ratelimit.clientIp(req);
  const email = admins.normaliseEmail(text(req.body.email, 200)).slice(0, 160);
  const password = text(req.body.password, 300);

  const byEmail = ratelimit.take("adminLoginEmail", email || "(blank)", { auditLabel: email || "(blank)" });
  if (!byEmail.allowed) return tooMany(res, byEmail);

  const result = await admins.checkPassword(email, password, ip);

  if (!result.ok) {
    return res.status(401).json({ error: LOGIN_FAILED, code: "login-failed" });
  }

  const row = result.admin;
  const stage = row.mustChangePassword ? "setup-password" : row.totpEnabled ? "totp" : "setup-totp";

  if (req.adminSession) sessions.revoke(req.adminSession.tokenHash, "replaced");

  const created = sessions.create({
    kind: "admin",
    subject: row.id,
    stage,
    ...pendingLife(),
    ip,
    userAgent: req.get("user-agent")
  });

  sessions.setSessionCookie(res, config.ADMIN_COOKIE, created.token, created.session);
  res.json({ ok: true, next: NEXT_BY_STAGE[stage], email: row.email, displayName: row.displayName });
});

router.post("/totp", ratelimit.byIp("adminTotpIp"), requireAdmin({ stage: "totp" }), (req, res) => {
  const second = admins.checkSecondFactor(req.admin, text(req.body.code, 24), ratelimit.clientIp(req));

  if (!second.ok) {
    return res.status(401).json({
      error: second.locked
        ? "This account is temporarily locked. Please wait and try again."
        : "That code was not accepted. Use the current 6-digit code from your authenticator app, or a recovery code.",
      code: "bad-code"
    });
  }

  const extra = {};

  if (second.usedRecovery) {
    extra.warning =
      `You signed in with a recovery code (${admins.recoveryCodesLeft(req.admin.id)} left). ` +
      "Each code works once. Ask an Electoral Officer to reset your two-factor set-up if you have lost your phone.";
  }

  finishSignIn(req, res, second.admin, extra);
});

/* ---------- first use: choose a password, then enrol two-factor ---------- */

router.post("/setup/password", requireAdmin({ stage: "setup-password" }), async (req, res) => {
  const result = await admins.changeOwnPassword(
    req.admin, "", text(req.body.newPassword, 300), req.adminSession.tokenHash, { requireCurrent: false }
  );

  if (!result.ok) return sendFailure(res, result);

  const fresh = admins.getById(req.admin.id);
  const stage = fresh.totpEnabled ? "totp" : "setup-totp";

  const next = sessions.rotate(req.adminSession, { stage, data: {}, ...pendingLife() });
  sessions.setSessionCookie(res, config.ADMIN_COOKIE, next.token, next.session);

  res.json({ ok: true, next: NEXT_BY_STAGE[stage] });
});

router.post("/setup/totp/start", requireAdmin({ stage: "setup-totp" }), (req, res) => {
  const setup = admins.beginTotpSetup(req.admin);

  // The pending secret waits in the session, encrypted, until the first code proves the phone has it.
  sessions.update(req.adminSession, {
    data: { ...req.adminSession.data, pendingSecret: keys.encryptString(setup.secret, "totp-enc") }
  });

  res.json({
    account: req.admin.email,
    issuer: "BOUESTI Vote",
    secret: setup.formattedSecret,
    uri: setup.uri
  });
});

router.post("/setup/totp/confirm", ratelimit.byIp("adminTotpIp"), requireAdmin({ stage: "setup-totp" }), (req, res) => {
  const pending = req.adminSession.data.pendingSecret;

  if (!pending) return clientError(res, "Start the two-factor set-up first.", "no-setup");

  const secret = keys.decryptString(pending, "totp-enc");
  const code = text(req.body.code, 12).replace(/\s/g, "");
  const result = admins.confirmTotpSetup(req.admin, secret, code);

  if (!result.ok) {
    return res.status(400).json({
      error: "That code did not match. Check that your phone's clock is automatic, then enter the next code.",
      code: "bad-code"
    });
  }

  finishSignIn(req, res, admins.getById(req.admin.id), {
    recoveryCodes: result.recoveryCodes,
    notice: "Save these recovery codes somewhere safe. Each works once if you lose your phone. They are shown only now."
  });
});

/* ---------- forgotten password: one-time code issued by an officer ---------- */

router.post("/reset/redeem", ratelimit.byIp("adminResetIp"), async (req, res) => {
  const email = admins.normaliseEmail(text(req.body.email, 200)).slice(0, 160);

  const byEmail = ratelimit.take("adminLoginEmail", `reset:${email || "(blank)"}`, { auditLabel: `reset:${email}` });
  if (!byEmail.allowed) return tooMany(res, byEmail);

  const result = await admins.redeemResetCode(
    email, text(req.body.code, 40), text(req.body.newPassword, 300), ratelimit.clientIp(req)
  );

  if (!result.ok) return sendFailure(res, result);

  res.json({ ok: true, message: "Your password has been changed. Sign in with the new password." });
});

/* ------------------------------------------------------------------ */
/* Signed-in housekeeping                                               */
/* ------------------------------------------------------------------ */

router.post("/keepalive", requireAdmin(), (req, res) => {
  res.json(describeSession(req));
});

router.post("/logout", (req, res) => {
  if (req.adminSession) {
    sessions.revoke(req.adminSession.tokenHash, "logout");
    audit.append(audit.adminActor(req.admin), "auth", "Signed out");
  }

  sessions.clearSessionCookie(res, config.ADMIN_COOKIE);
  res.json({ ok: true });
});

router.post("/logout-all", requireAdmin(), (req, res) => {
  const ended = sessions.revokeAllFor("admin", req.admin.id, "logout-all");

  audit.append(audit.adminActor(req.admin), "auth", `Signed out of all sessions (${ended})`);
  sessions.clearSessionCookie(res, config.ADMIN_COOKIE);
  res.json({ ok: true, ended });
});

/* A fresh two-factor code unlocks sensitive actions for STEP_UP_SEC. */
router.post("/stepup", requireAdmin(), (req, res) => {
  const limit = ratelimit.take("adminStepUp", String(req.admin.id), { auditLabel: req.admin.email });
  if (!limit.allowed) return tooMany(res, limit);

  const second = admins.checkSecondFactor(req.admin, text(req.body.code, 24), ratelimit.clientIp(req));

  if (!second.ok) {
    return res.status(401).json({
      error: "That code was not accepted. Wait for your app to show a new code and try again.",
      code: "bad-code"
    });
  }

  const updated = sessions.update(req.adminSession, { data: { ...req.adminSession.data, stepUpAt: Date.now() } });

  audit.append(
    audit.adminActor(req.admin), "auth",
    second.usedRecovery ? "Confirmed a sensitive action with a recovery code" : "Confirmed sensitive actions with a 2FA code"
  );

  res.json({ ok: true, stepUpValidForSec: stepUpSecondsLeft(updated) });
});

router.get("/security", requireAdmin({ passive: true }), (req, res) => {
  const mine = sessions
    .listActiveFor("admin", req.admin.id)
    .filter((session) => session.stage === "full")
    .map((session) => ({
      current: session.tokenHash === req.adminSession.tokenHash,
      signedInAt: session.createdAt,
      lastActiveAt: session.lastActiveAt,
      expiresInSec: secondsLeft(Math.min(session.idleExpiresAt, session.absoluteExpiresAt) - Date.now()),
      ip: session.ip,
      device: session.userAgent
    }));

  res.json({
    admin: admins.publicView(req.admin),
    sessions: mine,
    history: admins.loginHistory(req.admin.id, 20),
    recoveryCodesLeft: admins.recoveryCodesLeft(req.admin.id),
    policy: {
      idleMinutes: Math.round(config.ADMIN_IDLE_SEC / 60),
      absoluteHours: Math.round((config.ADMIN_ABSOLUTE_SEC / 3600) * 10) / 10,
      lockoutAttempts: config.ADMIN_MAX_FAILED,
      lockoutMinutes: Math.round(config.ADMIN_LOCK_SEC / 60),
      minPasswordLength: config.MIN_PASSWORD_LENGTH
    }
  });
});

router.post("/password", requireAdmin(), async (req, res) => {
  const limit = ratelimit.take("adminStepUp", `password:${req.admin.id}`, { auditLabel: req.admin.email });
  if (!limit.allowed) return tooMany(res, limit);

  const result = await admins.changeOwnPassword(
    req.admin, text(req.body.currentPassword, 300), text(req.body.newPassword, 300), req.adminSession.tokenHash
  );

  if (!result.ok) return sendFailure(res, result);

  res.json({ ok: true, message: "Password changed. Your other sessions were signed out." });
});

router.post("/recovery-codes/regenerate", requireAdmin({ stepUp: true }), (req, res) => {
  if (!req.admin.totpEnabled) return clientError(res, "Two-factor authentication is not enrolled.", "no-2fa", 409);

  res.json({
    ok: true,
    recoveryCodes: admins.regenerateRecoveryCodes(req.admin),
    notice: "The old recovery codes no longer work. Save these new ones now; they are not shown again."
  });
});

/* ------------------------------------------------------------------ */
/* Account management (Electoral Officer)                               */
/* ------------------------------------------------------------------ */

/*
  While a LIVE election's results are being counted, the web page may not
  change the credentials, role or status of the two officers who count and
  approve them. Otherwise one person with account-management rights could
  take over a colleague's account and satisfy the two-person rule alone.
  The Technical Support Officer can still recover a locked-out officer from
  the server console (npm run admin), which is logged separately.
*/
function frozenForResults(target) {
  const current = election.getElection();
  if (current.mode !== "live" || current.status !== "closed") return false;

  return target.role === "electoral_officer" || target.role === "results_officer";
}

function frozenReply(res) {
  return clientError(
    res,
    "Changes to the Electoral and Results Officers' accounts are frozen while live results are being counted and verified. " +
      "If someone is locked out, the Technical Support Officer can recover the account from the server (see docs/OPERATIONS.md).",
    "frozen",
    409
  );
}

function targetOf(req, res) {
  const id = idParam(req.params.id);
  const target = id ? admins.getById(id) : null;

  if (!target) {
    clientError(res, "Administrator not found.", "not-found", 404);
    return null;
  }

  return target;
}

router.get("/admins", requireAdmin({ permission: "admins.view" }), (req, res) => {
  const mayManage = can(req.admin.role, "admins.manage");

  res.json({
    admins: admins.list(),
    resets: mayManage ? admins.listResets() : [],
    roles: Object.entries(ROLES).map(([key, role]) => ({
      key,
      label: role.label,
      summary: role.summary,
      permissions: role.permissions
    })),
    policy: {
      lockoutAttempts: config.ADMIN_MAX_FAILED,
      lockoutMinutes: Math.round(config.ADMIN_LOCK_SEC / 60),
      resetCodeMinutes: Math.round(config.RESET_CODE_TTL_SEC / 60)
    },
    frozen: election.getElection().mode === "live" && election.getElection().status === "closed"
  });
});

router.post("/admins", requireAdmin({ permission: "admins.manage", stepUp: true }), async (req, res) => {
  if (["electoral_officer", "results_officer"].includes(text(req.body.role, 40))) {
    const current = election.getElection();
    if (current.mode === "live" && current.status === "closed") return frozenReply(res);
  }

  const result = await admins.createAdmin(
    { email: text(req.body.email, 200), displayName: text(req.body.displayName, 120), role: text(req.body.role, 40) },
    audit.adminActor(req.admin)
  );

  if (!result.ok) return sendFailure(res, result);

  res.json({
    ok: true,
    admin: result.admin,
    temporaryPassword: result.temporaryPassword,
    notice: "Give this temporary password to the person in private. It works once: they must choose their own password and set up two-factor at first sign-in. It is not shown again."
  });
});

router.post("/admins/:id/role", requireAdmin({ permission: "admins.manage", stepUp: true }), (req, res) => {
  const target = targetOf(req, res);
  if (!target) return;

  const newRole = text(req.body.role, 40);
  if (frozenForResults(target) || frozenForResults({ role: newRole })) return frozenReply(res);

  const result = admins.setRole(target.id, newRole, audit.adminActor(req.admin), req.admin.id);
  if (!result.ok) return sendFailure(res, result, 409);

  res.json({ ok: true });
});

router.post("/admins/:id/disable", requireAdmin({ permission: "admins.manage", stepUp: true }), (req, res) => {
  const target = targetOf(req, res);
  if (!target) return;
  if (frozenForResults(target)) return frozenReply(res);

  const result = admins.setDisabled(target.id, bool(req.body.disabled), audit.adminActor(req.admin), req.admin.id);
  if (!result.ok) return sendFailure(res, result, 409);

  res.json({ ok: true });
});

router.post("/admins/:id/unlock", requireAdmin({ permission: "admins.manage", stepUp: true }), (req, res) => {
  const target = targetOf(req, res);
  if (!target) return;

  const result = admins.unlock(target.id, audit.adminActor(req.admin));
  if (!result.ok) return sendFailure(res, result);

  res.json({ ok: true });
});

router.post("/admins/:id/reset-password", requireAdmin({ permission: "admins.manage", stepUp: true }), (req, res) => {
  const target = targetOf(req, res);
  if (!target) return;
  if (frozenForResults(target)) return frozenReply(res);

  const result = admins.issueResetCode(target.id, audit.adminActor(req.admin));
  if (!result.ok) return sendFailure(res, result);

  res.json({
    ok: true,
    code: result.code,
    expiresAt: result.expiresAt,
    notice:
      `Give this code to ${target.displayName} in person. They enter it, with their e-mail and a new password, ` +
      `under "Forgot your password?" on the sign-in page within ${Math.round(config.RESET_CODE_TTL_SEC / 60)} minutes. It is not shown again.`
  });
});

router.post("/admins/:id/reset-2fa", requireAdmin({ permission: "admins.manage", stepUp: true }), (req, res) => {
  const target = targetOf(req, res);
  if (!target) return;
  if (frozenForResults(target)) return frozenReply(res);

  const result = admins.resetTwoFactor(target.id, audit.adminActor(req.admin));
  if (!result.ok) return sendFailure(res, result);

  res.json({ ok: true, notice: "Their two-factor set-up was cleared and their sessions ended. They set it up again at next sign-in." });
});

router.get("/admins/:id/history", requireAdmin({ permission: "admins.view" }), (req, res) => {
  const target = targetOf(req, res);
  if (!target) return;

  res.json({ email: target.email, history: admins.loginHistory(target.id, 50) });
});

module.exports = router;
