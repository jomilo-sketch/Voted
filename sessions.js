/*
  BOUESTI Vote — server-side sessions.

  A session is a row in the database (sessions table), so it survives a
  server restart. The browser holds only a random 256-bit token in a
  cookie; the database stores just the SHA-256 of that token, so a copy
  of the database cannot be replayed as a login.

  Lifetimes
    idle      the session dies after this long without USER activity
    absolute  the session dies this long after sign-in, no matter what
  Background polling by the dashboard does not extend the idle timer —
  only real actions do (see touch()).

  Cookies: HttpOnly (JavaScript cannot read it), SameSite=Strict (never
  sent on cross-site requests), Secure whenever COOKIE_SECURE is on, and
  with the __Host- prefix in that case.
*/

"use strict";

const d = require("./db");
const config = require("./config");
const keys = require("./keys");

const TOUCH_INTERVAL_MS = 15_000;

function hashToken(token) {
  return keys.sha256Hex(String(token));
}

function rowToSession(row) {
  if (!row) return null;

  return {
    tokenHash: row.tokenHash,
    kind: row.kind,
    subject: row.subject,
    stage: row.stage,
    data: JSON.parse(row.data || "{}"),
    createdAt: row.createdAt,
    lastActiveAt: row.lastActiveAt,
    idleExpiresAt: row.idleExpiresAt,
    absoluteExpiresAt: row.absoluteExpiresAt,
    ip: row.ip,
    userAgent: row.userAgent
  };
}

function lifetimes(kind, overrides = {}) {
  const idleSec = overrides.idleSec ?? (kind === "admin" ? config.ADMIN_IDLE_SEC : config.VOTER_IDLE_SEC);
  const absoluteSec = overrides.absoluteSec ?? (kind === "admin" ? config.ADMIN_ABSOLUTE_SEC : config.VOTER_ABSOLUTE_SEC);
  return { idleSec, absoluteSec };
}

/* Create a session. Returns { token, session }; the token is shown to
   the browser once and never stored in readable form. */
function create({
  kind, subject, stage, data = {}, idleSec, absoluteSec, absoluteExpiresAt: fixedAbsolute, ip = null, userAgent = null
}) {
  const token = keys.randomToken(32);
  const now = Date.now();
  const life = lifetimes(kind, { idleSec, absoluteSec });
  const absoluteExpiresAt = fixedAbsolute || now + life.absoluteSec * 1000;
  const idleExpiresAt = Math.min(now + life.idleSec * 1000, absoluteExpiresAt);

  d.run(
    `INSERT INTO sessions
       (tokenHash, kind, subject, stage, data, createdAt, lastActiveAt, idleExpiresAt, absoluteExpiresAt, ip, userAgent)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    hashToken(token), kind, String(subject), stage, JSON.stringify(data),
    now, now, idleExpiresAt, absoluteExpiresAt,
    ip, userAgent ? String(userAgent).slice(0, 160) : null
  );

  return { token, session: rowToSession(d.get("SELECT * FROM sessions WHERE tokenHash = ?", hashToken(token))) };
}

/* Valid, un-revoked, un-expired session for this token — or null. */
function lookup(token, kind) {
  if (!token || typeof token !== "string" || token.length > 200) return null;

  const row = d.get("SELECT * FROM sessions WHERE tokenHash = ?", hashToken(token));
  if (!row || row.kind !== kind || row.revokedAt) return null;

  const now = Date.now();
  if (now >= row.idleExpiresAt || now >= row.absoluteExpiresAt) return null;

  return rowToSession(row);
}

/* Record real user activity: slides the idle deadline forward (never past
   the absolute deadline). Rate-limited so it is not a write on every request. */
function touch(session) {
  const now = Date.now();
  if (now - session.lastActiveAt < TOUCH_INTERVAL_MS) return session;

  const life = lifetimes(session.kind);
  const idleExpiresAt = Math.min(now + life.idleSec * 1000, session.absoluteExpiresAt);

  d.run(
    "UPDATE sessions SET lastActiveAt = ?, idleExpiresAt = ? WHERE tokenHash = ?",
    now, idleExpiresAt, session.tokenHash
  );

  return { ...session, lastActiveAt: now, idleExpiresAt };
}

/* Change stage and/or data in place (same token). */
function update(session, { stage, data }) {
  const nextStage = stage ?? session.stage;
  const nextData = data ?? session.data;

  d.run(
    "UPDATE sessions SET stage = ?, data = ? WHERE tokenHash = ?",
    nextStage, JSON.stringify(nextData), session.tokenHash
  );

  return { ...session, stage: nextStage, data: nextData };
}

/* Issue a NEW token for the same subject and retire the old one. Done on
   every privilege change (password OK -> 2FA OK, rules accepted -> OTP
   verified) so a token captured earlier cannot be upgraded. */
function rotate(session, { stage, data, idleSec, absoluteSec, preserveAbsolute = false, ip, userAgent }) {
  const fresh = create({
    kind: session.kind,
    subject: session.subject,
    stage: stage ?? session.stage,
    data: data ?? session.data,
    idleSec,
    absoluteSec,
    absoluteExpiresAt: preserveAbsolute ? session.absoluteExpiresAt : undefined,
    ip: ip ?? session.ip,
    userAgent: userAgent ?? session.userAgent
  });

  revoke(session.tokenHash, "rotated");
  return fresh;
}

function revoke(tokenHash, reason = "logout") {
  // A voter session carries a matric number, so it is deleted outright.
  // Administrator sessions are kept (marked revoked) as a record.
  const removed = d.run("DELETE FROM sessions WHERE tokenHash = ? AND kind = 'voter'", tokenHash).changes;
  if (removed) return removed;

  return d.run(
    "UPDATE sessions SET revokedAt = ?, revokedReason = ? WHERE tokenHash = ? AND revokedAt IS NULL",
    Date.now(), reason, tokenHash
  ).changes;
}

/* Delete the row outright (used the moment a ballot is accepted, so no
   matric-number-with-a-time record lingers). */
function destroy(tokenHash) {
  return d.run("DELETE FROM sessions WHERE tokenHash = ?", tokenHash).changes;
}

function revokeToken(token, reason = "logout") {
  return token ? revoke(hashToken(token), reason) : 0;
}

/* End every live session for a subject (password changed, account
   disabled, voter signs in again...). */
function revokeAllFor(kind, subject, reason, exceptTokenHash = null) {
  if (kind === "voter") {
    return d.run(
      "DELETE FROM sessions WHERE kind = 'voter' AND subject = ? AND tokenHash != ?",
      String(subject), exceptTokenHash || ""
    ).changes;
  }

  return d.run(
    `UPDATE sessions SET revokedAt = ?, revokedReason = ?
     WHERE kind = ? AND subject = ? AND revokedAt IS NULL AND tokenHash != ?`,
    Date.now(), reason, kind, String(subject), exceptTokenHash || ""
  ).changes;
}

/* End every live session of one kind (e.g. all voters when the election closes). */
function revokeAllForKind(kind, reason) {
  if (kind === "voter") return d.run("DELETE FROM sessions WHERE kind = 'voter'").changes;

  return d.run(
    "UPDATE sessions SET revokedAt = ?, revokedReason = ? WHERE kind = ? AND revokedAt IS NULL",
    Date.now(), reason, kind
  ).changes;
}

function listActiveFor(kind, subject) {
  const now = Date.now();

  return d
    .all(
      `SELECT * FROM sessions
       WHERE kind = ? AND subject = ? AND revokedAt IS NULL AND idleExpiresAt > ? AND absoluteExpiresAt > ?
       ORDER BY createdAt DESC`,
      kind, String(subject), now, now
    )
    .map(rowToSession);
}

function activeCounts() {
  const now = Date.now();
  const rows = d.all(
    `SELECT kind, COUNT(*) AS n FROM sessions
     WHERE revokedAt IS NULL AND idleExpiresAt > ? AND absoluteExpiresAt > ? AND (kind = 'voter' OR stage = 'full')
     GROUP BY kind`,
    now, now
  );

  const counts = { voter: 0, admin: 0 };
  rows.forEach((row) => {
    counts[row.kind] = row.n;
  });
  return counts;
}

/* Voter sessions hold a matric number, so they are deleted an hour after
   they end. Admin sessions are kept for 30 days as a record. */
const ENDED_AT = `CASE WHEN revokedAt IS NOT NULL THEN revokedAt
                        ELSE MIN(idleExpiresAt, absoluteExpiresAt) END`;

function sweep() {
  const now = Date.now();
  let removed = 0;

  removed += d.run(
    `DELETE FROM sessions WHERE kind = 'voter' AND (${ENDED_AT}) < ?`,
    now - 60 * 60 * 1000
  ).changes;

  removed += d.run(
    `DELETE FROM sessions WHERE kind = 'admin' AND (${ENDED_AT}) < ?`,
    now - 30 * 24 * 60 * 60 * 1000
  ).changes;

  return removed;
}

/* ---------- cookies ---------- */

function parseCookies(header) {
  const jar = {};
  String(header || "")
    .split(";")
    .forEach((part) => {
      const index = part.indexOf("=");
      if (index < 0) return;

      const name = part.slice(0, index).trim();
      const value = part.slice(index + 1).trim();

      if (name && !(name in jar)) {
        try {
          jar[name] = decodeURIComponent(value);
        } catch (error) {
          jar[name] = value;
        }
      }
    });
  return jar;
}

function cookieAttributes(maxAgeSec) {
  const attributes = ["Path=/", "HttpOnly", "SameSite=Strict"];
  if (config.COOKIE_SECURE) attributes.push("Secure");
  if (maxAgeSec !== undefined) attributes.push(`Max-Age=${Math.max(0, Math.floor(maxAgeSec))}`);
  return attributes.join("; ");
}

function appendSetCookie(res, value) {
  const existing = res.getHeader("Set-Cookie");
  if (!existing) res.setHeader("Set-Cookie", [value]);
  else res.setHeader("Set-Cookie", [].concat(existing, value));
}

function setSessionCookie(res, cookieName, token, session) {
  const remaining = Math.max(0, (session.absoluteExpiresAt - Date.now()) / 1000);
  appendSetCookie(res, `${cookieName}=${encodeURIComponent(token)}; ${cookieAttributes(remaining)}`);
}

function clearSessionCookie(res, cookieName) {
  appendSetCookie(res, `${cookieName}=; ${cookieAttributes(0)}`);
}

module.exports = {
  hashToken,
  create,
  lookup,
  touch,
  update,
  rotate,
  revoke,
  destroy,
  revokeToken,
  revokeAllFor,
  revokeAllForKind,
  listActiveFor,
  activeCounts,
  sweep,
  parseCookies,
  setSessionCookie,
  clearSessionCookie
};
