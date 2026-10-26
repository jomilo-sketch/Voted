/*
  BOUESTI Vote — audit trail.

  A tamper-evident, append-only record of security-relevant events:
  sign-ins, lockouts, election changes, backups, report signing, and so
  on. Three rules keep it safe to share with auditors:

    1. It NEVER contains a ballot choice. A voter's entry says only THAT a
       ballot was accepted ("Ballot accepted for v-3fa9c2d1b0"), never WHAT it
       held or WHICH ballot it was: ballot rows carry no time, no sequence
       number and no voter reference, so the log cannot be joined to them.
       Voter events use a keyed pseudonym, not the matric number, so a leaked
       log cannot be joined to the roster either.
    2. Each entry embeds the hash of the previous entry (chain.js), and
       the database refuses UPDATE and DELETE on the table.
    3. Reading the log is itself logged ("audit-access" entries).
*/

"use strict";

const d = require("./db");
const keys = require("./keys");
const chain = require("./chain");

const MAX_MESSAGE = 600;
const accessThrottle = new Map();

function clean(text, limit) {
  return String(text ?? "")
    .replace(/[\u0000-\u001f\u007f]+/g, " ")
    .trim()
    .slice(0, limit);
}

/* Short, stable pseudonym for a voter. Different key from the turnout
   table, so the two cannot be joined without the master key. */
function voterTag(matric) {
  return `v-${keys.hmacHex("audit-tag", String(matric)).slice(0, 10)}`;
}

function adminActor(admin) {
  return `admin:${admin.email}`;
}

/* Append one entry. Safe to call inside another transaction. */
function append(actor, category, message) {
  const safeActor = clean(actor, 120) || "system";
  const safeCategory = clean(category, 40) || "system";
  const safeMessage = clean(message, MAX_MESSAGE);

  return d.tx(() => {
    const last = d.get("SELECT id, hash FROM audit_log ORDER BY id DESC LIMIT 1");
    const prevHash = last ? last.hash : chain.GENESIS_HASH;
    const occurredAt = d.nowIso();
    const hash = chain.computeHash(prevHash, occurredAt, safeActor, safeCategory, safeMessage);

    const result = d.run(
      `INSERT INTO audit_log (occurredAt, actor, category, message, prevHash, hash)
       VALUES (?, ?, ?, ?, ?, ?)`,
      occurredAt, safeActor, safeCategory, safeMessage, prevHash, hash
    );

    return { id: Number(result.lastInsertRowid), hash, occurredAt };
  });
}

function head() {
  const row = d.get("SELECT id, hash, occurredAt FROM audit_log ORDER BY id DESC LIMIT 1");
  return row || { id: 0, hash: chain.GENESIS_HASH, occurredAt: null };
}

/* ---------- signed checkpoints ---------- */

function checkpointMessage(auditId, auditHash, createdAt) {
  return `bouesti-vote/audit-checkpoint/v1|${auditId}|${auditHash}|${createdAt}`;
}

/* Signs the current head of the chain. Officials keep copies of these
   (printed or exported) so that a wholesale rewrite of the log, which a
   database administrator could otherwise re-hash, is still detectable. */
function checkpoint(reason) {
  const current = head();
  const createdAt = d.nowIso();
  const signature = keys.sign(checkpointMessage(current.id, current.hash, createdAt));

  const result = d.run(
    `INSERT INTO audit_checkpoints (auditId, auditHash, reason, createdAt, signature)
     VALUES (?, ?, ?, ?, ?)`,
    current.id, current.hash, clean(reason, 120), createdAt, signature
  );

  return {
    id: Number(result.lastInsertRowid),
    auditId: current.id,
    auditHash: current.hash,
    createdAt,
    signature
  };
}

function listCheckpoints(limit = 100) {
  return d.all("SELECT * FROM audit_checkpoints ORDER BY id DESC LIMIT ?", limit);
}

/* ---------- reading ---------- */

function escapeLike(text) {
  return String(text).replace(/[\\%_]/g, (char) => `\\${char}`);
}

function list({ category, search, voter, beforeId, limit = 100 } = {}) {
  const where = [];
  const params = [];

  if (category) {
    where.push("category = ?");
    params.push(category);
  }

  if (search) {
    where.push("(message LIKE ? ESCAPE '\\' OR actor LIKE ? ESCAPE '\\')");
    params.push(`%${escapeLike(search)}%`, `%${escapeLike(search)}%`);
  }

  if (voter) {
    where.push("message LIKE ? ESCAPE '\\'");
    params.push(`%${escapeLike(voterTag(voter))}%`);
  }

  if (beforeId) {
    where.push("id < ?");
    params.push(Number(beforeId));
  }

  const clause = where.length ? `WHERE ${where.join(" AND ")}` : "";
  const safeLimit = Math.min(Math.max(Number(limit) || 100, 1), 500);

  const rows = d.all(
    `SELECT id, occurredAt, actor, category, message, prevHash, hash
     FROM audit_log ${clause} ORDER BY id DESC LIMIT ?`,
    ...params, safeLimit
  );

  return rows;
}

function categories() {
  return d.all("SELECT category, COUNT(*) AS n FROM audit_log GROUP BY category ORDER BY category");
}

/* ---------- verification ---------- */

/* Re-computes the entire chain and every signed checkpoint. */
function verify() {
  const iterator = d
    .db.prepare("SELECT id, occurredAt, actor, category, message, prevHash, hash FROM audit_log ORDER BY id")
    .iterate();

  const chainResult = chain.verifyRows(iterator);
  const checkpoints = d.all("SELECT * FROM audit_checkpoints ORDER BY id");
  const publicKey = keys.signingPublicKey();

  const checkpointProblems = [];

  checkpoints.forEach((cp) => {
    const signatureOk = keys.verifySignature(
      publicKey,
      checkpointMessage(cp.auditId, cp.auditHash, cp.createdAt),
      cp.signature
    );

    const entry = d.get("SELECT hash FROM audit_log WHERE id = ?", cp.auditId);
    const hashOk = cp.auditId === 0 ? cp.auditHash === chain.GENESIS_HASH : Boolean(entry) && entry.hash === cp.auditHash;

    if (!signatureOk) checkpointProblems.push(`checkpoint ${cp.id}: signature invalid`);
    if (!hashOk) checkpointProblems.push(`checkpoint ${cp.id}: chain no longer matches entry ${cp.auditId}`);
  });

  return {
    ok: chainResult.ok && checkpointProblems.length === 0,
    chain: chainResult,
    checkpointsChecked: checkpoints.length,
    checkpointProblems
  };
}

/* ---------- export (NDJSON) ---------- */

function exportLines() {
  const lines = [];
  const current = head();

  lines.push(JSON.stringify({
    type: "header",
    format: "bouesti-vote-audit-export/1",
    exportedAt: d.nowIso(),
    genesisHash: chain.GENESIS_HASH,
    headId: current.id,
    headHash: current.hash,
    publicKey: keys.signingPublicKey()
  }));

  for (const row of d.db
    .prepare("SELECT id, occurredAt, actor, category, message, prevHash, hash FROM audit_log ORDER BY id")
    .iterate()) {
    lines.push(JSON.stringify({ type: "entry", ...row }));
  }

  d.all("SELECT * FROM audit_checkpoints ORDER BY id").forEach((cp) => {
    lines.push(JSON.stringify({ type: "checkpoint", ...cp }));
  });

  return lines;
}

/* ---------- monitoring who reads the log ---------- */

/*
  Every read of audit data is itself recorded. Routine "refresh" views are
  throttled to one entry per administrator per minute so the log is not
  flooded; exports, verifications and voter look-ups are always recorded.
*/
function recordAccess(admin, what, { always = false } = {}) {
  const key = `${admin.id}:${what}`;
  const nowMs = Date.now();

  if (!always) {
    const last = accessThrottle.get(key) || 0;
    if (nowMs - last < 60_000) return null;
    accessThrottle.set(key, nowMs);
  }

  return append(adminActor(admin), "audit-access", `${admin.role}: ${what}`);
}

module.exports = {
  voterTag,
  adminActor,
  append,
  head,
  checkpoint,
  listCheckpoints,
  list,
  categories,
  verify,
  exportLines,
  recordAccess
};
