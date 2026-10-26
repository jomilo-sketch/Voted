/*
  BOUESTI Vote — administrator routes for results and their verification,
  the restricted/monitored audit log, and operations (monitoring, backups,
  restoration drills, the read-only audit copy, go-live checklist).

  Results never go public on one person's say-so:
    Results Officer   prepare  -> counts and signs a report
    Electoral Officer approve  -> a DIFFERENT person publishes it
    Two officials     compare  -> the live database against the published
                                  report, one supervising the other
*/

"use strict";

const fs = require("fs");
const path = require("path");
const express = require("express");
const keys = require("./keys");
const audit = require("./audit");
const election = require("./election");
const reports = require("./reports");
const ops = require("./ops");
const backup = require("./backup");
const backupCore = require("./backup-core");
const ratelimit = require("./ratelimit");
const { can } = require("./permissions");
const { requireAdmin, requireStepUp } = require("./middleware");
const { sendFailure, reply, clientError, idParam, text, csvLine, sendDownload, safeFileName } = require("./http");

const router = express.Router();

function heavyLimit(req, res, next) {
  const limit = ratelimit.take("adminHeavy", String(req.admin.id), { auditLabel: req.admin.email });

  if (!limit.allowed) {
    res.set("Retry-After", String(limit.retryAfterSec));
    return res.status(429).json({
      error: `Please wait ${ratelimit.waitText(limit.retryAfterSec)} before running another heavy operation.`,
      code: "rate-limited"
    });
  }

  next();
}

/* ------------------------------------------------------------------ */
/* Results                                                              */
/* ------------------------------------------------------------------ */

router.get("/results", requireAdmin({ permission: "results.view" }), (req, res) => {
  const view = reports.tallyView();

  res.json({
    ...view,
    comparisons: reports.listComparisons(15),
    me: {
      email: req.admin.email,
      canPrepare: can(req.admin.role, "results.prepare"),
      canApprove: can(req.admin.role, "results.approve"),
      canCompare: can(req.admin.role, "results.compare")
    }
  });
});

router.get("/results/export.csv", requireAdmin({ permission: "results.view" }), (req, res) => {
  const view = reports.tallyView();

  if (!view.available) return clientError(res, view.reason, "sealed", 409);

  const current = election.getElection();
  const lines = [
    csvLine(["election", current.electionName]),
    csvLine(["status", view.provisional ? "PROVISIONAL (voting not closed)" : "FINAL (voting closed)"]),
    csvLine(["ballots cast", view.ballotsCast]),
    "",
    csvLine(["position", "candidate", "votes", "share of position"])
  ];

  view.offices.forEach((office) => {
    office.candidates.forEach((candidate) => {
      const share = office.totalVotes > 0 ? `${((candidate.votes / office.totalVotes) * 100).toFixed(1)}%` : "0.0%";
      lines.push(csvLine([office.office, candidate.name, candidate.votes, share]));
    });
  });

  audit.append(audit.adminActor(req.admin), "report", "Exported the tally as CSV");

  sendDownload(res, {
    fileName: `results-${view.provisional ? "provisional" : "final"}.csv`,
    contentType: "text/csv; charset=utf-8",
    body: `﻿${lines.join("\r\n")}\r\n`
  });
});

router.get("/results/comparisons", requireAdmin({ permission: "results.view" }), (req, res) => {
  res.json({ comparisons: reports.listComparisons(50) });
});

router.post("/results/prepare", requireAdmin({ permission: "results.prepare", stepUp: true }), (req, res) => {
  reply(res, reports.prepareReport(req.admin, text(req.body.note, 300)), (result) => ({ ok: true, id: result.id, sequence: result.sequence }));
});

router.post("/results/:id/approve", requireAdmin({ permission: "results.approve", stepUp: true }), (req, res) => {
  const id = idParam(req.params.id);
  if (!id) return clientError(res, "Report not found.", "not-found", 404);

  reply(res, reports.approveReport(id, req.admin));
});

router.post("/results/:id/reject", requireAdmin({ permission: "results.approve", stepUp: true }), (req, res) => {
  const id = idParam(req.params.id);
  if (!id) return clientError(res, "Report not found.", "not-found", 404);

  reply(res, reports.rejectReport(id, req.admin, text(req.body.reason, 300)));
});

/* The signed package officials keep. Verify it on any computer with
   `node scripts/verify-report.js <file>` — no access to this server needed. */
router.get("/results/:id/download", requireAdmin({ permission: "results.view" }), (req, res) => {
  const id = idParam(req.params.id);
  const envelope = id ? reports.getEnvelope(id) : null;

  if (!envelope) return clientError(res, "Report not found.", "not-found", 404);

  audit.append(audit.adminActor(req.admin), "report", `Downloaded signed tally report #${envelope.report.sequence}`);

  sendDownload(res, {
    fileName: `bouesti-signed-tally-${envelope.report.sequence}-${envelope.status}.json`,
    contentType: "application/json; charset=utf-8",
    body: JSON.stringify(envelope, null, 2)
  });
});

/* Supervised comparison: the person running it signs in again as the witness. */
router.post("/results/:id/compare", requireAdmin({ permission: "results.compare" }), ratelimit.byIp("adminWitness"), async (req, res) => {
  const id = idParam(req.params.id);
  if (!id) return clientError(res, "Report not found.", "not-found", 404);

  const result = await reports.compareWithDatabase({
    reportId: id,
    performer: req.admin,
    witnessEmail: text(req.body.witnessEmail, 200),
    witnessPassword: text(req.body.witnessPassword, 300),
    witnessCode: text(req.body.witnessCode, 24),
    ip: ratelimit.clientIp(req)
  });

  if (!result.ok) return sendFailure(res, result, 400);
  res.json(result);
});

/* Check a downloaded package against THIS server's signing key. */
router.post("/results/verify", requireAdmin({ permission: "results.view" }), (req, res) => {
  let envelope = req.body.envelope;

  if (typeof req.body.text === "string") {
    try {
      envelope = JSON.parse(req.body.text);
    } catch (error) {
      return clientError(res, "That is not a valid report file.", "bad-file");
    }
  }

  if (!envelope || typeof envelope !== "object") return clientError(res, "Choose a signed report file to check.", "no-file");

  const outcome = reports.verifyEnvelope(envelope, keys.signingPublicKey());

  audit.append(audit.adminActor(req.admin), "report", `Checked a signed report file: ${outcome.ok ? "all checks passed" : "FAILED"}`);
  res.json({ ...outcome, trustedFingerprint: keys.publicKeyFingerprint() });
});

/* ------------------------------------------------------------------ */
/* Audit log — restricted, and every reading is itself recorded          */
/* ------------------------------------------------------------------ */

function lookingUpAVoter(req) {
  return Boolean(text(req.query.voter, 20));
}

router.get(
  "/audit",
  requireAdmin({ permission: "audit.view" }),
  (req, res, next) => (lookingUpAVoter(req) ? requireStepUp(req, res, next) : next()),
  (req, res) => {
    const voter = text(req.query.voter, 20);

    if (voter) {
      if (!/^\d{4,15}$/.test(voter)) return clientError(res, "Enter the matric number as digits only.", "matric-format");

      // Following one student's trail is always recorded, and the record names
      // the pseudonym, not the number.
      audit.recordAccess(req.admin, `looked up the audit trail of voter ${audit.voterTag(voter)}`, { always: true });
    } else {
      audit.recordAccess(req.admin, "viewed the audit log");
    }

    const entries = audit.list({
      category: text(req.query.category, 40) || undefined,
      search: text(req.query.search, 80) || undefined,
      voter: voter || undefined,
      beforeId: idParam(req.query.beforeId) || undefined,
      limit: Number(req.query.limit) || 100
    });

    res.json({
      entries,
      categories: audit.categories(),
      nextBeforeId: entries.length ? entries[entries.length - 1].id : null,
      head: audit.head()
    });
  }
);

router.post("/audit/verify", requireAdmin({ permission: "audit.view" }), (req, res) => {
  audit.recordAccess(req.admin, "ran an audit-log verification", { always: true });
  res.json(ops.chainStatus({ force: true }));
});

router.get("/audit/checkpoints", requireAdmin({ permission: "audit.view" }), (req, res) => {
  audit.recordAccess(req.admin, "viewed the signed checkpoints");
  res.json({ checkpoints: audit.listCheckpoints(100), publicKeyFingerprint: keys.publicKeyFingerprint() });
});

/* Who has been reading the log. Not itself logged (that would never end). */
router.get("/audit/access", requireAdmin({ permission: "audit.view" }), (req, res) => {
  res.json({ entries: audit.list({ category: "audit-access", limit: 150 }) });
});

router.get("/audit/export", requireAdmin({ permission: "audit.export", stepUp: true }), (req, res) => {
  audit.recordAccess(req.admin, "exported the full audit log", { always: true });
  audit.checkpoint("audit log exported");

  sendDownload(res, {
    fileName: `bouesti-audit-log-${new Date().toISOString().slice(0, 10)}.ndjson`,
    contentType: "application/x-ndjson; charset=utf-8",
    body: `${audit.exportLines().join("\n")}\n`
  });
});

/* ------------------------------------------------------------------ */
/* Operations                                                           */
/* ------------------------------------------------------------------ */

router.get("/ops/health", requireAdmin({ permission: "ops.view", passive: true }), (req, res) => {
  res.json(ops.health());
});

router.get("/ops/readiness", requireAdmin({ permission: "ops.view" }), (req, res) => {
  res.json(ops.readiness());
});

router.post("/ops/confirmations", requireAdmin({ permission: ["mode.manage", "ops.manage"] }), (req, res) => {
  const result = ops.setConfirmation(text(req.body.key, 40), req.body.confirmed === true, req.admin);
  if (!result.ok) return sendFailure(res, result);

  res.json({ ok: true, readiness: ops.readiness() });
});

router.post("/ops/test-mail", requireAdmin({ permission: "ops.manage" }), async (req, res) => {
  const limit = ratelimit.take("adminTestMail", String(req.admin.id), { auditLabel: req.admin.email });

  if (!limit.allowed) {
    res.set("Retry-After", String(limit.retryAfterSec));
    return clientError(res, `Please wait ${ratelimit.waitText(limit.retryAfterSec)} before sending another test.`, "rate-limited", 429);
  }

  const result = await ops.sendTestMail(text(req.body.to, 200), req.admin);
  if (!result.ok) return sendFailure(res, result, 502);

  res.json(result);
});

router.get("/ops/backups", requireAdmin({ permission: "ops.view" }), (req, res) => {
  res.json({ backups: backup.listBackups(60), status: backup.status() });
});

router.post("/ops/backup", requireAdmin({ permission: "ops.manage" }), heavyLimit, (req, res) => {
  const result = backup.createBackup("manual", `admin:${req.admin.email}`);
  if (!result.ok) return clientError(res, `The backup failed: ${result.error}`, "backup-failed", 500);

  res.json({ ok: true, file: result.file, sizeBytes: result.sizeBytes, stats: result.stats });
});

/* The encrypted file and its signed manifest. Useless without the master key. */
function sendBackupFile(req, res, withManifest) {
  const fullPath = backup.backupPathFor(text(req.params.file, 120));
  if (!fullPath) return clientError(res, "That backup file is not available.", "not-found", 404);

  const target = withManifest ? backupCore.manifestPathFor(fullPath) : fullPath;
  if (!fs.existsSync(target)) return clientError(res, "That file is not available.", "not-found", 404);

  audit.append(audit.adminActor(req.admin), "backup", `Downloaded ${path.basename(target)}`);

  res.setHeader("X-Content-Type-Options", "nosniff");
  res.download(target, safeFileName(path.basename(target)));
}

router.get("/ops/backups/:file", requireAdmin({ permission: "ops.manage", stepUp: true }), (req, res) => {
  sendBackupFile(req, res, false);
});

router.get("/ops/backups/:file/manifest", requireAdmin({ permission: "ops.manage", stepUp: true }), (req, res) => {
  sendBackupFile(req, res, true);
});

router.get("/ops/drills", requireAdmin({ permission: "ops.view" }), (req, res) => {
  res.json({ drills: backup.listDrills(30) });
});

router.post("/ops/drill", requireAdmin({ permission: "ops.manage" }), heavyLimit, (req, res) => {
  let file = null;

  if (req.body.file) {
    const known = backup.backupPathFor(text(req.body.file, 120));
    if (!known) return clientError(res, "That backup file is not available.", "not-found", 404);
    file = path.basename(known);
  }

  const result = backup.runDrill("manual", `admin:${req.admin.email}`, file);
  res.json(result);
});

router.get("/ops/audit-copies", requireAdmin({ permission: "ops.view" }), (req, res) => {
  res.json({ copies: backup.listAuditCopies(30) });
});

router.post("/ops/audit-copy", requireAdmin({ permission: "ops.manage" }), heavyLimit, (req, res) => {
  const result = backup.createAuditCopy("manual", `admin:${req.admin.email}`);
  if (!result.ok) return clientError(res, `The audit copy failed: ${result.error}`, "copy-failed", 500);

  res.json({ ok: true, ...result });
});

function sendAuditCopy(req, res, withManifest) {
  const fullPath = backup.auditCopyPathFor(text(req.params.file, 120));
  if (!fullPath) return clientError(res, "That audit copy is not available.", "not-found", 404);

  const target = withManifest ? `${fullPath}.manifest.json` : fullPath;
  if (!fs.existsSync(target)) return clientError(res, "That file is not available.", "not-found", 404);

  audit.recordAccess(req.admin, `downloaded ${path.basename(target)}`, { always: true });

  res.setHeader("X-Content-Type-Options", "nosniff");
  res.download(target, safeFileName(path.basename(target)));
}

router.get("/ops/audit-copies/:file", requireAdmin({ permission: "audit.export", stepUp: true }), (req, res) => {
  sendAuditCopy(req, res, false);
});

router.get("/ops/audit-copies/:file/manifest", requireAdmin({ permission: "audit.export", stepUp: true }), (req, res) => {
  sendAuditCopy(req, res, true);
});

module.exports = router;
