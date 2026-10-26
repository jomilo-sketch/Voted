/*
  BOUESTI Vote — administrator routes for running the election: dashboard
  summary, election details, candidates, announcements, the voter roster
  and statistics, student problem reports, and incidents.

  Every route names the permission it needs (permissions.js). Sensitive
  actions also need a fresh two-factor confirmation ("step-up").
*/

"use strict";

const express = require("express");
const audit = require("./audit");
const election = require("./election");
const voters = require("./voters");
const ops = require("./ops");
const backup = require("./backup");
const { can } = require("./permissions");
const { requireAdmin, requireStepUp } = require("./middleware");
const { sendFailure, reply, clientError, idParam, text, bool, csvLine, sendDownload } = require("./http");

const router = express.Router();

function phaseOf(current) {
  const state = election.votingState();
  return state.open ? "open" : state.reason;
}

function electionView() {
  const current = election.getElection();

  return {
    name: current.electionName,
    school: current.schoolName,
    status: current.status, // what the officer set: upcoming | active | closed
    phase: phaseOf(current), // what voters experience: upcoming | open | closed
    mode: current.mode,
    rosterMode: current.rosterMode,
    votingOpensAt: current.votingOpensAt,
    votingClosesAt: current.votingClosesAt,
    opensByItself: election.opensByItself(current), // upcoming, and the server will open it at votingOpensAt
    openedAt: current.openedAt,
    closedAt: current.closedAt,
    wentLiveAt: current.wentLiveAt,
    resultsPublished: Boolean(current.resultsPublished),
    updatedAt: current.updatedAt,
    updatedBy: current.updatedBy
  };
}

/* ------------------------------------------------------------------ */
/* Dashboard                                                            */
/* ------------------------------------------------------------------ */

router.get("/dashboard", requireAdmin({ permission: "election.view", passive: true }), (req, res) => {
  const counts = voters.studentCounts();
  const offices = election.getOffices();
  const rosterMode = election.getElection().rosterMode;

  const body = {
    election: electionView(),
    counts: {
      ...counts,
      turnoutPercent: rosterMode === "closed" && counts.active > 0 ? Math.round((counts.voted / counts.active) * 1000) / 10 : null
    },
    structure: {
      positions: offices.length,
      candidates: offices.reduce((sum, office) => sum + office.candidates.length, 0),
      lock: election.structureLock()
    },
    announcement: election.latestAnnouncement()
  };

  if (can(req.admin.role, "ops.view")) {
    const health = ops.health();
    body.health = { overall: health.overall, alerts: health.alerts.filter((alert) => alert.level !== "info").slice(0, 5) };
  }

  res.json(body);
});

/* Recent operational events for the home page. Routine voter and sign-in
   traffic is left out; reading this is itself logged (once a minute at most). */
const FEED_HIDDEN = new Set(["voter", "voting", "auth", "audit-access"]);

router.get("/activity", requireAdmin({ permission: "audit.view" }), (req, res) => {
  audit.recordAccess(req.admin, "viewed the recent-activity feed");

  const entries = audit
    .list({ limit: 150 })
    .filter((entry) => !FEED_HIDDEN.has(entry.category))
    .slice(0, 12)
    .map(({ id, occurredAt, actor, category, message }) => ({ id, occurredAt, actor, category, message }));

  res.json({ entries });
});

/* ------------------------------------------------------------------ */
/* Election details, status, mode                                       */
/* ------------------------------------------------------------------ */

router.get("/election", requireAdmin({ permission: "election.view" }), (req, res) => {
  res.json({
    election: electionView(),
    lock: election.structureLock(),
    offices: election.getOffices(),
    announcements: election.listAnnouncements(10),
    ballotsCast: election.ballotCount()
  });
});

function changesStatus(req) {
  return req.body.status !== undefined && req.body.status !== election.getElection().status;
}

router.put(
  "/election",
  requireAdmin({ permission: "election.manage" }),
  (req, res, next) => (changesStatus(req) ? requireStepUp(req, res, next) : next()),
  (req, res) => {
    const result = election.updateElection(
      {
        electionName: req.body.electionName === undefined ? undefined : text(req.body.electionName, 200),
        status: req.body.status === undefined ? undefined : text(req.body.status, 20),
        votingOpensAt: req.body.votingOpensAt === undefined ? undefined : req.body.votingOpensAt === null ? null : text(req.body.votingOpensAt, 40),
        votingClosesAt: req.body.votingClosesAt === undefined ? undefined : req.body.votingClosesAt === null ? null : text(req.body.votingClosesAt, 40)
      },
      req.admin
    );

    if (!result.ok) return sendFailure(res, result, 409);
    res.json({ ok: true, election: electionView(), notice: result.notice || null });
  }
);

router.put(
  "/settings",
  requireAdmin({ permission: "settings.manage" }),
  (req, res, next) => {
    const changing = req.body.rosterMode !== undefined && req.body.rosterMode !== election.getElection().rosterMode;
    return changing ? requireStepUp(req, res, next) : next();
  },
  (req, res) => {
    const result = election.updateSettings(
      {
        schoolName: req.body.schoolName === undefined ? undefined : text(req.body.schoolName, 200),
        rosterMode: req.body.rosterMode === undefined ? undefined : text(req.body.rosterMode, 10)
      },
      req.admin
    );

    if (!result.ok) return sendFailure(res, result, 409);
    res.json({ ok: true, election: electionView() });
  }
);

/* The one-way door. Refused unless the readiness checklist is complete. */
router.post("/go-live", requireAdmin({ permission: "mode.manage", stepUp: true }), (req, res) => {
  if (text(req.body.phrase, 20).trim().toUpperCase() !== "GO LIVE") {
    return clientError(res, 'Type GO LIVE to confirm.', "confirm-phrase");
  }

  const readiness = ops.readiness();

  if (readiness.alreadyLive) return clientError(res, "This election is already live.", "already-live", 409);

  if (!readiness.ready) {
    return res.status(409).json({
      error: "The go-live checklist is not complete.",
      code: "not-ready",
      blockers: readiness.blockers
    });
  }

  const actor = audit.adminActor(req.admin);

  // A rollback point, taken before anything is wiped.
  const before = backup.createBackup("pre-live", actor);
  if (!before.ok) return clientError(res, `A safety backup could not be made, so nothing was changed: ${before.error}`, "backup-failed", 500);

  const result = election.goLive(req.admin);
  if (!result.ok) return sendFailure(res, result, 409);

  backup.createBackup("post-live", actor);

  res.json({
    ok: true,
    removed: result.removed,
    message: "The election is now LIVE. Rehearsal data was wiped, the roster is closed, and voting is set to upcoming. Open voting when you are ready."
  });
});

router.post("/reset-rehearsal", requireAdmin({ permission: "mode.manage", stepUp: true }), (req, res) => {
  if (text(req.body.phrase, 20).trim().toUpperCase() !== "RESET") {
    return clientError(res, "Type RESET to confirm.", "confirm-phrase");
  }

  const result = election.resetRehearsal(req.admin);
  if (!result.ok) return sendFailure(res, result, 409);

  res.json({ ok: true, removed: result.removed });
});

/* ------------------------------------------------------------------ */
/* Positions and candidates                                             */
/* ------------------------------------------------------------------ */

router.post("/offices", requireAdmin({ permission: "election.manage" }), (req, res) => {
  const result = election.addOfficeWithCandidate(
    text(req.body.office, 120), text(req.body.candidate, 120), text(req.body.photoUrl, 450_000), req.admin
  );

  reply(res, result);
});

router.delete("/offices/:id", requireAdmin({ permission: "election.manage" }), (req, res) => {
  const id = idParam(req.params.id);
  if (!id) return clientError(res, "Position not found.", "not-found", 404);

  reply(res, election.removeOffice(id, req.admin));
});

router.post("/offices/:id/candidates", requireAdmin({ permission: "election.manage" }), (req, res) => {
  const id = idParam(req.params.id);
  if (!id) return clientError(res, "Position not found.", "not-found", 404);

  reply(res, election.addCandidate(id, text(req.body.name, 120), text(req.body.photoUrl, 450_000), req.admin));
});

router.post("/candidates/:id/toggle", requireAdmin({ permission: "election.manage" }), (req, res) => {
  const id = idParam(req.params.id);
  if (!id) return clientError(res, "Candidate not found.", "not-found", 404);

  reply(res, election.toggleCandidate(id, req.admin));
});

router.delete("/candidates/:id", requireAdmin({ permission: "election.manage" }), (req, res) => {
  const id = idParam(req.params.id);
  if (!id) return clientError(res, "Candidate not found.", "not-found", 404);

  reply(res, election.removeCandidate(id, req.admin));
});

/* ------------------------------------------------------------------ */
/* Announcements (the banner students see on the home page)              */
/* ------------------------------------------------------------------ */

router.get("/announcements", requireAdmin({ permission: "election.view" }), (req, res) => {
  res.json({ current: election.latestAnnouncement(), history: election.listAnnouncements(30) });
});

router.post("/announcements", requireAdmin({ permission: "announcements.manage" }), (req, res) => {
  reply(res, election.postAnnouncement(text(req.body.message, 1000), req.admin));
});

router.delete("/announcements/current", requireAdmin({ permission: "announcements.manage" }), (req, res) => {
  reply(res, election.clearAnnouncement(req.admin));
});

/* ------------------------------------------------------------------ */
/* Voter roster and statistics                                          */
/* ------------------------------------------------------------------ */

router.get("/students", requireAdmin({ permission: "voters.view" }), (req, res) => {
  const result = voters.listStudents({
    search: text(req.query.search, 80),
    filter: text(req.query.filter, 20),
    limit: Number(req.query.limit) || 200,
    offset: Number(req.query.offset) || 0
  });

  res.json({ ...result, counts: voters.studentCounts(), rosterMode: election.getElection().rosterMode });
});

router.get("/students/export.csv", requireAdmin({ permission: "voters.view", stepUp: true }), (req, res) => {
  const everyone = voters.allStudents();
  const lines = [csvLine(["matric", "name", "email", "registered", "verified", "voted", "active"])];

  everyone.forEach((student) => {
    lines.push(csvLine([
      student.matric, student.name, student.email,
      student.registered ? "yes" : "no", student.verified ? "yes" : "no",
      student.voted ? "yes" : "no", student.active ? "yes" : "no"
    ]));
  });

  audit.append(audit.adminActor(req.admin), "voters", `Exported the voter roster (${everyone.length} students)`);

  sendDownload(res, {
    fileName: "voter-roster.csv",
    contentType: "text/csv; charset=utf-8",
    body: `\ufeff${lines.join("\r\n")}\r\n`
  });
});

router.post("/students", requireAdmin({ permission: "voters.manage" }), (req, res) => {
  reply(res, voters.addStudent(
    { matric: text(req.body.matric, 40), name: text(req.body.name, 200), email: text(req.body.email, 200) },
    req.admin
  ));
});

router.post("/students/import", requireAdmin({ permission: "voters.manage", stepUp: true }), (req, res) => {
  let lines = req.body.lines;

  if (!Array.isArray(lines) && typeof req.body.csv === "string") {
    lines = req.body.csv.split(/\r?\n/);
  }

  if (!Array.isArray(lines) || lines.length === 0) {
    return clientError(res, "Choose a file or paste lines of: matric, name, email.", "no-lines");
  }

  if (lines.length > 20000) return clientError(res, "That is more than 20,000 lines. Split the file in two.", "too-many-lines");

  reply(res, voters.importStudents(lines.map((line) => text(line, 400)), req.admin));
});

function matricParam(req, res) {
  const matric = text(req.params.matric, 20);

  if (!/^\d{4,15}$/.test(matric)) {
    clientError(res, "Student not found.", "not-found", 404);
    return null;
  }

  return matric;
}

router.post("/students/:matric/toggle", requireAdmin({ permission: "voters.manage" }), (req, res) => {
  const matric = matricParam(req, res);
  if (matric) reply(res, voters.toggleStudent(matric, req.admin));
});

router.delete("/students/:matric", requireAdmin({ permission: "voters.manage", stepUp: true }), (req, res) => {
  const matric = matricParam(req, res);
  if (matric) reply(res, voters.removeStudent(matric, req.admin));
});

router.get("/statistics", requireAdmin({ permission: "stats.view", passive: true }), (req, res) => {
  res.json(voters.statistics());
});

/* ------------------------------------------------------------------ */
/* Students' problem reports                                            */
/* ------------------------------------------------------------------ */

router.get("/student-reports", requireAdmin({ permission: "reports.view" }), (req, res) => {
  res.json({ reports: ops.listStudentReports({ status: text(req.query.status, 12) }) });
});

router.post("/student-reports/:id", requireAdmin({ permission: "reports.manage" }), (req, res) => {
  const id = idParam(req.params.id);
  if (!id) return clientError(res, "Report not found.", "not-found", 404);

  reply(res, ops.handleStudentReport(id, text(req.body.status, 12), req.admin));
});

/* ------------------------------------------------------------------ */
/* Incidents                                                            */
/* ------------------------------------------------------------------ */

router.get("/incidents", requireAdmin({ permission: "incidents.view" }), (req, res) => {
  res.json({ incidents: ops.listIncidents({ status: text(req.query.status, 20) }), severities: ops.SEVERITIES });
});

router.post("/incidents", requireAdmin({ permission: "incidents.manage" }), (req, res) => {
  reply(res, ops.openIncident(
    { severity: text(req.body.severity, 12), title: text(req.body.title, 300), details: text(req.body.details, 4000) },
    req.admin
  ));
});

router.post("/incidents/:id", requireAdmin({ permission: "incidents.manage" }), (req, res) => {
  const id = idParam(req.params.id);
  if (!id) return clientError(res, "Incident not found.", "not-found", 404);

  reply(res, ops.updateIncident(
    id,
    {
      status: req.body.status === undefined ? undefined : text(req.body.status, 20),
      resolution: req.body.resolution === undefined ? undefined : text(req.body.resolution, 4000),
      details: req.body.details === undefined ? undefined : text(req.body.details, 4000)
    },
    req.admin
  ));
});

module.exports = router;
