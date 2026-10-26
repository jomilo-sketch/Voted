/*
  BOUESTI Vote — operations: monitoring, go-live readiness, incidents,
  and students' problem reports.

  This is the software half of the election-day procedure written up in
  docs/OPERATIONS.md. It does three jobs:

    health()      what an operator watches DURING voting: is the server
                  healthy, are students being locked out or not receiving
                  codes, are backups and restoration drills succeeding, is
                  the audit log still intact? Returns plain-language alerts.

    readiness()   the go-live checklist. The election cannot be switched
                  from rehearsal to live until every REQUIRED item passes,
                  including four confirmations that only people can give
                  (key custody, roster checked, students told, incident
                  contacts agreed).

    incidents     a simple log of things that went wrong and what was done,
                  so the post-election review has a record.

  Nothing here changes a ballot or reads a ballot choice.
*/

"use strict";

const fs = require("fs");
const d = require("./db");
const config = require("./config");
const keys = require("./keys");
const audit = require("./audit");
const election = require("./election");
const admins = require("./admins");
const sessions = require("./sessions");
const ratelimit = require("./ratelimit");
const backup = require("./backup");
const mailer = require("./mailer");
const voters = require("./voters");

const SEVERITIES = ["low", "medium", "high", "critical"];
const INCIDENT_STATUSES = ["open", "investigating", "resolved"];

const MIN = 60 * 1000;
const HOUR = 60 * MIN;

/* ---------- small helpers ---------- */

function ageMs(iso) {
  const ms = Date.parse(iso || "");
  return Number.isFinite(ms) ? Date.now() - ms : Infinity;
}

function minutesText(ms) {
  if (!Number.isFinite(ms)) return "never";
  const minutes = Math.round(ms / MIN);
  if (minutes < 1) return "less than a minute ago";
  if (minutes < 120) return `${minutes} minute${minutes === 1 ? "" : "s"} ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${hours} hours ago`;
  return `${Math.round(hours / 24)} days ago`;
}

function megabytes(bytes) {
  return Math.round((bytes / (1024 * 1024)) * 10) / 10;
}

/* Count audit entries of one category whose text matches any pattern, in a
   recent window. Looks only at the newest 100,000 rows so the cost stays
   flat however long the election runs. */
function countRecent(category, patterns, sinceMs) {
  const since = new Date(Date.now() - sinceMs).toISOString();
  const floor = Math.max(0, audit.head().id - 100_000);
  const clause = patterns.map(() => "message LIKE ?").join(" OR ");

  return d.get(
    `SELECT COUNT(*) AS n FROM audit_log
     WHERE category = ? AND id > ? AND occurredAt > ? AND (${clause})`,
    category, floor, since, ...patterns
  ).n;
}

/* ---------- cached integrity checks (expensive on a big log) ---------- */

const cache = { chain: null, integrity: null };

function chainStatus({ maxAgeMs = 5 * MIN, force = false } = {}) {
  if (!force && cache.chain && Date.now() - cache.chain.checkedAtMs < maxAgeMs) return cache.chain;

  const started = Date.now();
  const result = audit.verify();
  const wasOk = cache.chain ? cache.chain.ok : true;

  const problems = [...result.checkpointProblems];

  if (!result.chain.ok) {
    problems.unshift(`Entry ${result.chain.brokenAtId}: ${result.chain.reason}.`);
  }

  cache.chain = {
    ok: result.ok,
    checkedAt: d.nowIso(),
    checkedAtMs: Date.now(),
    durationMs: Date.now() - started,
    entries: result.chain.count,
    checkpointsChecked: result.checkpointsChecked,
    problems: problems.slice(0, 10)
  };

  if (!result.ok && wasOk) {
    audit.append("system", "security", "Audit-log verification FAILED: the record may have been altered or damaged");
  }

  return cache.chain;
}

function integrityStatus({ maxAgeMs = 10 * MIN, force = false } = {}) {
  if (!force && cache.integrity && Date.now() - cache.integrity.checkedAtMs < maxAgeMs) return cache.integrity;

  const result = d.integrityCheck();

  cache.integrity = {
    ok: result.ok,
    checkedAt: d.nowIso(),
    checkedAtMs: Date.now(),
    messages: result.messages.slice(0, 5),
    foreignKeyViolations: result.foreignKeyViolations
  };

  return cache.integrity;
}

/* ---------- health (what an operator watches during voting) ---------- */

function databaseFiles() {
  const size = (file) => {
    try {
      return fs.statSync(file).size;
    } catch (error) {
      return 0;
    }
  };

  return { databaseBytes: size(config.DB_PATH), walBytes: size(`${config.DB_PATH}-wal`) };
}

function hourlyTurnout() {
  const rows = d.all("SELECT hour, count FROM turnout_hourly ORDER BY hour DESC LIMIT 24").reverse();
  const thisHour = new Date().toISOString().slice(0, 13);
  const previousHour = new Date(Date.now() - HOUR).toISOString().slice(0, 13);

  const countFor = (hour) => {
    const row = rows.find((entry) => entry.hour === hour);
    return row ? row.count : 0;
  };

  return {
    recent: rows.map((row) => ({ hour: row.hour, voted: row.count })),
    thisHour: countFor(thisHour),
    previousHour: countFor(previousHour)
  };
}

function buildAlerts(facts) {
  const alerts = [];
  const add = (level, code, message) => alerts.push({ level, code, message });

  if (!facts.chain.ok) {
    add("critical", "audit-chain", "The audit log failed verification. Stop, do not publish results, and open an incident.");
  }

  if (!facts.integrity.ok) {
    add("critical", "database-integrity", "The database reported a consistency problem. Restore from the latest backup after an incident review.");
  }

  const open = facts.election.open;
  const backupGrace = Math.max(2 * config.BACKUP_INTERVAL_MIN, 60) * MIN;
  const lastBackupAge = facts.backups.lastBackup ? ageMs(facts.backups.lastBackup.finishedAt || facts.backups.lastBackup.startedAt) : Infinity;

  if (facts.backups.lastFailedBackup && (!facts.backups.lastBackup || facts.backups.lastFailedBackup.id > facts.backups.lastBackup.id)) {
    add("critical", "backup-failed", "The latest backup attempt FAILED. Check disk space and the audit log, then run a manual backup.");
  } else if (open && lastBackupAge > backupGrace) {
    // Only a LIVE election escalates to critical; a rehearsal just gets a nudge.
    const level = lastBackupAge > 2 * backupGrace && facts.election.mode === "live" ? "critical" : "warning";

    add(
      level, "backup-stale",
      facts.backups.lastBackup
        ? `The last successful backup was ${minutesText(lastBackupAge)}.`
        : "No backup has been made yet. Run one from the Operations page."
    );
  }

  if (facts.backups.lastDrill && facts.backups.lastDrill.status === "fail") {
    add("critical", "drill-failed", "The last restoration drill FAILED, so the backups may not be restorable. Investigate now.");
  } else if (open && facts.backups.lastPassingDrill && ageMs(facts.backups.lastPassingDrill.startedAt) > 2 * config.DRILL_INTERVAL_MIN * MIN) {
    add("warning", "drill-stale", "No passing restoration drill for a long time. Run one from the Operations page.");
  }

  const disk = facts.backups.disk;
  if (disk) {
    const freeShare = disk.totalBytes ? disk.freeBytes / disk.totalBytes : 1;
    if (disk.freeBytes < 100 * 1024 * 1024) add("critical", "disk-critical", `Only ${megabytes(disk.freeBytes)} MB of disk space is left. Backups and votes will start failing.`);
    else if (disk.freeBytes < 1024 * 1024 * 1024 || freeShare < 0.1) add("warning", "disk-low", `Disk space is running low (${megabytes(disk.freeBytes)} MB free).`);
  }

  if (facts.traffic.mailFailures15m >= 3) {
    add("warning", "mail-failing", `${facts.traffic.mailFailures15m} verification e-mails failed to send in the last 15 minutes. Students may not be receiving codes — check the mail service and tell students.`);
  }

  if (facts.traffic.rateLimitTrips1h >= 10) {
    add("warning", "rate-limits", `${facts.traffic.rateLimitTrips1h} rate-limit blocks in the last hour. If many real students are affected, check that TRUST_PROXY is set correctly behind the proxy.`);
  }

  if (facts.traffic.adminFailures1h >= 10) {
    add("warning", "admin-failures", `${facts.traffic.adminFailures1h} failed administrator sign-ins in the last hour. Possible guessing attack.`);
  }

  if (facts.traffic.voterWrongPassword1h >= 100) {
    add("warning", "voter-guessing", `${facts.traffic.voterWrongPassword1h} wrong student passwords in the last hour. Students may be mistyping, or someone is probing.`);
  }

  if (facts.reports.unhandled > 0) {
    add("warning", "student-reports", `${facts.reports.unhandled} student problem report${facts.reports.unhandled === 1 ? "" : "s"} waiting to be read.`);
  }

  if (facts.incidents.serious > 0) {
    add("warning", "incidents", `${facts.incidents.serious} high or critical incident${facts.incidents.serious === 1 ? " is" : "s are"} still open.`);
  }

  if ((open || facts.election.opensByItself) && !config.ENABLE_SCHEDULERS) {
    add(
      "warning", "schedulers-off",
      facts.election.opensByItself
        ? "Background schedulers are disabled, so voting will NOT open by itself at the scheduled time (and there are no automatic backups or drills)."
        : "Background schedulers are disabled: no automatic backups, drills or scheduled closing."
    );
  }

  if (facts.election.opensByItself) {
    const opensAt = Date.parse(facts.election.votingOpensAt);
    const closesAtTime = facts.election.votingClosesAt ? Date.parse(facts.election.votingClosesAt) : null;

    if (opensAt > Date.now()) {
      add("info", "opening-scheduled", `Voting will open by itself at ${facts.election.votingOpensAt} (UTC).`);
    } else if (Date.now() - opensAt > 2 * MIN) {
      add(
        "warning", "opening-missed",
        closesAtTime && closesAtTime <= Date.now()
          ? "The scheduled opening time passed and so did the closing time, so voting never opened. Set new times, or press Active."
          : "The scheduled opening time has passed but voting has not opened. Check that at least one position has an approved candidate, or press Active."
      );
    }
  }

  const closesAt = facts.election.votingClosesAt ? Date.parse(facts.election.votingClosesAt) : null;
  if (open && closesAt && closesAt - Date.now() < 30 * MIN && closesAt > Date.now()) {
    add("info", "closing-soon", `Voting is scheduled to close in ${Math.max(1, Math.round((closesAt - Date.now()) / MIN))} minute(s).`);
  }

  if (facts.election.mode === "rehearsal") {
    add("info", "rehearsal", "Rehearsal mode: test data only. The election is not live.");
  }

  return alerts;
}

function health() {
  const current = election.getElection();
  const state = election.votingState();
  const memory = process.memoryUsage();
  const files = databaseFiles();
  const counts = voters.studentCounts();
  const backupState = backup.status();

  const facts = {
    election: {
      name: current.electionName,
      status: current.status,
      mode: current.mode,
      rosterMode: current.rosterMode,
      votingOpensAt: current.votingOpensAt,
      votingClosesAt: current.votingClosesAt,
      opensByItself: election.opensByItself(current),
      open: state.open
    },

    chain: chainStatus(),
    integrity: integrityStatus(),
    backups: backupState,

    traffic: {
      rateLimitBlocksNow: ratelimit.currentlyBlocked(),
      rateLimitTrips1h: countRecent("security", ["Rate limit %"], HOUR),
      adminFailures1h: admins.recentFailureCount(HOUR),
      voterWrongPassword1h: countRecent("voter", ["Failed sign-in for %: wrong password"], HOUR),
      otpWrong1h: countRecent("voter", ["% entered a wrong verification code%", "% wrong codes; the code was cancelled"], HOUR),
      mailFailures15m: countRecent("system", ["Could not send a verification e-mail%"], 15 * MIN)
    },

    reports: {
      unhandled: d.get("SELECT COUNT(*) AS n FROM student_reports WHERE status = 'new'").n
    },

    incidents: {
      open: d.get("SELECT COUNT(*) AS n FROM incidents WHERE status != 'resolved'").n,
      serious: d.get("SELECT COUNT(*) AS n FROM incidents WHERE status != 'resolved' AND severity IN ('high', 'critical')").n
    }
  };

  const alerts = buildAlerts(facts);
  const rank = { critical: 3, warning: 2, info: 1 };
  alerts.sort((a, b) => rank[b.level] - rank[a.level]);

  const worst = alerts.reduce((level, alert) => Math.max(level, rank[alert.level]), 0);

  return {
    generatedAt: d.nowIso(),
    overall: worst >= 3 ? "critical" : worst === 2 ? "attention" : "ok",
    alerts,

    server: {
      uptimeSec: Math.round(process.uptime()),
      node: process.version,
      environment: config.NODE_ENV,
      otpMode: config.OTP_MODE,
      cookiesSecure: config.COOKIE_SECURE,
      schedulers: config.ENABLE_SCHEDULERS,
      memoryMb: { rss: megabytes(memory.rss), heapUsed: megabytes(memory.heapUsed) }
    },

    election: facts.election,

    turnout: {
      voted: counts.voted,
      registered: counts.registered,
      verified: counts.verified,
      activeRoster: counts.active,
      ...hourlyTurnout()
    },

    sessions: sessions.activeCounts(),

    traffic: facts.traffic,

    database: {
      bytes: files.databaseBytes,
      walBytes: files.walBytes,
      integrity: facts.integrity
    },

    audit: {
      entries: d.get("SELECT COUNT(*) AS n FROM audit_log").n,
      headId: audit.head().id,
      checkpoints: d.get("SELECT COUNT(*) AS n FROM audit_checkpoints").n,
      chain: facts.chain
    },

    backups: {
      lastBackup: backupState.lastBackup,
      lastDrill: backupState.lastDrill,
      lastPassingDrill: backupState.lastPassingDrill,
      lastAuditCopy: backupState.lastAuditCopy,
      files: backupState.backupFiles,
      bytes: backupState.backupBytes,
      disk: backupState.disk,
      intervals: backupState.intervals,
      mirrorConfigured: backupState.mirrorConfigured
    },

    reports: facts.reports,
    incidents: facts.incidents
  };
}

/* ---------- go-live confirmations (only people can give these) ---------- */

const CONFIRMATIONS = {
  keyCustody: "The master key is saved in at least two secure places, held by different officers (see docs/OPERATIONS.md, \"Key custody\").",
  rosterVerified: "The voter roster has been checked against the official student list and corrected.",
  studentsNotified: "Students have been told the voting dates, the web address, how the e-mail code works and where to report problems.",
  incidentContacts: "Every officer holds the printed incident contact list and knows who decides to pause or extend voting."
};

function readConfirmations() {
  try {
    return JSON.parse(d.getMeta("golive_confirmations") || "{}");
  } catch (error) {
    return {};
  }
}

function confirmations() {
  const stored = readConfirmations();

  return Object.entries(CONFIRMATIONS).map(([key, label]) => ({
    key,
    label,
    confirmed: Boolean(stored[key]),
    by: stored[key] ? stored[key].by : null,
    at: stored[key] ? stored[key].at : null
  }));
}

function setConfirmation(key, confirmed, admin) {
  if (!CONFIRMATIONS[key]) return { ok: false, error: "Unknown confirmation." };

  const current = election.getElection();
  if (current.mode === "live") return { ok: false, error: "The election is already live." };

  const stored = readConfirmations();

  if (confirmed) stored[key] = { by: admin.email, at: d.nowIso() };
  else delete stored[key];

  d.tx(() => {
    d.setMeta("golive_confirmations", JSON.stringify(stored));
    audit.append(audit.adminActor(admin), "ops", `Go-live item ${confirmed ? "confirmed" : "un-confirmed"}: ${key}`);
  });

  return { ok: true, confirmations: confirmations() };
}

/* ---------- the go-live checklist ---------- */

function smtpSignature() {
  return keys.sha256Hex(
    [config.SMTP_HOST, config.SMTP_PORT, config.SMTP_SECURE, config.SMTP_STARTTLS, config.SMTP_USER, config.SMTP_FROM].join("|")
  );
}

function readiness() {
  const current = election.getElection();
  const checks = [];

  const add = (id, label, required, ok, detail, fix = "") => {
    checks.push({ id, label, required, ok: Boolean(ok), detail, fix });
  };

  /* --- configuration of the server --- */

  add(
    "production-mode", "Server runs in production mode", true,
    config.PRODUCTION,
    config.PRODUCTION ? "NODE_ENV=production." : `NODE_ENV is "${config.NODE_ENV}".`,
    "Start the server with NODE_ENV=production."
  );

  add(
    "cookies-secure", "Session cookies are Secure (HTTPS)", true,
    config.COOKIE_SECURE,
    config.COOKIE_SECURE ? "Cookies are marked Secure and HttpOnly with SameSite=Strict." : "Cookies are not marked Secure.",
    "Serve the site over HTTPS (TLS_KEY_FILE / TLS_CERT_FILE, or an HTTPS reverse proxy) and leave COOKIE_SECURE unset."
  );

  add(
    "otp-mode", "Verification codes are e-mailed to students", true,
    config.OTP_MODE === "smtp",
    config.OTP_MODE === "smtp"
      ? "OTP_MODE=smtp: each code is random and sent to the student's university mailbox."
      : `OTP_MODE=${config.OTP_MODE}. ${config.OTP_MODE === "demo" ? "Anyone can use code 123456." : "Codes are printed on the server console, not e-mailed."}`,
    "Set OTP_MODE=smtp and the SMTP_* settings."
  );

  const testedAt = d.getMeta("smtp_test_ok_at");
  const testFresh = config.OTP_MODE === "smtp" && d.getMeta("smtp_test_sig") === smtpSignature() && ageMs(testedAt) < 72 * HOUR;

  add(
    "smtp-test", "A real test e-mail was delivered recently", true,
    testFresh,
    testFresh
      ? `Test e-mail accepted by the mail server ${minutesText(ageMs(testedAt))}.`
      : "No successful test e-mail with the current mail settings in the last 72 hours.",
    "Operations → Send a test e-mail, to a real mailbox, and confirm it arrives."
  );

  add(
    "schedulers", "Background schedulers are running", true,
    config.ENABLE_SCHEDULERS,
    config.ENABLE_SCHEDULERS ? "Automatic backups, drills, audit copies and scheduled open/close are on." : "ENABLE_SCHEDULERS is off.",
    "Remove ENABLE_SCHEDULERS=false."
  );

  /* --- the election itself --- */

  const roster = d.get(
    `SELECT COUNT(*) AS total,
            COALESCE(SUM(CASE WHEN active = 1 THEN 1 ELSE 0 END), 0) AS active,
            COALESCE(SUM(CASE WHEN active = 1 AND COALESCE(email, '') != '' THEN 1 ELSE 0 END), 0) AS withEmail
     FROM students`
  );

  add(
    "roster-loaded", "Voter roster is loaded", true,
    roster.withEmail > 0,
    `${roster.active} active student(s), ${roster.withEmail} with a university e-mail on file.`,
    "Voters/Students → Import the roster (matric, name, university e-mail)."
  );

  add(
    "roster-emails", "Every active student has a university e-mail on file", false,
    roster.active > 0 && roster.withEmail === roster.active,
    roster.active === roster.withEmail
      ? "All active students have an e-mail address."
      : `${roster.active - roster.withEmail} active student(s) have no e-mail and will be unable to vote in a live election.`,
    "Re-import those students with an e-mail address, or deactivate them."
  );

  const structure = election.getBallotStructure();

  add(
    "ballot", "At least one position has an approved candidate", true,
    structure.length > 0,
    `${structure.length} position(s) on the ballot.`,
    "Candidates → add positions and approve candidates."
  );

  const unopposed = structure.filter((office) => office.candidates.length < 2).map((office) => office.office);

  add(
    "ballot-contested", "Every position has at least two candidates", false,
    unopposed.length === 0,
    unopposed.length === 0 ? "All positions are contested." : `Only one candidate: ${unopposed.join(", ")}.`,
    "Fine if the position is deliberately unopposed."
  );

  /* --- people and accounts --- */

  const staff = d.all("SELECT email, role, mustChangePassword, totpEnabled FROM admins WHERE disabled = 0");
  const unsecured = staff.filter((row) => row.mustChangePassword || !row.totpEnabled);

  add(
    "admins-secured", "Every administrator has set a password and enrolled 2FA", true,
    staff.length > 0 && unsecured.length === 0,
    unsecured.length === 0
      ? `${staff.length} administrator(s), all secured.`
      : `Not finished: ${unsecured.map((row) => row.email).join(", ")}.`,
    "Each person signs in once, chooses a password and scans the 2FA secret."
  );

  const hasRole = (role) => staff.some((row) => row.role === role);

  add(
    "officers", "An active Electoral Officer and Results Officer exist", true,
    hasRole("electoral_officer") && hasRole("results_officer"),
    "Results need two different people: the Results Officer prepares, the Electoral Officer approves.",
    "Administrators → create the missing role."
  );

  add(
    "tech-officer", "A Technical Support Officer exists", false,
    hasRole("technical_support"),
    hasRole("technical_support") ? "Present." : "Nobody holds the backup and monitoring duties.",
    "Administrators → create a Technical Support Officer."
  );

  /* --- recovery --- */

  const backupState = backup.status();
  const backupGrace = Math.max(2 * config.BACKUP_INTERVAL_MIN, 60) * MIN;
  const lastBackupAge = backupState.lastBackup ? ageMs(backupState.lastBackup.finishedAt || backupState.lastBackup.startedAt) : Infinity;

  add(
    "backup-recent", "A recent encrypted backup exists", true,
    lastBackupAge <= backupGrace,
    backupState.lastBackup ? `Last backup ${minutesText(lastBackupAge)}.` : "No backup has been made yet.",
    "Operations → Back up now."
  );

  const lastDrill = backupState.lastDrill;
  const drillFresh = Boolean(lastDrill) && lastDrill.status === "pass" && ageMs(lastDrill.startedAt) <= 24 * HOUR;

  add(
    "drill-recent", "The latest restoration drill passed (last 24 hours)", true,
    drillFresh,
    !lastDrill ? "No restoration drill has been run." : `Latest drill ${lastDrill.status === "pass" ? "passed" : "FAILED"} ${minutesText(ageMs(lastDrill.startedAt))}.`,
    "Operations → Test a restore now. A backup that has never been restored is untested."
  );

  const chain = chainStatus({ force: true });

  add(
    "audit-chain", "The audit log verifies", true,
    chain.ok,
    chain.ok ? "Hash chain and signed checkpoints are intact." : chain.problems.join(" "),
    "Open an incident. Do not go live."
  );

  const integrity = integrityStatus({ force: true });

  add(
    "database-integrity", "The database passes its integrity check", true,
    integrity.ok,
    integrity.ok ? "SQLite integrity check: ok." : integrity.messages.join(" "),
    "Restore from backup after an incident review."
  );

  const disk = backupState.disk;

  add(
    "disk", "Enough free disk space (1 GB or more)", false,
    !disk || disk.freeBytes >= 1024 * 1024 * 1024,
    disk ? `${megabytes(disk.freeBytes)} MB free.` : "Could not be measured on this system.",
    "Free space or move the data folder to a larger disk."
  );

  add(
    "mirror", "Backups are also copied to a second location", false,
    backupState.mirrorConfigured,
    backupState.mirrorConfigured ? `Mirror: ${config.BACKUP_MIRROR_DIR}` : "Backups exist only on this machine.",
    "Set BACKUP_MIRROR_DIR to a USB drive or network share."
  );

  add(
    "trust-proxy", "Client addresses are seen correctly behind a proxy", false,
    !(config.COOKIE_SECURE && config.HOST === "127.0.0.1" && !config.TRUST_PROXY && !config.TLS_KEY_FILE),
    config.TRUST_PROXY ? `TRUST_PROXY=${config.TRUST_PROXY}.` : "TRUST_PROXY is not set.",
    "Behind nginx on the same machine set TRUST_PROXY=loopback, or every student appears to come from one address and shares one rate limit."
  );

  add(
    "voter-password", "Shared student password is not the published default", false,
    config.VOTER_PASSWORD !== "password1",
    config.VOTER_PASSWORD === "password1"
      ? "Every student signs in with the same password (password1). That is a Committee decision; the e-mail code is the real protection."
      : "A custom shared password is configured.",
    "Optional: set VOTER_PASSWORD."
  );

  /* --- people-only confirmations --- */

  confirmations().forEach((item) => {
    add(`confirm-${item.key}`, item.label, true, item.confirmed, item.confirmed ? `Confirmed by ${item.by}.` : "Not yet confirmed.", "Tick this box on the Operations page once it is true.");
  });

  const blockers = checks.filter((check) => check.required && !check.ok);

  return {
    mode: current.mode,
    ready: current.mode === "rehearsal" && blockers.length === 0,
    alreadyLive: current.mode === "live",
    blockers: blockers.map((check) => ({ id: check.id, label: check.label })),
    checks,
    confirmations: confirmations()
  };
}

/* ---------- test e-mail ---------- */

async function sendTestMail(toInput, admin) {
  const to = String(toInput ?? "").trim().toLowerCase();
  if (!admins.EMAIL_PATTERN.test(to)) return { ok: false, error: "Enter a valid e-mail address to send the test to." };

  try {
    const result = await mailer.send({
      to,
      subject: "BOUESTI Vote — test message",
      text:
        "This is a test message from the BOUESTI Vote server.\n\n" +
        "If you can read this, the server can deliver verification codes. No action is needed."
    });

    if (result.via === "smtp") {
      d.setMeta("smtp_test_ok_at", d.nowIso());
      d.setMeta("smtp_test_sig", smtpSignature());
      audit.append(audit.adminActor(admin), "ops", "Test e-mail accepted by the mail server");
      return { ok: true, via: "smtp", message: `The mail server accepted the test message for ${to}. Check that it arrives.` };
    }

    return {
      ok: true,
      via: result.via,
      message: `OTP_MODE=${config.OTP_MODE}: no real e-mail was sent. Set OTP_MODE=smtp to test delivery.`
    };
  } catch (error) {
    audit.append(audit.adminActor(admin), "ops", "Test e-mail FAILED");
    return { ok: false, error: `The mail server could not be reached or refused the message: ${String(error.message).slice(0, 200)}` };
  }
}

/* ---------- incidents ---------- */

function cleanText(value, min, max, label) {
  const text = String(value ?? "").replace(/[ \t]+/g, " ").replace(/\r/g, "").trim();
  if (text.length < min || text.length > max) return { error: `${label} must be ${min}–${max} characters.` };
  return { value: text };
}

/* Incident text is free-form and may mention a student, so it is kept in
   the incidents table only — the audit log records just that an incident
   existed and how it changed. */
function openIncident({ severity, title, details }, admin) {
  if (!SEVERITIES.includes(severity)) return { ok: false, error: "Choose a severity: low, medium, high or critical." };

  const cleanTitle = cleanText(title, 5, 120, "The title");
  const cleanDetails = cleanText(details || "", 0, 2000, "The details");
  if (cleanTitle.error || cleanDetails.error) return { ok: false, error: cleanTitle.error || cleanDetails.error };

  const id = d.tx(() => {
    const result = d.run(
      "INSERT INTO incidents (openedAt, openedBy, severity, title, details) VALUES (?, ?, ?, ?, ?)",
      d.nowIso(), admin.email, severity, cleanTitle.value, cleanDetails.value
    );

    const incidentId = Number(result.lastInsertRowid);
    audit.append(audit.adminActor(admin), "incident", `Incident #${incidentId} opened (${severity})`);
    return incidentId;
  });

  return { ok: true, id };
}

function updateIncident(id, { status, resolution, details }, admin) {
  const incident = d.get("SELECT * FROM incidents WHERE id = ?", Number(id));
  if (!incident) return { ok: false, error: "Incident not found." };

  const nextStatus = status === undefined ? incident.status : status;
  if (!INCIDENT_STATUSES.includes(nextStatus)) return { ok: false, error: "Choose open, investigating or resolved." };

  let nextResolution = incident.resolution;
  let nextDetails = incident.details;

  if (resolution !== undefined) {
    const cleaned = cleanText(resolution, 0, 2000, "The resolution");
    if (cleaned.error) return { ok: false, error: cleaned.error };
    nextResolution = cleaned.value;
  }

  if (details !== undefined) {
    const cleaned = cleanText(details, 0, 2000, "The details");
    if (cleaned.error) return { ok: false, error: cleaned.error };
    nextDetails = cleaned.value;
  }

  if (nextStatus === "resolved" && nextResolution.length < 5) {
    return { ok: false, error: "Say briefly how it was resolved before closing the incident." };
  }

  const resolving = nextStatus === "resolved" && incident.status !== "resolved";

  d.tx(() => {
    d.run(
      `UPDATE incidents SET status = ?, resolution = ?, details = ?,
         resolvedAt = ?, resolvedBy = ? WHERE id = ?`,
      nextStatus, nextResolution, nextDetails,
      nextStatus === "resolved" ? (resolving ? d.nowIso() : incident.resolvedAt) : null,
      nextStatus === "resolved" ? (resolving ? admin.email : incident.resolvedBy) : null,
      incident.id
    );

    audit.append(
      audit.adminActor(admin), "incident",
      `Incident #${incident.id} ${nextStatus !== incident.status ? `moved to ${nextStatus}` : "updated"}`
    );
  });

  return { ok: true };
}

function listIncidents({ status } = {}) {
  const rows = INCIDENT_STATUSES.includes(status)
    ? d.all("SELECT * FROM incidents WHERE status = ? ORDER BY id DESC LIMIT 200", status)
    : d.all("SELECT * FROM incidents ORDER BY id DESC LIMIT 200");

  return rows;
}

/* ---------- students' problem reports ---------- */

function listStudentReports({ status } = {}) {
  const rows = ["new", "seen", "resolved"].includes(status)
    ? d.all("SELECT * FROM student_reports WHERE status = ? ORDER BY id DESC LIMIT 300", status)
    : d.all("SELECT * FROM student_reports ORDER BY id DESC LIMIT 300");

  return rows;
}

function handleStudentReport(id, status, admin) {
  if (!["new", "seen", "resolved"].includes(status)) return { ok: false, error: "Choose new, seen or resolved." };

  const row = d.get("SELECT id FROM student_reports WHERE id = ?", Number(id));
  if (!row) return { ok: false, error: "Report not found." };

  d.tx(() => {
    d.run(
      "UPDATE student_reports SET status = ?, handledBy = ?, handledAt = ? WHERE id = ?",
      status, status === "new" ? null : admin.email, status === "new" ? null : d.nowIso(), row.id
    );
    audit.append(audit.adminActor(admin), "ops", `Student problem report #${row.id} marked ${status}`);
  });

  return { ok: true };
}

module.exports = {
  SEVERITIES,
  INCIDENT_STATUSES,
  CONFIRMATIONS,
  chainStatus,
  integrityStatus,
  health,
  readiness,
  confirmations,
  setConfirmation,
  sendTestMail,
  openIncident,
  updateIncident,
  listIncidents,
  listStudentReports,
  handleStudentReport
};
