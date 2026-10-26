/*
  BOUESTI Vote — background jobs.

  Everything the election needs to keep happening without someone pressing
  a button:

    every 15 s    open / close voting at the scheduled times
    every minute  delete expired sessions, old rate-limit counters, stale
                  password-reset codes
    every 5 min   re-verify the audit chain and the database
    every 30 min  encrypted backup                    (BACKUP_INTERVAL_MIN)
    every 6 h     restoration drill on the newest backup (DRILL_INTERVAL_MIN)
    every hour    read-only audit copy                (AUDIT_COPY_INTERVAL_MIN)
    on closing    one more backup + audit copy + drill, straight away
    at start-up   a first backup / drill / audit copy if none is recent

  Every job is wrapped so one failure never stops the others. Backup, drill
  and copy failures are recorded in the audit log by backup.js itself.
*/

"use strict";

const config = require("./config");
const d = require("./db");
const audit = require("./audit");
const election = require("./election");
const sessions = require("./sessions");
const ratelimit = require("./ratelimit");
const admins = require("./admins");
const backup = require("./backup");
const ops = require("./ops");

const MIN = 60 * 1000;

const timers = [];
let started = false;
let closeListener = null;

function safely(name, job) {
  return () => {
    try {
      job();
    } catch (error) {
      console.error(`[scheduler] ${name} failed: ${error.message}`);
    }
  };
}

/* ---------- the jobs ---------- */

const jobs = {
  schedule() {
    const change = election.applySchedule();
    if (change) console.log(`[scheduler] voting ${change} at the scheduled time`);
  },

  housekeeping() {
    sessions.sweep();
    ratelimit.sweep();
    admins.expireStaleResets();

    try {
      d.db.exec("PRAGMA wal_checkpoint(PASSIVE);");
    } catch (error) {
      /* busy — try again next minute */
    }
  },

  integrity() {
    ops.chainStatus({ force: true });
    ops.integrityStatus({ force: true });
  },

  backup() {
    backup.createBackup("schedule", "system");
  },

  drill() {
    backup.runDrill("schedule", "system");
  },

  auditCopy() {
    backup.createAuditCopy("schedule", "system");
  }
};

/* The "newest first" age of the last good run of something, in minutes. */
function minutesSince(sql) {
  const row = d.get(sql);
  if (!row || !row.at) return Infinity;
  return (Date.now() - Date.parse(row.at)) / MIN;
}

/* After a restart, do not wait a whole interval for the first backup. */
function startupCatchUp() {
  const backupAge = minutesSince("SELECT MAX(COALESCE(finishedAt, startedAt)) AS at FROM backup_runs WHERE status = 'ok'");
  if (backupAge > config.BACKUP_INTERVAL_MIN) safely("startup backup", jobs.backup)();

  const drillAge = minutesSince("SELECT MAX(startedAt) AS at FROM drill_runs WHERE status = 'pass'");
  if (drillAge > config.DRILL_INTERVAL_MIN) safely("startup drill", jobs.drill)();

  const copyAge = minutesSince("SELECT MAX(createdAt) AS at FROM audit_copies WHERE prunedAt IS NULL");
  if (copyAge > config.AUDIT_COPY_INTERVAL_MIN) safely("startup audit copy", jobs.auditCopy)();

  safely("startup integrity", jobs.integrity)();
}

function every(ms, name, job) {
  const timer = setInterval(safely(name, job), ms);
  timer.unref();
  timers.push(timer);
}

/* ---------- start / stop ---------- */

function start() {
  if (started || !config.ENABLE_SCHEDULERS) return false;
  started = true;

  every(config.SCHEDULE_TICK_SEC * 1000, "schedule", jobs.schedule);
  every(MIN, "housekeeping", jobs.housekeeping);
  every(5 * MIN, "integrity", jobs.integrity);
  every(config.BACKUP_INTERVAL_MIN * MIN, "backup", jobs.backup);
  every(config.DRILL_INTERVAL_MIN * MIN, "drill", jobs.drill);
  every(config.AUDIT_COPY_INTERVAL_MIN * MIN, "audit copy", jobs.auditCopy);

  // The moment voting closes (by hand or by the clock): freeze a copy of
  // everything and prove it can be restored.
  closeListener = () => {
    const later = setTimeout(() => {
      safely("closing backup", () => backup.createBackup("election-closed", "system"))();
      safely("closing audit copy", () => backup.createAuditCopy("election-closed", "system"))();
      safely("closing drill", () => backup.runDrill("election-closed", "system"))();
    }, 750);
    later.unref();
    timers.push(later);
  };
  election.events.on("closed", closeListener);

  const first = setTimeout(safely("start-up catch-up", startupCatchUp), 5000);
  first.unref();
  timers.push(first);

  return true;
}

function stop() {
  timers.forEach((timer) => {
    clearInterval(timer);
    clearTimeout(timer);
  });
  timers.length = 0;

  if (closeListener) election.events.off("closed", closeListener);
  closeListener = null;
  started = false;
}

module.exports = { start, stop, jobs, startupCatchUp };
