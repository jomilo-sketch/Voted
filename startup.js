/*
  BOUESTI Vote — what must happen once, every time the server starts, before
  it accepts a single request.

    * mark any backup that was interrupted by a crash as failed
    * apply the note left by an offline restore (so the audit log says so)
    * create the election (rehearsal mode) and the three starter
      administrator accounts if this is a brand-new database
    * clear out expired sessions, counters and reset codes
    * record "server started" in the audit log
*/

"use strict";

const config = require("./config");
const audit = require("./audit");
const backup = require("./backup");
const election = require("./election");
const admins = require("./admins");
const sessions = require("./sessions");
const ratelimit = require("./ratelimit");

async function bootstrap() {
  backup.markInterruptedRuns();

  const restored = backup.applyRestoreMarker();
  const createdElection = election.seedIfEmpty();
  const createdAdmins = await admins.seedInitialAdmins();

  sessions.sweep();
  ratelimit.sweep();
  admins.expireStaleResets();

  audit.append(
    "system", "system",
    `Server started (${config.NODE_ENV}; codes by ${config.OTP_MODE}; node ${process.version}; ` +
      `${config.ENABLE_SCHEDULERS ? "schedulers on" : "schedulers OFF"})`
  );

  return { restored, createdElection, createdAdmins };
}

module.exports = { bootstrap };
