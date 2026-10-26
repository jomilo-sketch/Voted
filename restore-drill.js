/*
  BOUESTI Vote — restoration drill: prove a backup can really be restored.

      npm run drill                     test the newest backup
      npm run drill -- <backup-file>    test a particular one (name or path)

  A backup that was never restored is only a hope. The drill decrypts the
  backup into a scratch folder, checks its signature and checksum, opens the
  restored database and runs every integrity check (ballots versus receipts,
  audit chain, SQLite's own integrity check), reports how much a restore
  would lose, and then deletes the scratch copy. Your live database is not
  touched. Each run is recorded in the audit log and shown on the
  Operations page. Exit status is 0 only when every check passed.
*/

"use strict";

const path = require("node:path");
const { quietExperimentalWarnings, parseArgs, operator, fail, requireDatabase, requireMasterKey, printChecks, printHeading } = require("./_cli");

quietExperimentalWarnings();

const config = require("../config");
const keys = require("../keys");

requireDatabase(config);
requireMasterKey(keys);

const backup = require("../backup");
const database = require("../db");

const { positional } = parseArgs(process.argv.slice(2));
const requested = positional[0] ? path.basename(positional[0]) : null;

const result = backup.runDrill("manual", operator(), requested);

database.close();

if (result.error && !result.checks.length) fail(result.error);

printHeading(`Restoration drill — ${result.file || "no backup"}`);
printChecks(result.checks);

console.log(`\n  Took ${result.durationMs} ms.`);

if (result.ok) {
  console.log("  RESULT: PASSED — this backup can be restored.\n");
} else {
  console.log("  RESULT: FAILED — do not rely on this backup. Take a new one and investigate (see docs/OPERATIONS.md, \"Incidents\").\n");
  process.exit(1);
}
