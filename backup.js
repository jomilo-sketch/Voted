/*
  BOUESTI Vote — take an encrypted backup right now.

      npm run backup

  Safe to run while the server is running and students are voting: the copy
  is a consistent snapshot made by SQLite itself. The result is an AES-256
  encrypted file in the backups folder plus a signed manifest, and is
  recorded in the audit log under your console name.

  Scheduled backups happen automatically (see BACKUP_INTERVAL_MIN); use this
  before a risky step, for example just before going live or just before
  voting closes. A backup is only worth having once a restoration drill has
  proved it can be restored — run `npm run drill` next.
*/

"use strict";

const { quietExperimentalWarnings, operator, fail, requireDatabase, requireMasterKey, printHeading } = require("./_cli");

quietExperimentalWarnings();

const config = require("../config");
const keys = require("../keys");

requireDatabase(config);
requireMasterKey(keys);

const backup = require("../backup");
const database = require("../db");

const who = operator();
const result = backup.createBackup("manual", who);

database.close();

if (!result.ok) fail(`The backup failed: ${result.error}`);

printHeading("Backup created");
console.log(`  File:      ${result.file}`);
console.log(`  Folder:    ${config.BACKUP_DIR}`);
console.log(`  Size:      ${result.sizeBytes} bytes (encrypted)`);
console.log(`  Contains:  ${result.stats.ballots} ballot(s), ${result.stats.auditEntries} audit entries`);

if (config.BACKUP_MIRROR_DIR) {
  console.log(`  Mirror:    also copied to ${config.BACKUP_MIRROR_DIR}`);
} else {
  console.log("  Mirror:    none configured (set BACKUP_MIRROR_DIR to a USB drive or network share)");
}

console.log("\n  Next: npm run drill   — proves this backup can really be restored.\n");
