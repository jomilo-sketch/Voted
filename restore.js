/*
  BOUESTI Vote — restore the election database from an encrypted backup.

      npm run restore -- <backup-file>              ask before replacing anything
      npm run restore -- <backup-file> --yes        do not ask (scripted use)

  STOP THE SERVER FIRST. This replaces election.db. The tool

    1. refuses to run while the server is running,
    2. decrypts the backup into a scratch folder and checks its signature,
       checksum and contents (nothing is changed if any check fails),
    3. moves the CURRENT database aside into data/pre-restore-<time>/ —
       it is never deleted, so a wrong choice can be undone,
    4. puts the restored database in place and leaves a note that the
       server writes into the audit log when it next starts.

  The master key must be the one the backup was made with: either
  data/keys/master.key or the BOUESTI_MASTER_KEY setting. On a replacement
  machine, put the key back FIRST (from the sealed copy).

  Changes made after the backup was taken are not in it. The tool tells you
  how many ballots the backup holds so you can compare with the live count
  and decide whether to ask for the voting period to be extended.
*/

"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { quietExperimentalWarnings, parseArgs, fail, requireMasterKey, runningServerPid, confirmPhrase, printChecks, printHeading } = require("./_cli");

quietExperimentalWarnings();

const config = require("../config");
const keys = require("../keys");
const core = require("../backup-core");

const { positional, flags } = parseArgs(process.argv.slice(2));

async function main() {
  if (!positional[0]) {
    fail(
      "Say which backup to restore, for example:\n" +
        `    npm run restore -- bouesti-20261014093000-a1b2c3.bvbak\n` +
        `  Backups are kept in ${config.BACKUP_DIR}`
    );
  }

  const running = runningServerPid(config);

  if (running && !flags["server-is-stopped"]) {
    fail(
      `The server appears to be running (process ${running}). Stop it first, then run this again.\n` +
        "  If you are certain it is stopped and this is a leftover from a crash, add --server-is-stopped."
    );
  }

  const asGiven = path.resolve(positional[0]);
  const backupPath = fs.existsSync(asGiven) ? asGiven : path.join(config.BACKUP_DIR, path.basename(positional[0]));

  if (!fs.existsSync(backupPath)) fail(`Backup file not found: ${positional[0]}`);
  if (!fs.existsSync(core.manifestPathFor(backupPath))) {
    fail(`The signed manifest ${path.basename(core.manifestPathFor(backupPath))} must sit next to the backup file.`);
  }

  requireMasterKey(keys);

  fs.mkdirSync(config.DATA_DIR, { recursive: true, mode: 0o700 });

  // Look before leaping: verify without replacing anything, and show what the backup holds.
  const scratch = path.join(config.DATA_DIR, `restore-preview-${Date.now()}`);
  const preview = core.verifyBackupFile(backupPath, scratch);
  core.removeDirectory(scratch);

  printHeading(`Checking ${path.basename(backupPath)}`);
  printChecks(preview.checks);

  if (!preview.ok) {
    fail("This backup did not pass its checks, so nothing was changed. Try an earlier backup, or the mirrored copy.");
  }

  const manifest = JSON.parse(fs.readFileSync(core.manifestPathFor(backupPath), "utf8"));

  console.log(`\n  Taken at:        ${manifest.createdAt}`);
  console.log(`  Ballots inside:  ${preview.stats.ballots}`);
  console.log(`  Audit entries:   ${preview.stats.auditEntries}`);
  console.log(`  Current database ${fs.existsSync(config.DB_PATH) ? "WILL BE MOVED ASIDE (kept, not deleted)" : "does not exist"}.`);

  if (!flags.yes) {
    const agreed = await confirmPhrase("\n  Replace the election database with this backup?", "RESTORE");
    if (!agreed) fail("Cancelled. Nothing was changed.", 2);
  }

  const result = core.restoreBackup(backupPath);

  if (!result.ok) {
    printChecks(result.checks);
    fail(result.error);
  }

  printHeading("Restored");
  console.log(`  The database now holds ${result.stats.ballots} ballot(s) and ${result.stats.auditEntries} audit entries.`);
  console.log(
    result.safetyCopy
      ? `  The previous database is kept in: ${result.safetyCopy}`
      : "  There was no previous database to keep (this looks like a replacement machine)."
  );
  console.log("\n  Start the server again (npm start). It records the restore in the audit log.");
  console.log("  Then take a new backup and run a restoration drill.\n");
}

main().catch((error) => fail(error.message));
