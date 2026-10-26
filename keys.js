/*
  BOUESTI Vote — the master key and the result-signing key.

      npm run keys                    show fingerprints (safe to share)
      npm run keys -- check           confirm the key opens the election database
      npm run keys -- public          print the result-signing PUBLIC key (safe to share)
      npm run keys -- export          print the MASTER KEY so it can be written down and sealed

  The master key is the one secret that cannot be re-created. Everything else
  is derived from it: the key that encrypts backups, the key that signs result
  reports, the key that scrambles matric numbers in the turnout record. If it
  is lost, encrypted backups cannot be opened and published results can no
  longer be signed with the same identity.

  Keep at least TWO sealed copies, held by DIFFERENT officers, in different
  places, and never next to the backups. After writing a copy down, prove it is
  right:   BOUESTI_MASTER_KEY=<the copy> npm run keys -- check
*/

"use strict";

const fs = require("node:fs");
const path = require("node:path");
// _cli is required before node:sqlite on purpose: it explains an out-of-date Node.js in plain words.
const { quietExperimentalWarnings, parseArgs, fail, requireMasterKey, confirmPhrase, printHeading, groupsOfFour } = require("./_cli");
const { DatabaseSync } = require("node:sqlite");

quietExperimentalWarnings();

const config = require("../config");
const keys = require("../keys");

const { positional, flags } = parseArgs(process.argv.slice(2));
const command = positional[0] || "show";

/* Read the fingerprint stored in the database WITHOUT opening it the way the server does. */
function storedFingerprint() {
  if (!fs.existsSync(config.DB_PATH)) return undefined;

  const handle = new DatabaseSync(config.DB_PATH, { readOnly: true });

  try {
    const row = handle.prepare("SELECT value FROM meta WHERE key = 'key_fingerprint'").get();
    return row ? row.value : null;
  } finally {
    handle.close();
  }
}

function keySource() {
  return process.env.BOUESTI_MASTER_KEY
    ? "the BOUESTI_MASTER_KEY setting"
    : `the file ${path.join(config.KEY_DIR, "master.key")}`;
}

function showFingerprints() {
  printHeading("Keys");
  console.log(`  Master key comes from:      ${keySource()}`);
  console.log(`  Master key fingerprint:     ${groupsOfFour(keys.fingerprint())}`);
  console.log("                              (identifies the key without revealing it)");
  console.log(`  Result-signing key (public): ${keys.signingPublicKey()}`);
  console.log(`  Its fingerprint:             ${keys.publicKeyFingerprint()}`);
  console.log("                              (officials announce this so anyone can confirm signed reports)");
}

function checkAgainstDatabase() {
  const stored = storedFingerprint();

  printHeading("Does this key open the election database?");

  if (stored === undefined) {
    console.log(`  There is no database at ${config.DB_PATH} yet, so there is nothing to compare with.\n`);
    return true;
  }

  if (stored === null) {
    console.log("  The database has no key fingerprint recorded (it has never been started). Nothing to compare.\n");
    return true;
  }

  if (stored === keys.fingerprint()) {
    console.log("  MATCH — this is the key the database was created with.\n");
    return true;
  }

  console.log("  DOES NOT MATCH — this is NOT the key the database was created with.");
  console.log("  The server will refuse to start with it, and backups made by the original key will not open.\n");
  return false;
}

async function exportMasterKey() {
  console.log("\n  ┌──────────────────────────────────────────────────────────────────────┐");
  console.log("  │  You are about to display the MASTER KEY.                            │");
  console.log("  │  Anyone who sees it can read backups and impersonate the server's    │");
  console.log("  │  result-signing identity. Do this in private, write it on paper,     │");
  console.log("  │  seal it, and close this terminal afterwards.                        │");
  console.log("  └──────────────────────────────────────────────────────────────────────┘");

  if (!flags.yes) {
    const agreed = await confirmPhrase("\n  Are you alone, and ready to write it down?", "EXPORT");
    if (!agreed) fail("Cancelled. The key was not shown.", 2);
  }

  const hex = keys.exportMasterKeyHex();

  printHeading("MASTER KEY (64 hexadecimal characters)");
  console.log(`  ${hex.match(/.{1,8}/g).join("  ")}`);
  console.log(`\n  Fingerprint (to check your written copy later): ${groupsOfFour(keys.fingerprint())}`);
  console.log("  Check a copy:  BOUESTI_MASTER_KEY=<the 64 characters, no spaces> npm run keys -- check\n");
}

async function main() {
  requireMasterKey(keys);

  switch (command) {
    case "show":
      showFingerprints();
      checkAgainstDatabase();
      break;

    case "check":
      if (!checkAgainstDatabase()) process.exit(1);
      break;

    case "public":
      console.log(`\n  Public key:   ${keys.signingPublicKey()}`);
      console.log(`  Fingerprint:  ${keys.publicKeyFingerprint()}\n`);
      break;

    case "export":
      await exportMasterKey();
      break;

    default:
      fail(`Unknown command "${command}". Use: show, check, public or export.`);
  }
}

main().catch((error) => fail(error.message));
