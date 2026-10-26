/*
  BOUESTI Vote — administrator rescue from the server console.

      npm run admin -- list
      npm run admin -- roles
      npm run admin -- history <email>
      npm run admin -- unlock <email>
      npm run admin -- reset-code <email>
      npm run admin -- reset-2fa <email>
      npm run admin -- disable <email>
      npm run admin -- enable <email>
      npm run admin -- create <email> <role> "<Full name>"

  This is the way back in when someone is locked out: a forgotten password, a
  lost authenticator phone, or an account locked by repeated wrong guesses.
  It works even while the web dashboard has frozen the Electoral and Results
  Officers' accounts during live counting — which is exactly why it needs
  access to the server itself, and why every action is written to the audit
  log under your console name AND, during a live election, as a SECURITY
  entry that the other officers will see.

  A password is never chosen or shown here. `reset-code` prints a one-time
  code (valid for a short time) that the person types on the sign-in page to
  choose their own new password; `create` prints a one-time temporary password
  that must be changed at first sign-in. Hand either over in person.
*/

"use strict";

const { quietExperimentalWarnings, parseArgs, operator, fail, requireDatabase, requireMasterKey, confirmPhrase, printHeading } = require("./_cli");

quietExperimentalWarnings();

const config = require("../config");
const keys = require("../keys");

requireDatabase(config);
requireMasterKey(keys);

const database = require("../db");
const admins = require("../admins");
const audit = require("../audit");
const election = require("../election");
const { ROLES, ROLE_KEYS } = require("../permissions");

const { positional, flags } = parseArgs(process.argv.slice(2));
const [command, ...rest] = positional;
const who = operator();

function findAdmin(email) {
  if (!email) fail("Say which administrator, by e-mail address.");

  const row = admins.getByEmail(email);
  if (!row) fail(`No administrator has the e-mail address ${email}. Run "npm run admin -- list" to see them.`);

  return row;
}

/* During a live election, console changes are also logged where every officer will notice them. */
function flagIfLive(action) {
  const current = election.getElection();

  if (current.mode === "live") {
    audit.append(who, "security", `Console administrator action during the live election: ${action}`);
  }
}

async function confirm(question) {
  if (flags.yes) return;

  const agreed = await confirmPhrase(question, "YES");
  if (!agreed) fail("Cancelled. Nothing was changed.", 2);
}

function printAdmins() {
  const rows = admins.list();

  printHeading(`Administrators (${rows.length})`);

  rows.forEach((row) => {
    const state = row.disabled ? "DISABLED" : row.locked ? "LOCKED" : "active";

    console.log(
      `  ${row.email.padEnd(30)} ${row.roleLabel.padEnd(27)} ${state.padEnd(9)} ` +
        `2FA ${row.totpEnabled ? "on " : "OFF"}  ` +
        `last sign-in ${row.lastLoginAt ? row.lastLoginAt.slice(0, 16).replace("T", " ") : "never"}`
    );
  });

  console.log("");
}

function printRoles() {
  printHeading("Roles");

  ROLE_KEYS.forEach((key) => {
    console.log(`  ${key.padEnd(18)} ${ROLES[key].label}`);
    console.log(`  ${"".padEnd(18)} ${ROLES[key].summary}\n`);
  });
}

async function main() {
  switch (command) {
    case "list":
      printAdmins();
      break;

    case "roles":
      printRoles();
      break;

    case "history": {
      const target = findAdmin(rest[0]);
      const history = admins.loginHistory(target.id, 30);

      audit.append(who, "admin", `Viewed the sign-in history of ${target.email}`);
      printHeading(`Recent sign-in activity for ${target.email}`);

      if (!history.length) console.log("  (none yet)");
      history.forEach((entry) => {
        console.log(`  ${entry.at.slice(0, 19).replace("T", " ")}  ${String(entry.outcome).padEnd(16)} ${entry.ip || "-"}  ${entry.detail || ""}`);
      });

      console.log("");
      break;
    }

    case "unlock": {
      const target = findAdmin(rest[0]);
      const result = admins.unlock(target.id, who);

      if (!result.ok) fail(result.error);
      flagIfLive(`unlocked ${target.email}`);
      console.log(`\n  ${target.email} is unlocked and can try again.\n`);
      break;
    }

    case "reset-code": {
      const target = findAdmin(rest[0]);
      const result = admins.issueResetCode(target.id, who);

      if (!result.ok) fail(result.error);
      flagIfLive(`issued a password-reset code for ${target.email}`);

      printHeading(`One-time reset code for ${target.email}`);
      console.log(`  ${result.code}`);
      console.log(`\n  Valid for ${Math.round(config.RESET_CODE_TTL_SEC / 60)} minutes, single use.`);
      console.log("  Give it to them in person. They enter it on the administrator sign-in page, under \"Use a reset code\",");
      console.log("  and choose their own new password. It will not be shown again.\n");
      break;
    }

    case "reset-2fa": {
      const target = findAdmin(rest[0]);

      await confirm(`\n  Remove two-factor authentication from ${target.email}? They must enrol again at next sign-in.`);

      const result = admins.resetTwoFactor(target.id, who);
      if (!result.ok) fail(result.error);

      flagIfLive(`reset two-factor authentication for ${target.email}`);
      console.log(`\n  Two-factor authentication was reset for ${target.email}. All their sessions were ended.\n`);
      break;
    }

    case "disable":
    case "enable": {
      const target = findAdmin(rest[0]);
      const disabling = command === "disable";

      if (disabling) await confirm(`\n  Disable ${target.email}? They are signed out at once and cannot sign in.`);

      // byId 0: the console is not an administrator account, so the "not your own account" rule cannot apply.
      const result = admins.setDisabled(target.id, disabling, who, 0);
      if (!result.ok) fail(result.error);

      flagIfLive(`${disabling ? "disabled" : "re-enabled"} ${target.email}`);
      console.log(`\n  ${target.email} is now ${disabling ? "disabled" : "enabled"}.\n`);
      break;
    }

    case "create": {
      const [email, role, ...nameParts] = rest;

      if (!email || !role || !nameParts.length) {
        fail(`Use: npm run admin -- create <email> <role> "<Full name>"\n  Roles: ${ROLE_KEYS.join(", ")}`);
      }

      await confirm(`\n  Create a ${role} account for ${email}?`);

      const result = await admins.createAdmin({ email, displayName: nameParts.join(" "), role }, who);
      if (!result.ok) fail(result.error);

      flagIfLive(`created ${role} account ${result.admin.email}`);

      printHeading(`New account: ${result.admin.email} (${result.admin.roleLabel})`);
      console.log(`  Temporary password: ${result.temporaryPassword}`);
      console.log("\n  They must change it, and enrol two-factor authentication, at their first sign-in.");
      console.log("  Give it to them in person. It will not be shown again.\n");
      break;
    }

    default:
      fail(
        `Unknown command "${command || ""}". Use: list, roles, history, unlock, reset-code, reset-2fa, disable, enable or create.\n` +
          "  See the top of scripts/admin-cli.js for examples."
      );
  }
}

main()
  .then(() => database.close())
  .catch((error) => {
    database.close();
    fail(error.message);
  });
