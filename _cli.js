/*
  BOUESTI Vote — small helpers shared by the command-line tools in this folder.

  These tools are run by a person at the server (never by students or
  through the web). Anything that changes the election is recorded in the
  audit log under the operator's console name, e.g. "console:technician".
*/

"use strict";

const fs = require("node:fs");
const os = require("node:os");
const readline = require("node:readline");

/*
  Every tool requires this file first, so an out-of-date Node.js is reported here,
  in plain words, before anything tries to load the database.
*/
const runtimeProblem = require("../runtime").versionProblem();

if (runtimeProblem) {
  console.error(`\n  ✖ ${runtimeProblem}\n`);
  process.exit(1);
}

/* node:sqlite prints a one-line "experimental" notice on every run; operators do not need it. */
function quietExperimentalWarnings() {
  const original = process.emitWarning;

  process.emitWarning = function emitWarning(warning, ...rest) {
    const type = typeof rest[0] === "string" ? rest[0] : rest[0] && rest[0].type;

    if (type === "ExperimentalWarning") return undefined;
    return original.call(process, warning, ...rest);
  };
}

/*
  "restore file.bvbak --yes --note=x"  ->  { positional: ["file.bvbak"], flags: { yes: true, note: "x" } }
  Flags listed in valueFlags take the next word as their value ("--note hello").
*/
function parseArgs(argv, valueFlags = []) {
  const positional = [];
  const flags = {};

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];

    if (!arg.startsWith("--")) {
      positional.push(arg);
      continue;
    }

    const body = arg.slice(2);
    const equals = body.indexOf("=");

    if (equals !== -1) {
      flags[body.slice(0, equals)] = body.slice(equals + 1);
    } else if (valueFlags.includes(body)) {
      flags[body] = argv[index + 1];
      index += 1;
    } else {
      flags[body] = true;
    }
  }

  return { positional, flags };
}

/* Who is at the keyboard, for the audit log. */
function operator() {
  let name = process.env.USER || process.env.USERNAME || "unknown";

  try {
    name = os.userInfo().username || name;
  } catch (error) {
    /* some containers have no passwd entry */
  }

  return `console:${name}`;
}

function fail(message, code = 1) {
  console.error(`\n  ✖ ${message}\n`);
  process.exit(code);
}

/* Must run BEFORE anything requires ../db, which would otherwise create an empty database. */
function requireDatabase(config) {
  if (!fs.existsSync(config.DB_PATH)) {
    fail(
      `There is no election database at ${config.DB_PATH}.\n` +
        "  If your data lives somewhere else, set DATA_DIR to that folder first."
    );
  }
}

/* The key module would quietly invent a new key if none exists; an operator tool must never do that. */
function requireMasterKey(keys) {
  if (!keys.masterKeyFileExists()) {
    fail(
      "No master key was found.\n" +
        "  Put the saved key at <data folder>/keys/master.key, or set BOUESTI_MASTER_KEY, and run this again.\n" +
        "  A new key would not open the existing database or backups, so none is created here."
    );
  }
}

/* The process id of a running server, or null. A leftover file from a crash does not count. */
function runningServerPid(config) {
  let pid;

  try {
    pid = Number(fs.readFileSync(config.PID_FILE, "utf8").trim());
  } catch (error) {
    return null;
  }

  if (!Number.isInteger(pid) || pid <= 0) return null;

  try {
    process.kill(pid, 0);
    return pid;
  } catch (error) {
    return error.code === "EPERM" ? pid : null;
  }
}

/* Ask for a typed phrase. Refuses to guess when there is no keyboard. */
function confirmPhrase(question, phrase) {
  if (!process.stdin.isTTY) {
    fail(`This needs a typed confirmation. Run it in a terminal, or add --yes if you are sure.`);
  }

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

  return new Promise((resolve) => {
    rl.question(`${question}\n  Type ${phrase} to continue: `, (answer) => {
      rl.close();
      resolve(answer.trim() === phrase);
    });
  });
}

/* A list of { name, ok, detail } checks, one per line. */
function printChecks(checks) {
  checks.forEach((check) => {
    const mark = check.ok ? "PASS" : "FAIL";
    const detail = check.detail ? `  — ${check.detail}` : "";
    console.log(`  ${mark}  ${check.name}${detail}`);
  });
}

function printHeading(text) {
  console.log(`\n${text}\n${"─".repeat(text.length)}`);
}

/* Groups of four so a key can be read aloud and written down without mistakes. */
function groupsOfFour(text) {
  return String(text).replace(/(.{4})/g, "$1 ").trim();
}

module.exports = {
  quietExperimentalWarnings,
  parseArgs,
  operator,
  fail,
  requireDatabase,
  requireMasterKey,
  runningServerPid,
  confirmPhrase,
  printChecks,
  printHeading,
  groupsOfFour
};
