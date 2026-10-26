#!/usr/bin/env node
/*
  BOUESTI Vote — independent verification of the audit log.

      node scripts/verify-audit.js <audit-export.ndjson | audit-copy.db> [options]

  Standalone, like verify-report.js: no server, no database of the live
  election, no secret. It recomputes the whole tamper-evident chain from the
  first entry to the last and checks every signed checkpoint.

  How the log protects itself
    Every entry stores the hash of the entry before it, so changing, removing
    or re-ordering any one entry breaks every hash that follows. A person who
    could edit the database could in theory re-compute all the hashes — so the
    server also signs "checkpoints" (entry number + hash + time) at important
    moments, and officials keep a copy. A rewritten log can no longer match
    those signatures, or the head hash you wrote down.

  Input: either the NDJSON file from "Export" on the Audit page, or a
  read-only audit copy (.db) from the Operations page.

  Options
    --trusted-fingerprint "ABCD 1234 ..."  the signing-key fingerprint the officials announced
    --public-key <base64>                  use this key for the checkpoint signatures instead of the one in the file
    --expect-head <hash>                   the head hash an official wrote down; it must be the last entry
    --expect-entries <number>              the number of entries an official recorded
    --json                                 machine-readable output

  Exit status: 0 = everything checked out, 1 = a check failed, 2 = could not run.
*/

"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");

const originalEmitWarning = process.emitWarning;
process.emitWarning = function emitWarning(warning, ...rest) {
  const type = typeof rest[0] === "string" ? rest[0] : rest[0] && rest[0].type;
  if (type === "ExperimentalWarning") return undefined;
  return originalEmitWarning.call(process, warning, ...rest);
};

const CHECKPOINT_PREFIX = "bouesti-vote/audit-checkpoint/v1";
const GENESIS_HASH = "0".repeat(64);
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function sha256Hex(input) {
  return crypto.createHash("sha256").update(input).digest("hex");
}

function fingerprintOf(rawPublicBase64) {
  return sha256Hex(Buffer.from(rawPublicBase64, "base64")).slice(0, 32).toUpperCase().replace(/(.{4})/g, "$1 ").trim();
}

function normaliseFingerprint(text) {
  return String(text || "").replace(/[^0-9a-fA-F]/g, "").toUpperCase();
}

function verifySignature(rawPublicBase64, data, signatureBase64) {
  try {
    const publicKey = crypto.createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(rawPublicBase64, "base64")]),
      format: "der",
      type: "spki"
    });

    return crypto.verify(null, Buffer.from(data), publicKey, Buffer.from(signatureBase64, "base64"));
  } catch (error) {
    return false;
  }
}

/* ---------- command line ---------- */

function parseArguments(argv) {
  const options = { file: null, trusted: null, publicKey: null, expectHead: null, expectEntries: null, json: false };
  const valued = { "--trusted-fingerprint": "trusted", "--public-key": "publicKey", "--expect-head": "expectHead", "--expect-entries": "expectEntries" };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    const [name, inline] = arg.includes("=") ? [arg.slice(0, arg.indexOf("=")), arg.slice(arg.indexOf("=") + 1)] : [arg, undefined];

    if (valued[name]) options[valued[name]] = inline !== undefined ? inline : argv[++index];
    else if (arg === "--json") options.json = true;
    else if (arg === "--help" || arg === "-h") options.help = true;
    else if (!arg.startsWith("--") && !options.file) options.file = arg;
    else {
      console.error(`Unknown option: ${arg}`);
      process.exit(2);
    }
  }

  return options;
}

const options = parseArguments(process.argv.slice(2));

if (options.help || !options.file) {
  console.log(fs.readFileSync(__filename, "utf8").split("*/")[0].replace(/^#!.*\n/, "").replace("/*", "").trim());
  process.exit(options.help ? 0 : 2);
}

/* ---------- loading either kind of input ---------- */

function loadNdjson(text) {
  const entries = [];
  const checkpoints = [];
  let header = null;

  text.split(/\r?\n/).forEach((line, index) => {
    if (!line.trim()) return;

    let row;

    try {
      row = JSON.parse(line);
    } catch (error) {
      throw new Error(`line ${index + 1} is not valid JSON`);
    }

    if (row.type === "header") header = row;
    else if (row.type === "entry") entries.push(row);
    else if (row.type === "checkpoint") checkpoints.push(row);
  });

  return { entries, checkpoints, publicKey: header && header.publicKey, headerHeadId: header && header.headId, headerHeadHash: header && header.headHash, kind: "export" };
}

function loadDatabase(file) {
  let DatabaseSync;

  try {
    ({ DatabaseSync } = require("node:sqlite"));
  } catch (error) {
    throw new Error("opening an audit copy (.db) needs Node.js 22.13 or newer. The exported .ndjson file can be checked on any recent Node.js");
  }

  const db = new DatabaseSync(file, { readOnly: true });

  try {
    const entries = db.prepare("SELECT id, occurredAt, actor, category, message, prevHash, hash FROM audit_log ORDER BY id").all();
    const checkpoints = db.prepare("SELECT id, auditId, auditHash, reason, createdAt, signature FROM audit_checkpoints ORDER BY id").all();

    let meta = {};

    try {
      meta = Object.fromEntries(db.prepare("SELECT key, value FROM copy_meta").all().map((row) => [row.key, row.value]));
    } catch (error) {
      /* an ordinary database has no copy_meta */
    }

    return { entries, checkpoints, publicKey: meta.signingPublicKey, headerHeadId: Number(meta.auditHeadId), headerHeadHash: meta.auditHeadHash, kind: meta.signingPublicKey ? "audit copy" : "database", meta };
  } finally {
    db.close();
  }
}

let input;

try {
  const head = fs.readFileSync(options.file).subarray(0, 16).toString("latin1");

  input = head.startsWith("SQLite format 3") ? loadDatabase(options.file) : loadNdjson(fs.readFileSync(options.file, "utf8"));
} catch (error) {
  console.error(`Could not read ${options.file}: ${error.message}`);
  process.exit(2);
}

/* ---------- checks ---------- */

const results = [];
const record = (name, status, detail = "") => results.push({ name, status, detail });
const check = (name, condition, detail = "") => {
  record(name, condition ? "pass" : "fail", detail);
  return Boolean(condition);
};

const { entries, checkpoints } = input;

check("The file contains audit entries", entries.length > 0, `${entries.length} entries`);

/* The chain */
let previous = GENESIS_HASH;
let chainBroken = null;

for (const entry of entries) {
  if (entry.prevHash !== previous) {
    chainBroken = `entry ${entry.id} does not link to the entry before it`;
    break;
  }

  const expected = sha256Hex(JSON.stringify([entry.prevHash, entry.occurredAt, entry.actor, entry.category, entry.message]));

  if (entry.hash !== expected) {
    chainBroken = `entry ${entry.id} has been altered (its content does not match its hash)`;
    break;
  }

  previous = entry.hash;
}

check("Every entry links to the one before it and matches its own hash", !chainBroken, chainBroken || `${entries.length} entries verified from the first to the last`);

const last = entries[entries.length - 1];
const gaps = entries.slice(1).filter((entry, index) => entry.id !== entries[index].id + 1).length;

if (gaps) record("Entry numbers are consecutive", "warn", `${gaps} gap(s) in the numbering — normal only for an excerpt`);
else record("Entry numbers are consecutive", "pass");

if (last && input.headerHeadHash) {
  check("The file's stated end-of-log matches its last entry", input.headerHeadHash === last.hash && input.headerHeadId === last.id, `entry ${input.headerHeadId}`);
}

if (options.expectHead) {
  check("The last entry is the head hash an official wrote down", Boolean(last) && last.hash === String(options.expectHead).trim().toLowerCase(), last ? `last entry ${last.id}: ${last.hash}` : "");
}

if (options.expectEntries !== null) {
  check("The number of entries is what an official recorded", entries.length === Number(options.expectEntries), `${entries.length} found`);
}

/* The signed checkpoints */
const publicKey = options.publicKey || input.publicKey;

if (!publicKey) {
  record("Signed checkpoints", "warn", "No signing key is in the file. Give one with --public-key to check the checkpoint signatures.");
} else {
  const computed = fingerprintOf(publicKey);

  if (options.trusted) {
    check("The signing key is the one the officials announced", normaliseFingerprint(options.trusted) === normaliseFingerprint(computed), `key fingerprint ${computed}`);
  } else {
    record("The signing key was compared with the announced fingerprint", "warn", `Not checked. The file's key is ${computed}; compare it with the one the officials announced, or use --trusted-fingerprint.`);
  }

  const byId = new Map(entries.map((entry) => [entry.id, entry.hash]));
  const problems = [];

  checkpoints.forEach((cp) => {
    const signedOk = verifySignature(publicKey, `${CHECKPOINT_PREFIX}|${cp.auditId}|${cp.auditHash}|${cp.createdAt}`, cp.signature);
    const expectedHash = cp.auditId === 0 ? GENESIS_HASH : byId.get(cp.auditId);

    if (!signedOk) problems.push(`checkpoint ${cp.id}: the signature is not valid`);
    if (expectedHash === undefined) problems.push(`checkpoint ${cp.id}: refers to entry ${cp.auditId}, which is not in the file`);
    else if (expectedHash !== cp.auditHash) problems.push(`checkpoint ${cp.id}: entry ${cp.auditId} no longer has the hash that was signed`);
  });

  check("Every signed checkpoint is genuine and still matches the log", problems.length === 0, problems.join("; ") || `${checkpoints.length} checkpoint(s)`);
}

/* ---------- a short description of what the log says ---------- */

const byCategory = new Map();
entries.forEach((entry) => byCategory.set(entry.category, (byCategory.get(entry.category) || 0) + 1));

const notable = {
  security: entries.filter((entry) => entry.category === "security").length,
  restores: entries.filter((entry) => /DATABASE RESTORED/.test(entry.message)).length,
  starts: entries.filter((entry) => /^Server started/.test(entry.message)).length
};

const failed = results.filter((result) => result.status === "fail").length;
const warnings = results.filter((result) => result.status === "warn").length;

if (options.json) {
  console.log(JSON.stringify({
    ok: failed === 0,
    failed,
    warnings,
    checks: results,
    log: {
      source: input.kind,
      entries: entries.length,
      first: entries[0] ? { id: entries[0].id, at: entries[0].occurredAt } : null,
      last: last ? { id: last.id, at: last.occurredAt, hash: last.hash } : null,
      categories: Object.fromEntries(byCategory),
      ...notable
    }
  }, null, 2));
  process.exit(failed === 0 ? 0 : 1);
}

console.log(`\nBOUESTI Vote — independent verification of the audit log in ${options.file} (${input.kind})\n`);

results.forEach((result) => {
  const mark = result.status === "pass" ? "PASS" : result.status === "fail" ? "FAIL" : "WARN";
  console.log(`  ${mark}  ${result.name}${result.detail ? `\n          ${result.detail}` : ""}`);
});

if (entries.length) {
  console.log("\nWhat the log contains");
  console.log(`  Entries:     ${entries.length}  (from ${entries[0].occurredAt} to ${last.occurredAt})`);
  console.log(`  Head hash:   ${last.hash}   <- the number to write down`);
  console.log(`  By category: ${[...byCategory.entries()].sort().map(([name, count]) => `${name} ${count}`).join(", ")}`);
  console.log(`  Server starts: ${notable.starts}   Restores from backup: ${notable.restores}   Security entries: ${notable.security}`);
}

console.log("");

if (failed === 0) {
  console.log(`RESULT: VERIFIED${warnings ? ` (with ${warnings} warning${warnings === 1 ? "" : "s"} — read them above)` : ""}\n`);
  process.exit(0);
}

console.log(`RESULT: NOT VERIFIED — ${failed} check${failed === 1 ? "" : "s"} failed. The log may have been altered.\n`);
process.exit(1);
