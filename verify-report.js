#!/usr/bin/env node
/*
  BOUESTI Vote — independent verification of a signed tally report.

      node scripts/verify-report.js <signed-report.json> [options]

  This file is deliberately STANDALONE. It uses nothing from the election
  system — not the database, not the server, not any secret — only Node 22.13+
  and the files you give it. An observer, a lecturer or an external examiner
  can copy this one file next to the downloaded report and run it on their own
  computer.

  What it proves, in order
    1. The report is exactly what was signed (not one byte changed).
    2. The signing key is the one the officials announced.
    3. The totals add up (per candidate, per position, ballots = receipts = turnout).
    4. The publication record is signed, names THIS report, and was approved
       by a DIFFERENT person from the one who prepared it (two-person rule).
    5. With --audit-copy: the ballots in the read-only audit copy, counted
       again from scratch, give the same totals, and their digest matches.
       The audit log in that copy is intact and contains the entry the
       report was anchored to.

  Options
    --trusted-fingerprint "ABCD 1234 ..."   fingerprint announced by the officials (strongly recommended)
    --audit-copy <audit-copy.db>            recount the ballots from the read-only audit copy
    --allow-unpublished                     check a report that is still waiting for approval
    --json                                  machine-readable output

  Exit status: 0 = every check passed, 1 = at least one check failed,
               2 = the check could not be run (bad file or arguments).
*/

"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");

/* node:sqlite prints an "experimental" notice; it is not useful here. */
const originalEmitWarning = process.emitWarning;
process.emitWarning = function emitWarning(warning, ...rest) {
  const type = typeof rest[0] === "string" ? rest[0] : rest[0] && rest[0].type;
  if (type === "ExperimentalWarning") return undefined;
  return originalEmitWarning.call(process, warning, ...rest);
};

/* ---------- the exact conventions the server used when it signed ---------- */

const ENVELOPE_FORMAT = "bouesti-vote-signed-tally/1";
const REPORT_DOMAIN = "bouesti-vote/result-report/v1\n";
const PUBLICATION_DOMAIN = "bouesti-vote/publication/v1\n";
const CHECKPOINT_PREFIX = "bouesti-vote/audit-checkpoint/v1";
const GENESIS_HASH = "0".repeat(64);
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function sortKeys(value) {
  if (Array.isArray(value)) return value.map(sortKeys);

  if (value && typeof value === "object") {
    return Object.keys(value).sort().reduce((sorted, key) => {
      sorted[key] = sortKeys(value[key]);
      return sorted;
    }, {});
  }

  return value;
}

function canonicalJson(value) {
  return JSON.stringify(sortKeys(value));
}

function sha256Hex(input) {
  return crypto.createHash("sha256").update(input).digest("hex");
}

/* Groups of four, e.g. "9F2A 61C0 ..." — the form officials read aloud. */
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

/* The arithmetic every honest set of totals must satisfy. */
function consistencyProblems(figures) {
  const problems = [];
  const { ballotsCast, turnoutRecords, receiptsIssued, offices } = figures;

  if (ballotsCast !== turnoutRecords) problems.push(`Ballots cast (${ballotsCast}) do not equal turnout records (${turnoutRecords}).`);
  if (ballotsCast !== receiptsIssued) problems.push(`Ballots cast (${ballotsCast}) do not equal receipts issued (${receiptsIssued}).`);

  offices.forEach((office) => {
    const sum = office.candidates.reduce((total, candidate) => total + candidate.votes, 0);

    if (sum !== office.totalVotes) {
      problems.push(`${office.office}: candidate votes (${sum}) do not add up to the office total (${office.totalVotes}).`);
    }

    if (office.onBallot === true && office.totalVotes !== ballotsCast) {
      problems.push(`${office.office}: ${office.totalVotes} votes recorded but ${ballotsCast} ballots were cast.`);
    } else if (office.totalVotes > ballotsCast) {
      problems.push(`${office.office}: ${office.totalVotes} votes but only ${ballotsCast} ballots.`);
    }
  });

  return problems;
}

/* One line per ballot, sorted by its random id, hashed together. Same rule the server uses. */
function ballotBoxDigest(db) {
  const hash = crypto.createHash("sha256");
  const rows = db.prepare(
    `SELECT b.ballotId AS ballotId, s.officeId AS officeId, s.candidateId AS candidateId
     FROM ballots b LEFT JOIN ballot_selections s ON s.ballotId = b.ballotId
     ORDER BY b.ballotId, s.officeId`
  ).iterate();

  let current = null;
  let parts = [];

  for (const row of rows) {
    if (row.ballotId !== current) {
      if (current !== null) hash.update(`${current}|${parts.join(",")}\n`);
      current = row.ballotId;
      parts = [];
    }

    if (row.officeId !== null) parts.push(`${row.officeId}:${row.candidateId}`);
  }

  if (current !== null) hash.update(`${current}|${parts.join(",")}\n`);
  return hash.digest("hex");
}

function auditChainProblem(db) {
  let previous = GENESIS_HASH;
  let count = 0;

  for (const row of db.prepare("SELECT id, occurredAt, actor, category, message, prevHash, hash FROM audit_log ORDER BY id").iterate()) {
    if (row.prevHash !== previous) return { ok: false, count, reason: `entry ${row.id} does not link to the one before it` };

    const expected = sha256Hex(JSON.stringify([row.prevHash, row.occurredAt, row.actor, row.category, row.message]));
    if (row.hash !== expected) return { ok: false, count, reason: `entry ${row.id} does not match its stored hash` };

    previous = row.hash;
    count += 1;
  }

  return { ok: true, count, headHash: previous };
}

/* ---------- reading the command line ---------- */

function parseArguments(argv) {
  const options = { file: null, trusted: null, auditCopy: null, allowUnpublished: false, json: false };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];

    if (arg === "--trusted-fingerprint") options.trusted = argv[++index];
    else if (arg.startsWith("--trusted-fingerprint=")) options.trusted = arg.slice(arg.indexOf("=") + 1);
    else if (arg === "--audit-copy") options.auditCopy = argv[++index];
    else if (arg.startsWith("--audit-copy=")) options.auditCopy = arg.slice(arg.indexOf("=") + 1);
    else if (arg === "--allow-unpublished") options.allowUnpublished = true;
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

/* ---------- the checks ---------- */

const results = [];

function record(group, name, status, detail = "") {
  results.push({ group, name, status, detail });
}

const pass = (group, name, detail) => record(group, name, "pass", detail);
const fail = (group, name, detail) => record(group, name, "fail", detail);
const warn = (group, name, detail) => record(group, name, "warn", detail);

function check(group, name, condition, detail = "") {
  if (condition) pass(group, name, detail);
  else fail(group, name, detail);

  return Boolean(condition);
}

let envelope;

try {
  envelope = JSON.parse(fs.readFileSync(options.file, "utf8"));
} catch (error) {
  console.error(`Could not read ${options.file}: ${error.message}`);
  process.exit(2);
}

let report = null;

/* 1. the file itself */
const G1 = "1. The file";

if (check(G1, "It is a BOUESTI signed tally report", envelope && envelope.format === ENVELOPE_FORMAT, `format is ${envelope && envelope.format}`)) {
  try {
    report = JSON.parse(envelope.reportJson);
    pass(G1, "The signed text can be read");
  } catch (error) {
    fail(G1, "The signed text can be read", error.message);
  }
}

if (report) {
  check(G1, "The signed text is in the exact canonical form the server produces", canonicalJson(report) === envelope.reportJson);
  check(G1, "The readable copy in the file is identical to the signed text", canonicalJson(envelope.report) === envelope.reportJson);

  /* 2. the key */
  const G2 = "2. The signing key";
  const computed = fingerprintOf(envelope.publicKey);

  check(G2, "The key fingerprint written in the file is correct", envelope.publicKeyFingerprint === computed && report.signer.fingerprint === computed, computed);
  check(G2, "The key inside the signed report is the same key", report.signer.publicKey === envelope.publicKey);

  if (options.trusted) {
    check(G2, "It is the key the officials announced", normaliseFingerprint(options.trusted) === normaliseFingerprint(computed), `announced ${options.trusted}`);
  } else {
    warn(G2, "Not checked against an announced fingerprint", `The file's key is ${computed}. Compare it with the one the officials announced, or run again with --trusted-fingerprint.`);
  }

  /* 3. the signature and the arithmetic */
  const G3 = "3. The report";

  check(G3, "The report signature is valid", verifySignature(envelope.publicKey, REPORT_DOMAIN + envelope.reportJson, envelope.reportSignature));

  const problems = consistencyProblems({ ...report.totals, offices: report.offices });
  check(G3, "Candidate votes add up to each position's total, and ballots = receipts = turnout", problems.length === 0, problems.join(" "));
  check(G3, "The tally digest matches the vote totals", sha256Hex(canonicalJson(report.offices)) === report.integrity.tallyDigest);

  /* 4. publication */
  const G4 = "4. Publication (two-person rule)";

  if (envelope.publicationJson) {
    let publication = null;

    try {
      publication = JSON.parse(envelope.publicationJson);
    } catch (error) {
      fail(G4, "The publication record can be read", error.message);
    }

    if (publication) {
      check(G4, "The publication record is signed by the same key", verifySignature(envelope.publicKey, PUBLICATION_DOMAIN + envelope.publicationJson, envelope.publicationSignature));
      check(G4, "It refers to this exact report", publication.reportHash === sha256Hex(envelope.reportJson) && publication.reportSequence === report.sequence);
      check(
        G4,
        "The person who published it is not the person who prepared it",
        String(publication.preparedBy).toLowerCase() !== String(publication.approvedBy).toLowerCase(),
        `prepared by ${publication.preparedBy}, published by ${publication.approvedBy}`
      );
    }
  } else if (options.allowUnpublished) {
    warn(G4, "This report has not been published yet", "Allowed because --allow-unpublished was given.");
  } else {
    fail(G4, "The report has been published", "There is no publication record. Use --allow-unpublished to check a report that is still waiting for approval.");
  }

  /* 5. recount from the audit copy */
  if (options.auditCopy) recountFromAuditCopy(report, envelope);
}

function recountFromAuditCopy(theReport, theEnvelope) {
  const G5 = "5. Independent recount from the audit copy";
  let DatabaseSync;

  try {
    ({ DatabaseSync } = require("node:sqlite"));
  } catch (error) {
    fail(G5, "SQLite support is available", "This check needs Node 22.13 or newer.");
    return;
  }

  let db;

  try {
    db = new DatabaseSync(options.auditCopy, { readOnly: true });
  } catch (error) {
    fail(G5, "The audit copy can be opened", error.message);
    return;
  }

  try {
    pass(G5, "The audit copy was opened read-only", `SHA-256 of the file: ${sha256Hex(fs.readFileSync(options.auditCopy))}`);

    const meta = Object.fromEntries(db.prepare("SELECT key, value FROM copy_meta").all().map((row) => [row.key, row.value]));
    check(G5, "It is a BOUESTI read-only audit copy", meta.kind === "bouesti-vote read-only audit copy");
    check(G5, "It was made with the same signing key as the report", meta.signingPublicKey === theEnvelope.publicKey);

    if (theReport.election.closedAt && meta.createdAt) {
      check(G5, "It was made after voting closed", meta.createdAt >= theReport.election.closedAt, `copy ${meta.createdAt}, voting closed ${theReport.election.closedAt}`);
    }

    // The ballots, counted again from nothing.
    const counted = new Map(
      db.prepare("SELECT candidateId, COUNT(*) AS n FROM ballot_selections GROUP BY candidateId").all().map((row) => [row.candidateId, row.n])
    );

    const known = new Set();
    const differences = [];

    theReport.offices.forEach((office) => {
      office.candidates.forEach((candidate) => {
        known.add(candidate.candidateId);
        const actual = counted.get(candidate.candidateId) || 0;

        if (actual !== candidate.votes) differences.push(`${office.office} / ${candidate.name}: report ${candidate.votes}, recount ${actual}`);
      });
    });

    counted.forEach((votes, candidateId) => {
      if (!known.has(candidateId)) differences.push(`votes (${votes}) for a candidate that is not in the report (id ${candidateId})`);
    });

    check(G5, "Every candidate's vote count is identical after recounting", differences.length === 0, differences.join("; "));

    const ballots = db.prepare("SELECT COUNT(*) AS n FROM ballots").get().n;
    const receipts = db.prepare("SELECT COUNT(*) AS n FROM receipts").get().n;

    check(G5, "Ballots in the copy equal ballots in the report", ballots === theReport.totals.ballotsCast, `${ballots} vs ${theReport.totals.ballotsCast}`);
    check(G5, "Receipts in the copy equal receipts in the report", receipts === theReport.totals.receiptsIssued, `${receipts} vs ${theReport.totals.receiptsIssued}`);

    if (meta.turnoutRecords !== undefined) {
      check(G5, "The recorded turnout equals the report", Number(meta.turnoutRecords) === theReport.totals.turnoutRecords, `${meta.turnoutRecords} vs ${theReport.totals.turnoutRecords}`);
    }

    const doubled = db.prepare(
      "SELECT COUNT(*) AS n FROM (SELECT ballotId, officeId FROM ballot_selections GROUP BY ballotId, officeId HAVING COUNT(*) > 1)"
    ).get().n;
    check(G5, "No ballot has two choices for the same position", doubled === 0, doubled ? `${doubled} ballot position(s) with more than one choice` : "");

    check(G5, "The digest of the whole ballot box matches the report", ballotBoxDigest(db) === theReport.integrity.ballotBoxDigest);

    // The audit log inside the copy.
    const chainResult = auditChainProblem(db);
    check(G5, "The audit log is an unbroken hash chain", chainResult.ok, chainResult.ok ? `${chainResult.count} entries` : chainResult.reason);

    const anchor = db.prepare("SELECT hash FROM audit_log WHERE id = ?").get(theReport.integrity.auditHeadId);
    check(G5, "The audit log contains the entry the report was anchored to", Boolean(anchor) && anchor.hash === theReport.integrity.auditHeadHash);

    const checkpointProblems = [];
    const checkpoints = db.prepare("SELECT id, auditId, auditHash, createdAt, signature FROM audit_checkpoints ORDER BY id").all();

    checkpoints.forEach((cp) => {
      const signed = verifySignature(theEnvelope.publicKey, `${CHECKPOINT_PREFIX}|${cp.auditId}|${cp.auditHash}|${cp.createdAt}`, cp.signature);
      const entry = cp.auditId === 0 ? { hash: GENESIS_HASH } : db.prepare("SELECT hash FROM audit_log WHERE id = ?").get(cp.auditId);

      if (!signed) checkpointProblems.push(`checkpoint ${cp.id}: signature invalid`);
      if (!entry || entry.hash !== cp.auditHash) checkpointProblems.push(`checkpoint ${cp.id}: does not match audit entry ${cp.auditId}`);
    });

    check(G5, "Every signed audit checkpoint is genuine and matches the log", checkpointProblems.length === 0, checkpointProblems.join("; ") || `${checkpoints.length} checkpoint(s)`);
  } catch (error) {
    fail(G5, "The audit copy could be examined", error.message);
  } finally {
    db.close();
  }
}

/* ---------- the verdict ---------- */

const failed = results.filter((result) => result.status === "fail").length;
const warnings = results.filter((result) => result.status === "warn").length;

if (options.json) {
  console.log(JSON.stringify({
    ok: failed === 0,
    failed,
    warnings,
    checks: results,
    summary: report && {
      election: report.election.name,
      sequence: report.sequence,
      ballotsCast: report.totals.ballotsCast,
      offices: report.offices.map((office) => ({
        office: office.office,
        candidates: office.candidates.map((candidate) => ({ name: candidate.name, votes: candidate.votes }))
      }))
    }
  }, null, 2));
  process.exit(failed === 0 ? 0 : 1);
}

console.log(`\nBOUESTI Vote — independent verification of ${options.file}`);

let lastGroup = null;

results.forEach((result) => {
  if (result.group !== lastGroup) {
    console.log(`\n${result.group}`);
    lastGroup = result.group;
  }

  const mark = result.status === "pass" ? "PASS" : result.status === "fail" ? "FAIL" : "WARN";
  console.log(`  ${mark}  ${result.name}${result.detail ? `\n          ${result.detail}` : ""}`);
});

if (report) {
  console.log(`\nWhat the report says — ${report.election.name}, report #${report.sequence}`);
  console.log(`  Ballots cast: ${report.totals.ballotsCast}`);

  report.offices.forEach((office) => {
    console.log(`  ${office.office}`);
    office.candidates.forEach((candidate) => console.log(`      ${String(candidate.votes).padStart(6)}  ${candidate.name}`));
  });
}

console.log("");

if (failed === 0) {
  console.log(`RESULT: VERIFIED${warnings ? ` (with ${warnings} warning${warnings === 1 ? "" : "s"} — read them above)` : ""}`);
  if (!options.auditCopy) console.log("        The ballots themselves were not recounted. Add --audit-copy <file> for the full check.");
  console.log("");
  process.exit(0);
}

console.log(`RESULT: NOT VERIFIED — ${failed} check${failed === 1 ? "" : "s"} failed. Do not rely on this report.\n`);
process.exit(1);
