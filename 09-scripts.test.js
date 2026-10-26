"use strict";

/*
  The command-line tools, run for real as separate processes against a
  finished election: the two independent verifiers (and the ways a forger
  could try to fool them), backups, restoration drills, restoring onto a
  replacement machine, the key tool and the administrator rescue tool.
*/

const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { freshEnv } = require("./helpers");

const dir = freshEnv();

const test = require("node:test");
const assert = require("node:assert");
const { spawnSync } = require("child_process");
const { DatabaseSync } = require("node:sqlite");

const d = require("../db");
const config = require("../config");
const keys = require("../keys");
const chain = require("../chain");
const admins = require("../admins");
const audit = require("../audit");
const backup = require("../backup");
const core = require("../backup-core");
const reports = require("../reports");
const fixture = require("./fixture-election");

const ROOT = path.join(__dirname, "..");
const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "bouesti-scripts-"));
process.on("exit", () => fs.rmSync(scratch, { recursive: true, force: true }));

/* ---------- running a tool the way an operator would ---------- */

function run(script, args = [], { env = {}, dataDir = dir, input = "", cwd = ROOT, file = null } = {}) {
  const result = spawnSync(
    process.execPath,
    ["--disable-warning=ExperimentalWarning", file || path.join(ROOT, "scripts", script), ...args],
    {
      cwd,
      env: { ...process.env, DATA_DIR: dataDir, SCRYPT_N: "1024", ...env },
      input,
      encoding: "utf8",
      timeout: 90_000
    }
  );

  return { status: result.status, out: result.stdout, err: result.stderr, both: `${result.stdout}\n${result.stderr}` };
}

function json(result) {
  assert.ok(result.out.trim().startsWith("{"), `expected JSON, got: ${result.both.slice(0, 300)}`);
  return JSON.parse(result.out);
}

const failing = (verdict) => verdict.checks.filter((check) => check.status === "fail").map((check) => check.name);
const warnings = (verdict) => verdict.checks.filter((check) => check.status === "warn").map((check) => check.name);

function verifyReport(file, extra = []) {
  const result = run("verify-report.js", [file, "--json", ...extra]);
  return { status: result.status, verdict: json(result), raw: result };
}

function verifyAudit(file, extra = []) {
  const result = run("verify-audit.js", [file, "--json", ...extra]);
  return { status: result.status, verdict: json(result), raw: result };
}

/* ---------- state shared by the tests below ---------- */

let built;
let published;
let pending;
let copyPath;
let exportedHead;
let fingerprint;
const files = {};

function write(name, content) {
  const file = path.join(scratch, name);
  fs.writeFileSync(file, content);
  return file;
}

const readNdjson = (file) => fs.readFileSync(file, "utf8").trim().split("\n").map((line) => JSON.parse(line));
const writeNdjson = (name, rows) => write(name, `${rows.map((row) => JSON.stringify(row)).join("\n")}\n`);

function tamperedCopy(name, change) {
  const target = path.join(scratch, `tampered-${name}.db`);

  fs.copyFileSync(copyPath, target);
  fs.chmodSync(target, 0o644);

  const handle = new DatabaseSync(target);

  try {
    change(handle);
  } finally {
    handle.close();
  }

  return target;
}

/* An attacker with their OWN signing key and full knowledge of the formats. */
function forge(envelope, change) {
  const pair = crypto.generateKeyPairSync("ed25519");
  const rawKey = pair.publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("base64");
  const sign = (text) => crypto.sign(null, Buffer.from(text), pair.privateKey).toString("base64");

  const report = JSON.parse(JSON.stringify(envelope.report));
  const publication = envelope.publication ? JSON.parse(JSON.stringify(envelope.publication)) : null;

  change(report, publication);

  report.integrity.tallyDigest = reports.tallyDigest(report.offices);
  report.signer = { algorithm: "Ed25519", publicKey: rawKey, fingerprint: keys.publicKeyFingerprint(rawKey) };

  const reportJson = reports.canonicalJson(report);
  const forged = {
    ...envelope,
    report,
    reportJson,
    reportSignature: sign(reports.REPORT_DOMAIN + reportJson),
    publicKey: rawKey,
    publicKeyFingerprint: keys.publicKeyFingerprint(rawKey)
  };

  if (publication) {
    publication.reportHash = keys.sha256Hex(reportJson);
    forged.publication = publication;
    forged.publicationJson = reports.canonicalJson(publication);
    forged.publicationSignature = sign(reports.PUBLICATION_DOMAIN + forged.publicationJson);
  }

  return forged;
}

/* ================================================================== */
/*  setup                                                              */
/* ================================================================== */

test("setup: a finished election, a backup, an audit copy, and the files an observer would receive", async () => {
  built = await fixture.buildClosedElection();
  published = reports.getPublishedEnvelope();

  // A second report prepared afterwards, still waiting for approval.
  const second = reports.prepareReport(built.officers.results_officer.row, "recount for the observers");
  assert.ok(second.ok, JSON.stringify(second));
  pending = reports.getEnvelope(second.id);
  assert.strictEqual(pending.status, "pending");

  const made = backup.createBackup("manual", "console:setup");
  assert.ok(made.ok, JSON.stringify(made));

  const copy = backup.createAuditCopy("close", "console:setup");
  assert.ok(copy.ok, JSON.stringify(copy));
  copyPath = path.join(config.AUDIT_COPY_DIR, copy.file);

  fingerprint = keys.publicKeyFingerprint();

  files.report = write("signed-tally.json", JSON.stringify(published, null, 2));
  files.pending = write("pending-tally.json", JSON.stringify(pending, null, 2));
  files.audit = write("audit.ndjson", `${audit.exportLines().join("\n")}\n`);
  exportedHead = audit.head();

  assert.strictEqual(published.report.totals.ballotsCast, 5);
});

/* ================================================================== */
/*  verify-report.js                                                   */
/* ================================================================== */

test("verify-report: an untouched published report passes, alone and with the audit-copy recount", () => {
  const plain = run("verify-report.js", [files.report]);
  assert.strictEqual(plain.status, 0, plain.both);
  assert.match(plain.out, /RESULT: VERIFIED \(with 1 warning/);
  assert.match(plain.out, /ballots themselves were not recounted/);
  assert.match(plain.out, /Amara Okafor/);

  const full = verifyReport(files.report, ["--audit-copy", copyPath, "--trusted-fingerprint", fingerprint]);
  assert.strictEqual(full.status, 0, full.raw.both);
  assert.strictEqual(full.verdict.ok, true);
  assert.deepStrictEqual(failing(full.verdict), []);
  assert.deepStrictEqual(warnings(full.verdict), []);
  assert.ok(full.verdict.checks.length >= 25, "every group of checks ran");
  assert.ok(full.verdict.checks.some((check) => /recounting/.test(check.name) && check.status === "pass"));
  assert.strictEqual(full.verdict.summary.ballotsCast, 5);
  assert.strictEqual(full.verdict.summary.offices.length, 9);

  // the same fingerprint written the way people copy it from a printed notice
  const lowercase = verifyReport(files.report, ["--trusted-fingerprint", fingerprint.toLowerCase().replace(/ /g, "")]);
  assert.strictEqual(lowercase.status, 0, lowercase.raw.both);
});

test("verify-report: it is standalone — no project code, no database, no secrets", () => {
  ["verify-report.js", "verify-audit.js"].forEach((name) => {
    const source = fs.readFileSync(path.join(ROOT, "scripts", name), "utf8");
    const required = [...source.matchAll(/require\(\s*["']([^"']+)["']\s*\)/g)].map((match) => match[1]);

    assert.ok(required.length > 0);
    required.forEach((id) => assert.ok(id.startsWith("node:"), `${name} requires "${id}", which is not part of Node itself`));
  });

  // Copy each verifier into an empty folder, far from the project, with no data directory.
  const lonely = fs.mkdtempSync(path.join(scratch, "observer-"));
  fs.copyFileSync(path.join(ROOT, "scripts", "verify-report.js"), path.join(lonely, "verify-report.js"));
  fs.copyFileSync(path.join(ROOT, "scripts", "verify-audit.js"), path.join(lonely, "verify-audit.js"));

  const env = { DATA_DIR: path.join(lonely, "no-such-data"), BOUESTI_MASTER_KEY: "" };

  const report = run("", [files.report, "--audit-copy", copyPath, "--trusted-fingerprint", fingerprint], { cwd: lonely, env, file: path.join(lonely, "verify-report.js") });
  assert.strictEqual(report.status, 0, report.both);

  const log = run("", [files.audit], { cwd: lonely, env, file: path.join(lonely, "verify-audit.js") });
  assert.strictEqual(log.status, 0, log.both);

  assert.deepStrictEqual(fs.readdirSync(lonely).sort(), ["verify-audit.js", "verify-report.js"], "the verifiers create no files");
});

test("verify-report: usage errors exit with 2, and --help explains the tool", () => {
  assert.strictEqual(run("verify-report.js", []).status, 2);
  assert.strictEqual(run("verify-report.js", [files.report, "--bogus"]).status, 2);
  assert.strictEqual(run("verify-report.js", [path.join(scratch, "missing.json")]).status, 2);
  assert.strictEqual(run("verify-report.js", [write("garbage.json", "this is not json")]).status, 2);

  const help = run("verify-report.js", ["--help"]);
  assert.strictEqual(help.status, 0);
  assert.match(help.out, /independent verification of a signed tally report/);
  assert.match(help.out, /--audit-copy/);
});

test("verify-report: the wrong announced fingerprint is refused", () => {
  const wrong = verifyReport(files.report, ["--trusted-fingerprint", "0000 1111 2222 3333 4444 5555 6666 7777"]);

  assert.strictEqual(wrong.status, 1);
  assert.deepStrictEqual(failing(wrong.verdict), ["It is the key the officials announced"]);

  const text = run("verify-report.js", [files.report, "--trusted-fingerprint", "0000 1111 2222 3333 4444 5555 6666 7777"]);
  assert.match(text.out, /RESULT: NOT VERIFIED — 1 check failed/);
});

test("verify-report: edited votes, edited text, an edited readable copy and a replaced signature are all caught", () => {
  // 1. someone changes a vote total and re-canonicalises the text, but cannot re-sign it
  const edited = JSON.parse(JSON.stringify(published));
  edited.report.offices[0].candidates[0].votes += 1;
  edited.report.offices[0].totalVotes += 1;
  edited.reportJson = reports.canonicalJson(edited.report);

  const one = verifyReport(write("edited-votes.json", JSON.stringify(edited)));
  assert.strictEqual(one.status, 1);
  assert.ok(failing(one.verdict).includes("The report signature is valid"));

  // 2. one character of the signed text changes
  const text = { ...published, reportJson: published.reportJson.replace('"ballotsCast":5', '"ballotsCast":6') };
  const two = verifyReport(write("edited-text.json", JSON.stringify(text)));
  assert.strictEqual(two.status, 1);
  assert.ok(failing(two.verdict).includes("The report signature is valid"));

  // 3. only the readable copy (the part a human reads) is edited; the signed text is untouched
  const readable = JSON.parse(JSON.stringify(published));
  readable.report.offices[0].candidates[0].votes = 99;
  const three = verifyReport(write("edited-readable.json", JSON.stringify(readable)));
  assert.strictEqual(three.status, 1);
  assert.ok(failing(three.verdict).includes("The readable copy in the file is identical to the signed text"));

  // 4. the signature is replaced by garbage
  const four = verifyReport(write("bad-signature.json", JSON.stringify({ ...published, reportSignature: Buffer.alloc(64, 1).toString("base64") })));
  assert.strictEqual(four.status, 1);
  assert.ok(failing(four.verdict).includes("The report signature is valid"));

  // 5. not a BOUESTI report at all
  const five = verifyReport(write("other-format.json", JSON.stringify({ ...published, format: "something-else/1" })));
  assert.strictEqual(five.status, 1);
  assert.ok(failing(five.verdict).includes("It is a BOUESTI signed tally report"));
});

test("verify-report: arithmetic that does not add up is caught even when the forger signs it", () => {
  // The forger has their own key and fixes the digest, so every signature is valid.
  const lopsided = forge(published, (report) => {
    report.offices[0].candidates[0].votes += 2; // two extra votes for one candidate, total left alone
  });

  const verdict = verifyReport(write("lopsided.json", JSON.stringify(lopsided)), ["--trusted-fingerprint", fingerprint]);

  assert.strictEqual(verdict.status, 1);
  assert.ok(failing(verdict.verdict).includes("Candidate votes add up to each position's total, and ballots = receipts = turnout"));
  assert.ok(failing(verdict.verdict).includes("It is the key the officials announced"));
});

test("verify-report: a perfectly consistent forgery is exposed by the announced fingerprint, and by the recount", () => {
  // President: the forger moves one vote from the winner to the runner-up, keeping every total consistent.
  const swapped = forge(published, (report) => {
    report.offices[0].candidates[0].votes -= 1;
    report.offices[0].candidates[1].votes += 1;
  });
  const file = write("swapped-vote.json", JSON.stringify(swapped));

  // Without an announced fingerprint it is self-consistent: only a warning says so. That is why the fingerprint is announced.
  const blind = verifyReport(file);
  assert.strictEqual(blind.status, 0, "a forgery signed with the forger's own key is internally consistent");
  assert.ok(warnings(blind.verdict).includes("Not checked against an announced fingerprint"));

  const withKey = verifyReport(file, ["--trusted-fingerprint", fingerprint]);
  assert.strictEqual(withKey.status, 1);
  assert.deepStrictEqual(failing(withKey.verdict), ["It is the key the officials announced"]);

  // With the audit copy it fails even for someone who never learned the fingerprint.
  const recount = verifyReport(file, ["--audit-copy", copyPath]);
  assert.strictEqual(recount.status, 1);
  assert.ok(failing(recount.verdict).includes("Every candidate's vote count is identical after recounting"));
  assert.ok(!failing(recount.verdict).includes("The digest of the whole ballot box matches the report"), "the ballot box itself was not touched");
  assert.ok(failing(recount.verdict).includes("It was made with the same signing key as the report"));
});

test("verify-report: the two-person rule is checked, and an unpublished report is refused unless allowed", () => {
  const solo = forge(published, (report, publication) => {
    publication.approvedBy = publication.preparedBy;
  });

  const soloVerdict = verifyReport(write("solo.json", JSON.stringify(solo)), ["--trusted-fingerprint", keys.publicKeyFingerprint(solo.publicKey)]);
  assert.strictEqual(soloVerdict.status, 1);
  assert.deepStrictEqual(failing(soloVerdict.verdict), ["The person who published it is not the person who prepared it"]);

  const refused = verifyReport(files.pending);
  assert.strictEqual(refused.status, 1);
  assert.deepStrictEqual(failing(refused.verdict), ["The report has been published"]);

  const allowed = verifyReport(files.pending, ["--allow-unpublished"]);
  assert.strictEqual(allowed.status, 0, allowed.raw.both);
  assert.ok(warnings(allowed.verdict).includes("This report has not been published yet"));

  // a publication record that points at a different report
  const wrongReport = JSON.parse(JSON.stringify(published));
  wrongReport.publication.reportSequence = 7;
  wrongReport.publicationJson = reports.canonicalJson(wrongReport.publication);
  const mismatch = verifyReport(write("wrong-sequence.json", JSON.stringify(wrongReport)));
  assert.strictEqual(mismatch.status, 1);
  assert.ok(failing(mismatch.verdict).includes("The publication record is signed by the same key"));
});

test("verify-report: an audit copy that was tampered with is caught in every way we can think of", () => {
  const offices = published.report.offices;
  const president = offices[0];
  const [first, second] = president.candidates;

  const moved = tamperedCopy("moved-vote", (handle) => {
    handle.exec("DROP TRIGGER trg_selections_no_update");
    handle.prepare(
      `UPDATE ballot_selections SET candidateId = ?
       WHERE officeId = ? AND ballotId = (SELECT ballotId FROM ballot_selections WHERE officeId = ? AND candidateId = ? LIMIT 1)`
    ).run(second.candidateId, president.officeId, president.officeId, first.candidateId);
  });

  const a = verifyReport(files.report, ["--audit-copy", moved]);
  assert.strictEqual(a.status, 1);
  assert.ok(failing(a.verdict).includes("Every candidate's vote count is identical after recounting"));
  assert.ok(failing(a.verdict).includes("The digest of the whole ballot box matches the report"));

  const removed = tamperedCopy("removed-vote", (handle) => {
    handle.exec(
      "DELETE FROM ballot_selections WHERE officeId = " + president.officeId +
        " AND ballotId = (SELECT ballotId FROM ballot_selections WHERE officeId = " + president.officeId + " LIMIT 1)"
    );
  });

  const b = verifyReport(files.report, ["--audit-copy", removed]);
  assert.strictEqual(b.status, 1);
  assert.ok(failing(b.verdict).includes("Every candidate's vote count is identical after recounting"));

  const stuffed = tamperedCopy("stuffed-box", (handle) => {
    const ballotId = "f".repeat(32);
    handle.prepare("INSERT INTO ballots (ballotId) VALUES (?)").run(ballotId);

    offices.forEach((office) => {
      handle.prepare("INSERT INTO ballot_selections (ballotId, officeId, candidateId) VALUES (?, ?, ?)")
        .run(ballotId, office.officeId, office.candidates[0].candidateId);
    });
  });

  const c = verifyReport(files.report, ["--audit-copy", stuffed]);
  assert.strictEqual(c.status, 1);
  assert.ok(failing(c.verdict).includes("Ballots in the copy equal ballots in the report"));
  assert.ok(failing(c.verdict).includes("The digest of the whole ballot box matches the report"));

  const doubled = tamperedCopy("two-choices", (handle) => {
    handle.exec("DROP TRIGGER trg_selections_no_update");
    handle.exec("PRAGMA foreign_keys = OFF");
    // Give one ballot a second selection for a position: the primary key forbids it, so rebuild the table without it.
    handle.exec(`
      ALTER TABLE ballot_selections RENAME TO ballot_selections_old;
      CREATE TABLE ballot_selections (ballotId TEXT NOT NULL, officeId INTEGER NOT NULL, candidateId INTEGER NOT NULL);
      INSERT INTO ballot_selections SELECT * FROM ballot_selections_old;
      DROP TABLE ballot_selections_old;
    `);
    const row = handle.prepare("SELECT ballotId, officeId, candidateId FROM ballot_selections LIMIT 1").get();
    handle.prepare("INSERT INTO ballot_selections (ballotId, officeId, candidateId) VALUES (?, ?, ?)").run(row.ballotId, row.officeId, row.candidateId);
  });

  const e = verifyReport(files.report, ["--audit-copy", doubled]);
  assert.strictEqual(e.status, 1);
  assert.ok(failing(e.verdict).includes("No ballot has two choices for the same position"));

  const relabelled = tamperedCopy("edited-log", (handle) => {
    handle.exec("DROP TRIGGER trg_audit_no_update");
    handle.prepare("UPDATE audit_log SET message = 'nothing to see here' WHERE id = 3").run();
  });

  const f = verifyReport(files.report, ["--audit-copy", relabelled]);
  assert.strictEqual(f.status, 1);
  assert.ok(failing(f.verdict).includes("The audit log is an unbroken hash chain"));

  const rekeyed = tamperedCopy("other-key", (handle) => {
    handle.prepare("UPDATE copy_meta SET value = ? WHERE key = 'signingPublicKey'").run(Buffer.alloc(32, 9).toString("base64"));
  });

  const g = verifyReport(files.report, ["--audit-copy", rekeyed]);
  assert.strictEqual(g.status, 1);
  assert.ok(failing(g.verdict).includes("It was made with the same signing key as the report"));

  const notACopy = verifyReport(files.report, ["--audit-copy", path.join(scratch, "does-not-exist.db")]);
  assert.strictEqual(notACopy.status, 1);
  assert.ok(failing(notACopy.verdict).includes("The audit copy can be opened"));
});

/* ================================================================== */
/*  verify-audit.js                                                    */
/* ================================================================== */

test("verify-audit: an exported log and an audit copy both verify, and the head hash can be pinned", () => {
  const exported = verifyAudit(files.audit, ["--trusted-fingerprint", fingerprint, "--expect-head", exportedHead.hash, "--expect-entries", String(exportedHead.id)]);

  assert.strictEqual(exported.status, 0, exported.raw.both);
  assert.deepStrictEqual(failing(exported.verdict), []);
  assert.deepStrictEqual(warnings(exported.verdict), []);
  assert.strictEqual(exported.verdict.log.entries, exportedHead.id);
  assert.strictEqual(exported.verdict.log.last.hash, exportedHead.hash);
  assert.ok(exported.verdict.log.categories.voting === 5);

  const text = run("verify-audit.js", [files.audit]);
  assert.match(text.out, /RESULT: VERIFIED \(with 1 warning/);
  assert.match(text.out, /Head hash:\s+[0-9a-f]{64}/);

  const fromCopy = verifyAudit(copyPath);
  assert.strictEqual(fromCopy.status, 0, fromCopy.raw.both);
  assert.strictEqual(fromCopy.verdict.log.source, "audit copy");
  assert.ok(fromCopy.verdict.log.entries >= 30);

  // the live database itself can be checked, given the public key
  const live = path.join(scratch, "live-snapshot.db");
  d.db.prepare("VACUUM INTO ?").run(live);
  const snapshot = verifyAudit(live, ["--public-key", keys.signingPublicKey()]);
  assert.strictEqual(snapshot.status, 0, snapshot.raw.both);
});

test("verify-audit: usage errors exit with 2", () => {
  assert.strictEqual(run("verify-audit.js", []).status, 2);
  assert.strictEqual(run("verify-audit.js", [files.audit, "--nope"]).status, 2);
  assert.strictEqual(run("verify-audit.js", [path.join(scratch, "missing.ndjson")]).status, 2);
  assert.strictEqual(run("verify-audit.js", [write("broken.ndjson", '{"type":"entry"\nnot json')]).status, 2);
  assert.strictEqual(run("verify-audit.js", ["--help"]).status, 0);
});

test("verify-audit: wrong head hash, wrong entry count and the wrong key are refused", () => {
  const head = verifyAudit(files.audit, ["--expect-head", "0".repeat(64)]);
  assert.strictEqual(head.status, 1);
  assert.deepStrictEqual(failing(head.verdict), ["The last entry is the head hash an official wrote down"]);

  const count = verifyAudit(files.audit, ["--expect-entries", "9999"]);
  assert.strictEqual(count.status, 1);
  assert.deepStrictEqual(failing(count.verdict), ["The number of entries is what an official recorded"]);

  const key = verifyAudit(files.audit, ["--trusted-fingerprint", "0000 1111 2222 3333 4444 5555 6666 7777"]);
  assert.strictEqual(key.status, 1);
  assert.deepStrictEqual(failing(key.verdict), ["The signing key is the one the officials announced"]);

  const other = crypto.generateKeyPairSync("ed25519").publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("base64");
  const forgedKey = verifyAudit(files.audit, ["--public-key", other]);
  assert.strictEqual(forgedKey.status, 1);
  assert.deepStrictEqual(failing(forgedKey.verdict), ["Every signed checkpoint is genuine and still matches the log"]);
});

test("verify-audit: an edited entry, a removed entry, a cut-off tail and a forged checkpoint are caught", () => {
  // an entry's text is edited
  const edited = readNdjson(files.audit);
  edited.find((row) => row.type === "entry" && row.id === 10).message = "Nothing happened here";
  const a = verifyAudit(writeNdjson("edited-entry.ndjson", edited));
  assert.strictEqual(a.status, 1);
  assert.match(a.verdict.checks.find((check) => check.status === "fail").detail, /entry 10 has been altered/);

  // an entry is removed from the middle
  const gap = readNdjson(files.audit).filter((row) => !(row.type === "entry" && row.id === 12));
  const b = verifyAudit(writeNdjson("removed-entry.ndjson", gap));
  assert.strictEqual(b.status, 1);
  assert.match(b.verdict.checks.find((check) => check.status === "fail").detail, /entry 13 does not link/);

  // the most recent entries are cut off (the chain itself stays valid)
  const cut = readNdjson(files.audit).filter((row) => !(row.type === "entry" && row.id > exportedHead.id - 3));
  const c = verifyAudit(writeNdjson("cut-tail.ndjson", cut));
  assert.strictEqual(c.status, 1);
  assert.ok(failing(c.verdict).includes("The file's stated end-of-log matches its last entry"));
  assert.ok(failing(c.verdict).includes("Every signed checkpoint is genuine and still matches the log"));

  // ...and even if the cut-off file also hides the header, an official's written head hash exposes it
  const quietCut = cut.filter((row) => row.type !== "header");
  const quiet = verifyAudit(writeNdjson("cut-tail-no-header.ndjson", quietCut), ["--expect-head", exportedHead.hash, "--public-key", keys.signingPublicKey()]);
  assert.strictEqual(quiet.status, 1);
  assert.ok(failing(quiet.verdict).includes("The last entry is the head hash an official wrote down"));

  // one checkpoint's signature is replaced
  const forged = readNdjson(files.audit);
  forged.find((row) => row.type === "checkpoint").signature = Buffer.alloc(64, 3).toString("base64");
  const e = verifyAudit(writeNdjson("forged-checkpoint.ndjson", forged));
  assert.strictEqual(e.status, 1);
  assert.match(e.verdict.checks.find((check) => check.status === "fail").detail, /the signature is not valid/);

  // an empty export
  const empty = verifyAudit(write("empty.ndjson", "\n"));
  assert.strictEqual(empty.status, 1);
  assert.ok(failing(empty.verdict).includes("The file contains audit entries"));
});

test("verify-audit: a log rewritten with every hash recomputed still fails, because the signed checkpoints no longer match", () => {
  // A database administrator edits an old entry and re-computes every hash after it: the chain is internally perfect.
  const rows = readNdjson(files.audit);
  const entries = rows.filter((row) => row.type === "entry");
  const header = rows.find((row) => row.type === "header");

  const target = entries.findIndex((entry) => entry.id === 8);
  entries[target].message = "A perfectly ordinary entry";

  let previous = entries[target - 1].hash;

  for (let index = target; index < entries.length; index += 1) {
    entries[index].prevHash = previous;
    entries[index].hash = chain.computeHash(previous, entries[index].occurredAt, entries[index].actor, entries[index].category, entries[index].message);
    previous = entries[index].hash;
  }

  header.headHash = previous;

  const rewritten = verifyAudit(writeNdjson("rewritten.ndjson", rows));

  assert.strictEqual(rewritten.status, 1);
  assert.ok(!failing(rewritten.verdict).includes("Every entry links to the one before it and matches its own hash"), "the hashes were recomputed, so the chain itself is consistent");
  assert.ok(failing(rewritten.verdict).includes("Every signed checkpoint is genuine and still matches the log"));

  const detail = rewritten.verdict.checks.find((check) => /checkpoint/.test(check.name) && check.status === "fail").detail;
  assert.match(detail, /no longer has the hash that was signed/);
});

/* ================================================================== */
/*  keys.js                                                            */
/* ================================================================== */

test("keys: shows fingerprints and confirms the key opens this database", () => {
  const shown = run("keys.js");
  assert.strictEqual(shown.status, 0, shown.both);
  assert.match(shown.out, /Master key fingerprint:\s+[0-9a-f]{4}( [0-9a-f]{4}){7}/);
  assert.ok(shown.out.includes(fingerprint));
  assert.ok(shown.out.includes(keys.signingPublicKey()));
  assert.match(shown.out, /MATCH — this is the key the database was created with/);
  assert.ok(!shown.out.includes(keys.exportMasterKeyHex()), "the master key itself is never printed by default");

  const publicKey = run("keys.js", ["public"]);
  assert.strictEqual(publicKey.status, 0);
  assert.ok(publicKey.out.includes(keys.signingPublicKey()));

  const check = run("keys.js", ["check"]);
  assert.strictEqual(check.status, 0);
  assert.match(check.out, /MATCH/);
});

test("keys: a key supplied from a written-down copy is checked, and a wrong one is refused", () => {
  const right = run("keys.js", ["check"], { env: { BOUESTI_MASTER_KEY: keys.exportMasterKeyHex() } });
  assert.strictEqual(right.status, 0, right.both);
  assert.match(right.out, /MATCH/);

  const wrong = run("keys.js", ["check"], { env: { BOUESTI_MASTER_KEY: "ab".repeat(32) } });
  assert.strictEqual(wrong.status, 1);
  assert.match(wrong.out, /DOES NOT MATCH/);

  const malformed = run("keys.js", ["check"], { env: { BOUESTI_MASTER_KEY: "too short" } });
  assert.notStrictEqual(malformed.status, 0);
});

test("keys: exporting the master key needs a typed confirmation (or --yes), and shows the key once", () => {
  const refused = run("keys.js", ["export"]);
  assert.strictEqual(refused.status, 1);
  assert.match(refused.both, /typed confirmation/);
  assert.ok(!refused.both.includes(keys.exportMasterKeyHex()));

  const shown = run("keys.js", ["export", "--yes"]);
  assert.strictEqual(shown.status, 0, shown.both);

  const hex = keys.exportMasterKeyHex();
  assert.ok(shown.out.includes(hex.match(/.{1,8}/g).join("  ")), "the key appears in groups of eight characters");
  assert.match(shown.out, /Fingerprint \(to check your written copy later\)/);

  assert.strictEqual(run("keys.js", ["bogus"]).status, 1);
});

test("keys, backup, drill, restore and the admin tool never invent a database or a key", () => {
  // 1. no database at all
  const nothing = fs.mkdtempSync(path.join(scratch, "empty-machine-"));

  ["backup.js", "restore-drill.js"].forEach((script) => {
    const result = run(script, [], { dataDir: nothing });
    assert.strictEqual(result.status, 1, `${script}: ${result.both}`);
    assert.match(result.err, /There is no election database/);
  });

  const noDb = run("admin-cli.js", ["list"], { dataDir: nothing });
  assert.strictEqual(noDb.status, 1);
  assert.match(noDb.err, /There is no election database/);
  assert.deepStrictEqual(fs.readdirSync(nothing), [], "nothing was created in the empty data folder");

  // 2. a database but no master key: a new key would not open it, so none may be made
  const keyless = fs.mkdtempSync(path.join(scratch, "keyless-machine-"));
  d.db.prepare("VACUUM INTO ?").run(path.join(keyless, "election.db"));

  ["backup.js", "restore-drill.js"].forEach((script) => {
    const result = run(script, [], { dataDir: keyless });
    assert.strictEqual(result.status, 1, `${script}: ${result.both}`);
    assert.match(result.err, /No master key was found/);
  });

  const noKey = run("keys.js", [], { dataDir: keyless });
  assert.strictEqual(noKey.status, 1);
  assert.match(noKey.err, /No master key was found/);

  const noKeyAdmin = run("admin-cli.js", ["list"], { dataDir: keyless });
  assert.strictEqual(noKeyAdmin.status, 1);
  assert.match(noKeyAdmin.err, /No master key was found/);

  assert.ok(!fs.existsSync(path.join(keyless, "keys")), "no key was invented");
});

/* ================================================================== */
/*  backup.js and restore-drill.js                                     */
/* ================================================================== */

test("backup: takes an encrypted backup of the live database and records it under the operator's console name", () => {
  const before = d.get("SELECT COUNT(*) AS n FROM backup_runs WHERE status = 'ok'").n;
  const result = run("backup.js");

  assert.strictEqual(result.status, 0, result.both);
  assert.match(result.out, /Backup created/);
  assert.match(result.out, /5 ballot\(s\)/);
  assert.match(result.out, /none configured/);

  const after = d.get("SELECT COUNT(*) AS n FROM backup_runs WHERE status = 'ok'").n;
  assert.strictEqual(after, before + 1);

  const latest = backup.listBackups(1)[0];
  assert.strictEqual(latest.trigger, "manual");
  assert.ok(latest.present);
  assert.ok(fs.existsSync(core.manifestPathFor(path.join(config.BACKUP_DIR, latest.file))));

  const entry = audit.list({ category: "backup", limit: 5 }).find((row) => /Encrypted backup created \(manual\)/.test(row.message) && row.actor.startsWith("console:"));
  assert.ok(entry, "the log names the person at the console");
  assert.ok(audit.verify().ok);
});

test("drill: tests the newest backup by really restoring it, records the result, and exits 0 only on success", () => {
  const result = run("restore-drill.js");

  assert.strictEqual(result.status, 0, result.both);
  assert.match(result.out, /Restoration drill — bouesti-/);
  assert.match(result.out, /PASS {2}Audit hash-chain intact/);
  assert.match(result.out, /PASS {2}Recovery point/);
  assert.match(result.out, /RESULT: PASSED/);
  assert.ok(!/FAIL/.test(result.out));

  const recorded = backup.listDrills()[0];
  assert.strictEqual(recorded.status, "pass");
  assert.strictEqual(recorded.trigger, "manual");
  assert.deepStrictEqual(fs.readdirSync(config.DRILL_DIR), [], "the scratch restore is deleted");
});

test("drill: a damaged backup fails loudly, with exit status 1 and a security entry", () => {
  const name = "bouesti-damaged-by-test.bvbak";
  const damaged = path.join(config.BACKUP_DIR, name);

  fs.writeFileSync(damaged, Buffer.concat([core.MAGIC, Buffer.alloc(300, 5)]));
  fs.writeFileSync(core.manifestPathFor(damaged), "{}");

  try {
    const result = run("restore-drill.js", [name]);

    assert.strictEqual(result.status, 1);
    assert.match(result.out, /FAIL/);
    assert.match(result.out, /RESULT: FAILED/);
    assert.strictEqual(backup.listDrills()[0].status, "fail");
    assert.ok(audit.list({ category: "security", limit: 5 }).some((row) => /Restoration drill FAILED/.test(row.message)));
  } finally {
    fs.unlinkSync(damaged);
    fs.unlinkSync(core.manifestPathFor(damaged));
  }
});

/* ================================================================== */
/*  restore.js — onto a replacement machine                            */
/* ================================================================== */

function newestBackup() {
  const row = backup.listBackups(10).find((entry) => entry.present);
  return path.join(config.BACKUP_DIR, row.file);
}

/* A new computer: the sealed master key put back, and the backup file copied across. */
function replacementMachine({ withKey = true, withManifest = true } = {}) {
  const machine = fs.mkdtempSync(path.join(scratch, "machine-"));
  const source = newestBackup();
  const folder = path.join(machine, "incoming");

  fs.mkdirSync(folder);
  fs.copyFileSync(source, path.join(folder, path.basename(source)));

  if (withManifest) fs.copyFileSync(core.manifestPathFor(source), core.manifestPathFor(path.join(folder, path.basename(source))));
  if (withKey) fs.cpSync(config.KEY_DIR, path.join(machine, "keys"), { recursive: true });

  return { machine, file: path.join(folder, path.basename(source)) };
}

test("restore: refuses without a backup name, with a missing file, without its manifest, or without the master key", () => {
  assert.match(run("restore.js", [], { dataDir: replacementMachine().machine }).err, /Say which backup/);

  const { machine } = replacementMachine();
  assert.match(run("restore.js", [path.join(machine, "nope.bvbak"), "--yes"], { dataDir: machine }).err, /not found/);

  const bare = replacementMachine({ withManifest: false });
  const noManifest = run("restore.js", [bare.file, "--yes"], { dataDir: bare.machine });
  assert.strictEqual(noManifest.status, 1);
  assert.match(noManifest.err, /signed manifest/);

  const keyless = replacementMachine({ withKey: false });
  const noKey = run("restore.js", [keyless.file, "--yes"], { dataDir: keyless.machine });
  assert.strictEqual(noKey.status, 1);
  assert.match(noKey.err, /No master key was found/);
  assert.ok(!fs.existsSync(path.join(keyless.machine, "keys")), "no key was invented");
  assert.ok(!fs.existsSync(path.join(keyless.machine, "election.db")));
});

test("restore: the wrong master key and a damaged backup change nothing", () => {
  const wrongKey = replacementMachine({ withKey: false });
  const wrong = run("restore.js", [wrongKey.file, "--yes"], { dataDir: wrongKey.machine, env: { BOUESTI_MASTER_KEY: "cd".repeat(32) } });

  assert.strictEqual(wrong.status, 1);
  assert.match(wrong.out, /FAIL {2}Backup was made with this master key/);
  assert.match(wrong.err, /did not pass its checks, so nothing was changed/);
  assert.ok(!fs.existsSync(path.join(wrongKey.machine, "election.db")));
  assert.ok(!fs.existsSync(path.join(wrongKey.machine, "restore-marker.json")));

  const damaged = replacementMachine();
  const bytes = Buffer.from(fs.readFileSync(damaged.file));
  bytes[Math.floor(bytes.length / 2)] ^= 0xff;
  fs.writeFileSync(damaged.file, bytes);

  const flipped = run("restore.js", [damaged.file, "--yes"], { dataDir: damaged.machine });
  assert.strictEqual(flipped.status, 1);
  assert.match(flipped.out, /FAIL/);
  assert.ok(!fs.existsSync(path.join(damaged.machine, "election.db")));
  assert.ok(!fs.existsSync(path.join(damaged.machine, "restore-marker.json")));
});

test("restore: shows what is inside first, and will not run without a typed confirmation or while the server runs", () => {
  const { machine, file } = replacementMachine();

  const unconfirmed = run("restore.js", [file], { dataDir: machine });
  assert.strictEqual(unconfirmed.status, 1);
  assert.match(unconfirmed.out, /Ballots inside:\s+5/);
  assert.match(unconfirmed.err, /typed confirmation/);
  assert.ok(!fs.existsSync(path.join(machine, "election.db")), "nothing was restored");

  // a running server (its process id is in the pid file) blocks the restore
  fs.writeFileSync(path.join(machine, "server.pid"), `${process.pid}\n`);

  const running = run("restore.js", [file, "--yes"], { dataDir: machine });
  assert.strictEqual(running.status, 1);
  assert.match(running.err, /server appears to be running/);
  assert.ok(!fs.existsSync(path.join(machine, "election.db")));

  // a leftover pid file from a crash (no such process) does not block it
  fs.writeFileSync(path.join(machine, "server.pid"), "2147483000\n");
  const leftover = run("restore.js", [file, "--yes"], { dataDir: machine });
  assert.strictEqual(leftover.status, 0, leftover.both);
  assert.ok(fs.existsSync(path.join(machine, "election.db")));
});

test("restore: a replacement machine comes up with the ballots, the audit chain intact and the restore recorded", () => {
  const { machine, file } = replacementMachine();
  const result = run("restore.js", [file, "--yes"], { dataDir: machine });

  assert.strictEqual(result.status, 0, result.both);
  assert.match(result.out, /Ballots inside:\s+5/);
  assert.match(result.out, /does not exist/);
  assert.match(result.out, /5 ballot\(s\)/);
  assert.match(result.out, /no previous database to keep/);
  assert.deepStrictEqual(fs.readdirSync(machine).filter((name) => name.startsWith("pre-restore-")), [], "no empty safety folder is left");
  assert.ok(fs.existsSync(path.join(machine, "restore-marker.json")));

  // the key tool agrees the restored database belongs to this key
  const check = run("keys.js", ["check"], { dataDir: machine });
  assert.strictEqual(check.status, 0, check.both);
  assert.match(check.out, /MATCH/);

  // the restored database's audit log verifies independently
  const restoredLog = verifyAudit(path.join(machine, "election.db"), ["--public-key", keys.signingPublicKey()]);
  assert.strictEqual(restoredLog.status, 0, restoredLog.raw.both);

  // the administrators came back
  const list = run("admin-cli.js", ["list"], { dataDir: machine });
  assert.strictEqual(list.status, 0, list.both);
  assert.match(list.out, /electoral@bouesti\.ng/);

  // the server's next start writes the restore into the audit log
  const script = write("boot-restored.js", `
    const { bootstrap } = require(${JSON.stringify(path.join(ROOT, "startup.js"))});
    const audit = require(${JSON.stringify(path.join(ROOT, "audit.js"))});
    bootstrap().then((result) => {
      const lines = audit.list({ category: "backup", limit: 5 }).map((row) => row.message);
      console.log(JSON.stringify({ restored: result.restored && result.restored.backup, lines, chainOk: audit.verify().ok }));
      require(${JSON.stringify(path.join(ROOT, "db.js"))}).close();
    });
  `);

  const started = run("", [], { dataDir: machine, file: script });
  assert.strictEqual(started.status, 0, started.both);

  const seen = JSON.parse(started.out.trim().split("\n").pop());
  assert.strictEqual(seen.restored, path.basename(file));
  assert.ok(seen.lines.some((line) => /DATABASE RESTORED/.test(line)));
  assert.strictEqual(seen.chainOk, true);
  assert.ok(!fs.existsSync(path.join(machine, "restore-marker.json")), "the marker is used once");
});

test("restore: the existing database is moved aside, never deleted", () => {
  const { machine, file } = replacementMachine();

  fs.writeFileSync(path.join(machine, "election.db"), "the damaged database, as it was");

  const result = run("restore.js", [file, "--yes"], { dataDir: machine });
  assert.strictEqual(result.status, 0, result.both);
  assert.match(result.out, /WILL BE MOVED ASIDE/);

  const kept = fs.readdirSync(machine).filter((name) => name.startsWith("pre-restore-"));
  assert.strictEqual(kept.length, 1);
  assert.strictEqual(fs.readFileSync(path.join(machine, kept[0], "election.db"), "utf8"), "the damaged database, as it was");
  assert.ok(result.out.includes(path.join(machine, kept[0])));

  const restored = new DatabaseSync(path.join(machine, "election.db"), { readOnly: true });
  assert.strictEqual(restored.prepare("SELECT COUNT(*) AS n FROM ballots").get().n, 5);
  restored.close();
});

/* ================================================================== */
/*  admin-cli.js                                                       */
/* ================================================================== */

test("admin tool: lists administrators and roles without revealing any secret", () => {
  const list = run("admin-cli.js", ["list"]);

  assert.strictEqual(list.status, 0, list.both);
  ["electoral@bouesti.ng", "results@bouesti.ng", "tech@bouesti.ng"].forEach((email) => assert.ok(list.out.includes(email), email));
  assert.match(list.out, /Electoral Officer\s+active\s+2FA on/);
  assert.ok(!/scrypt/.test(list.both), "no password hash");

  Object.values(built.officers).forEach((officer) => {
    assert.ok(!list.both.includes(officer.secret), "no two-factor secret");
    assert.ok(!list.both.includes(officer.password), "no password");
  });

  const roles = run("admin-cli.js", ["roles"]);
  assert.strictEqual(roles.status, 0);
  ["electoral_officer", "results_officer", "technical_support"].forEach((role) => assert.ok(roles.out.includes(role), role));

  assert.strictEqual(run("admin-cli.js", ["frobnicate"]).status, 1);
  assert.strictEqual(run("admin-cli.js", []).status, 1);
  assert.match(run("admin-cli.js", ["unlock", "nobody@example.com"]).err, /No administrator has the e-mail address/);
  assert.match(run("admin-cli.js", ["unlock"]).err, /Say which administrator/);
});

test("admin tool: unlocks a locked account and records who did it", () => {
  d.run("UPDATE admins SET failedAttempts = 0, lockedUntil = ? WHERE email = 'tech@bouesti.ng'", Date.now() + 15 * 60_000);
  assert.match(run("admin-cli.js", ["list"]).out, /tech@bouesti\.ng\s+Technical Support Officer\s+LOCKED/);

  const result = run("admin-cli.js", ["unlock", "tech@bouesti.ng"]);
  assert.strictEqual(result.status, 0, result.both);
  assert.match(result.out, /tech@bouesti\.ng is unlocked/);

  assert.strictEqual(admins.getByEmail("tech@bouesti.ng").lockedUntil, 0);

  const entry = audit.list({ category: "admin", limit: 5 }).find((row) => /Unlocked account tech@bouesti\.ng/.test(row.message));
  assert.ok(entry);
  assert.match(entry.actor, /^console:/);

  // not a live election, so no extra security notice
  assert.ok(!audit.list({ category: "security", limit: 20 }).some((row) => /Console administrator action/.test(row.message)));
});

test("admin tool: sign-in history is shown, and looking at it is itself logged", () => {
  const target = admins.getByEmail("results@bouesti.ng");
  admins.recordHistory(target.id, target.email, "10.0.0.7", "password-failed");
  admins.recordHistory(target.id, target.email, "10.0.0.8", "login-success");

  const result = run("admin-cli.js", ["history", "results@bouesti.ng"]);
  assert.strictEqual(result.status, 0, result.both);
  assert.match(result.out, /password-failed\s+10\.0\.0\.7/);
  assert.match(result.out, /login-success\s+10\.0\.0\.8/);

  assert.ok(audit.list({ category: "admin", limit: 5 }).some((row) => /Viewed the sign-in history of results@bouesti\.ng/.test(row.message) && row.actor.startsWith("console:")));
});

test("admin tool: issues a one-time reset code that really lets the person choose a new password", async () => {
  const result = run("admin-cli.js", ["reset-code", "results@bouesti.ng"]);
  assert.strictEqual(result.status, 0, result.both);

  const code = result.out.match(/\b([A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5})\b/);
  assert.ok(code, result.out);
  assert.match(result.out, /30 minutes, single use/);
  assert.ok(!/scrypt/.test(result.both));

  const redeemed = await admins.redeemResetCode("results@bouesti.ng", code[1], "Lantern-Quartz-Harbor-2291-Moss", "10.0.0.9");
  assert.ok(redeemed.ok, JSON.stringify(redeemed));

  const again = await admins.redeemResetCode("results@bouesti.ng", code[1], "Another-Long-Phrase-5518-River", "10.0.0.9");
  assert.strictEqual(again.ok, false, "a reset code works once");

  assert.ok((await admins.checkPassword("results@bouesti.ng", "Lantern-Quartz-Harbor-2291-Moss", "10.0.0.9")).ok);
  assert.ok(audit.list({ category: "admin", limit: 10 }).some((row) => /reset code issued for results@bouesti\.ng/.test(row.message) && row.actor.startsWith("console:")));
});

test("admin tool: dangerous actions need a typed confirmation or --yes", () => {
  ["reset-2fa", "disable"].forEach((command) => {
    const refused = run("admin-cli.js", [command, "results@bouesti.ng"]);
    assert.strictEqual(refused.status, 1, command);
    assert.match(refused.err, /typed confirmation/);
  });

  const create = run("admin-cli.js", ["create", "new.officer@bouesti.ng", "results_officer", "New Officer"]);
  assert.strictEqual(create.status, 1);
  assert.strictEqual(admins.getByEmail("new.officer@bouesti.ng"), null);

  assert.ok(admins.getByEmail("results@bouesti.ng").totpEnabled, "nothing was changed");
  assert.strictEqual(admins.getByEmail("results@bouesti.ng").disabled, 0);
});

test("admin tool: resets two-factor, disables and re-enables, and protects the last Electoral Officer", () => {
  const reset = run("admin-cli.js", ["reset-2fa", "results@bouesti.ng", "--yes"]);
  assert.strictEqual(reset.status, 0, reset.both);
  assert.strictEqual(admins.getByEmail("results@bouesti.ng").totpEnabled, 0);
  assert.match(run("admin-cli.js", ["list"]).out, /results@bouesti\.ng\s+Results Officer\s+active\s+2FA OFF/);

  const off = run("admin-cli.js", ["disable", "tech@bouesti.ng", "--yes"]);
  assert.strictEqual(off.status, 0, off.both);
  assert.strictEqual(admins.getByEmail("tech@bouesti.ng").disabled, 1);
  assert.match(run("admin-cli.js", ["list"]).out, /tech@bouesti\.ng\s+Technical Support Officer\s+DISABLED/);

  const on = run("admin-cli.js", ["enable", "tech@bouesti.ng"]);
  assert.strictEqual(on.status, 0, on.both);
  assert.strictEqual(admins.getByEmail("tech@bouesti.ng").disabled, 0);

  const last = run("admin-cli.js", ["disable", "electoral@bouesti.ng", "--yes"]);
  assert.strictEqual(last.status, 1);
  assert.match(last.err, /At least one active Electoral Officer must remain/);
  assert.strictEqual(admins.getByEmail("electoral@bouesti.ng").disabled, 0);
});

test("admin tool: creates an account with a one-time temporary password that must be changed", async () => {
  const result = run("admin-cli.js", ["create", "witness@bouesti.ng", "results_officer", "Dr.", "A.", "Witness", "--yes"]);
  assert.strictEqual(result.status, 0, result.both);

  const temporary = result.out.match(/Temporary password: (\S+)/);
  assert.ok(temporary, result.out);
  assert.match(result.out, /must change it, and enrol two-factor/);

  const row = admins.getByEmail("witness@bouesti.ng");
  assert.strictEqual(row.role, "results_officer");
  assert.strictEqual(row.displayName, "Dr. A. Witness");
  assert.strictEqual(row.mustChangePassword, 1);
  assert.ok((await admins.checkPassword("witness@bouesti.ng", temporary[1], "10.0.0.5")).ok);

  const duplicate = run("admin-cli.js", ["create", "witness@bouesti.ng", "results_officer", "Someone Else", "--yes"]);
  assert.strictEqual(duplicate.status, 1);
  assert.match(duplicate.err, /already exists/);

  const badRole = run("admin-cli.js", ["create", "boss@bouesti.ng", "president", "The Boss", "--yes"]);
  assert.strictEqual(badRole.status, 1);
  assert.match(badRole.err, /valid role/);

  const usage = run("admin-cli.js", ["create", "boss@bouesti.ng", "--yes"]);
  assert.strictEqual(usage.status, 1);
  assert.match(usage.err, /Use: npm run admin -- create/);
});

test("admin tool: during a LIVE election every console action is also logged as a security entry", () => {
  d.run("UPDATE election SET mode = 'live' WHERE id = 1");

  const result = run("admin-cli.js", ["unlock", "electoral@bouesti.ng"]);
  assert.strictEqual(result.status, 0, result.both);

  const notice = audit.list({ category: "security", limit: 10 }).find((row) => /Console administrator action during the live election: unlocked electoral@bouesti\.ng/.test(row.message));
  assert.ok(notice, "the other officers will see this in the security log");
  assert.match(notice.actor, /^console:/);

  assert.ok(audit.verify().ok, "every entry the tools added is part of a valid chain");
});

/* ================================================================== */
/*  housekeeping                                                       */
/* ================================================================== */

test("every npm script points at a file that exists", () => {
  const pkg = require("../package.json");
  const named = Object.entries(pkg.scripts)
    .map(([name, command]) => [name, (command.match(/scripts\/[\w-]+\.js|\bserver\.js/) || [])[0]])
    .filter(([, file]) => file);

  assert.ok(named.length >= 9);

  named.forEach(([name, file]) => {
    assert.ok(fs.existsSync(path.join(ROOT, file)), `npm run ${name} points at ${file}, which does not exist`);
  });

  ["backup", "drill", "restore", "keys", "admin", "verify-report", "verify-audit", "start", "test"].forEach((name) => {
    assert.ok(pkg.scripts[name], `npm run ${name} exists`);
  });

  assert.deepStrictEqual(Object.keys(pkg.dependencies), ["express"], "Express is the only runtime dependency");
  assert.ok(dir && core);
});
