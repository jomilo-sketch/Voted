"use strict";

const { freshEnv } = require("./helpers");
freshEnv();

const test = require("node:test");
const assert = require("node:assert");

const d = require("../db");
const config = require("../config");
const keys = require("../keys");
const totp = require("../totp");
const election = require("../election");
const voters = require("../voters");
const admins = require("../admins");
const audit = require("../audit");
const reports = require("../reports");

election.seedIfEmpty();

const IP = "10.2.2.2";
let eo;
let ro;
let ts;
const secrets = {};

async function enrol(seeded, role) {
  const account = seeded.find((a) => a.role === role);
  const row = admins.getByEmail(account.email);
  const password = `tulip-Harbor-47-Quartz-${role.length}`;

  const changed = await admins.changeOwnPassword(row, account.temporaryPassword, password);
  assert.ok(changed.ok, JSON.stringify(changed));

  const setup = admins.beginTotpSetup(row);
  assert.ok(admins.confirmTotpSetup(row, setup.secret, totp.generate(setup.secret)).ok);

  secrets[role] = { email: account.email, password, secret: setup.secret };
  return admins.getByEmail(account.email);
}

async function vote(matric, pick = 0) {
  let { session } = voters.login({ matric, password: "password1", ip: IP });
  session = voters.acceptRules(session).session;
  const sent = await voters.requestOtp(session, `s${matric}@bouesti.edu.ng`, IP);
  const verified = voters.verifyOtp(sent.session, config.DEMO_OTP, IP);

  const choices = {};
  election.getBallotStructure().forEach((office) => {
    choices[office.id] = office.candidates[Math.min(pick, office.candidates.length - 1)].id;
  });

  const result = voters.castVote(verified.session, choices, IP);
  assert.ok(result.ok, JSON.stringify(result));
}

test("setup: three enrolled officers and some ballots", async () => {
  const seeded = await admins.seedInitialAdmins();
  eo = await enrol(seeded, "electoral_officer");
  ro = await enrol(seeded, "results_officer");
  ts = await enrol(seeded, "technical_support");

  await vote("1001", 0);
  await vote("1002", 0);
  await vote("1003", 1);
  await vote("1004", 0);
  await vote("1005", 1);

  assert.strictEqual(election.ballotCount(), 5);
});

test("tallies are computed from the ballots, and nobody can prepare a report while voting is open", () => {
  const view = reports.tallyView();
  assert.ok(view.available && view.provisional, "rehearsal shows a provisional running tally");

  const president = view.offices[0];
  assert.deepStrictEqual(president.candidates.map((c) => c.votes), [3, 2]);
  assert.strictEqual(president.totalVotes, 5);
  assert.deepStrictEqual(view.problems, []);

  const early = reports.prepareReport(ro);
  assert.strictEqual(early.ok, false);
  assert.match(early.error, /after voting has closed/);
});

test("prepare, sign, two-person publish, and verify", () => {
  election.updateElection({ status: "closed" }, eo);

  const prepared = reports.prepareReport(ro, "final count");
  assert.ok(prepared.ok, JSON.stringify(prepared));

  // the preparer cannot publish their own report
  const self = reports.approveReport(prepared.id, ro);
  assert.strictEqual(self.ok, false);
  assert.match(self.error, /Two-person rule/);

  // a role without results.approve cannot publish
  const wrongRole = reports.approveReport(prepared.id, ts);
  assert.strictEqual(wrongRole.ok, false);

  // nothing is public yet
  assert.strictEqual(reports.getPublishedEnvelope(), null);
  assert.strictEqual(election.getElection().resultsPublished, 0);

  const approved = reports.approveReport(prepared.id, eo);
  assert.ok(approved.ok, JSON.stringify(approved));
  assert.strictEqual(election.getElection().resultsPublished, 1);

  const envelope = reports.getPublishedEnvelope();
  assert.strictEqual(envelope.status, "published");
  assert.strictEqual(envelope.publication.preparedBy, ro.email);
  assert.strictEqual(envelope.publication.approvedBy, eo.email);
  assert.strictEqual(envelope.report.totals.ballotsCast, 5);

  const verdict = reports.verifyEnvelope(envelope, keys.signingPublicKey());
  assert.ok(verdict.ok, JSON.stringify(verdict.checks.filter((c) => !c.ok)));

  // the report is anchored to the audit chain and the ballot box
  assert.match(envelope.report.integrity.ballotBoxDigest, /^[0-9a-f]{64}$/);
  assert.strictEqual(envelope.report.integrity.auditChainVerified, true);
  assert.ok(audit.listCheckpoints().some((c) => c.reason === "results published"));
});

test("a published report cannot be edited, and any tampering with the package is caught", () => {
  const row = d.get("SELECT * FROM result_reports WHERE status = 'published'");

  assert.throws(() => d.run("UPDATE result_reports SET reportJson = ? WHERE id = ?", "{}", row.id), /cannot be edited/);
  assert.throws(() => d.run("UPDATE result_reports SET signature = ? WHERE id = ?", "AAAA", row.id), /cannot be edited/);
  assert.throws(() => d.run("DELETE FROM result_reports WHERE id = ?", row.id), /cannot be deleted/);

  const original = reports.getPublishedEnvelope();
  const trusted = keys.signingPublicKey();

  // 1. change one candidate's votes
  const changed = JSON.parse(JSON.stringify(original));
  changed.report.offices[0].candidates[0].votes += 1;
  changed.reportJson = reports.canonicalJson(changed.report);
  assert.strictEqual(reports.verifyEnvelope(changed, trusted).ok, false, "edited totals break the signature");

  // 2. change the JSON text only
  const text = { ...original, reportJson: original.reportJson.replace('"ballotsCast":5', '"ballotsCast":6') };
  assert.strictEqual(reports.verifyEnvelope(text, trusted).ok, false);

  // 3. swap in someone else's key and re-sign: caught by the trusted-key check
  const attackerKeyPair = require("crypto").generateKeyPairSync("ed25519");
  const rawAttackerKey = attackerKeyPair.publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("base64");
  const forged = { ...original, publicKey: rawAttackerKey };
  assert.strictEqual(reports.verifyEnvelope(forged, trusted).ok, false);

  // 4. publication record that points at a different report
  const swapped = JSON.parse(JSON.stringify(original));
  swapped.publication.reportHash = "0".repeat(64);
  swapped.publicationJson = reports.canonicalJson(swapped.publication);
  assert.strictEqual(reports.verifyEnvelope(swapped, trusted).ok, false);

  // 5. two-person rule forged in the record
  const solo = JSON.parse(JSON.stringify(original));
  solo.publication.approvedBy = solo.publication.preparedBy;
  solo.publicationJson = reports.canonicalJson(solo.publication);
  assert.strictEqual(reports.verifyEnvelope(solo, trusted).ok, false);

  // 6. change only the readable copy that sits beside the signed text: nobody signed those numbers
  const readable = JSON.parse(JSON.stringify(original));
  readable.report.offices[0].candidates[0].votes += 1;

  const readableVerdict = reports.verifyEnvelope(readable, trusted);

  assert.strictEqual(readableVerdict.ok, false, "a changed readable copy is caught");
  assert.ok(readableVerdict.checks.some((check) => !check.ok && /readable copy/.test(check.name)), JSON.stringify(readableVerdict.checks));

  assert.ok(reports.verifyEnvelope(original, trusted).ok, "the untouched package still verifies");
});

test("supervised comparison needs a DIFFERENT, authenticated witness", async () => {
  const published = reports.getPublishedEnvelope();
  const reportId = d.get("SELECT id FROM result_reports WHERE status = 'published'").id;

  const witnessCode = () => totp.generate(secrets.electoral_officer.secret, Date.now() + 30_000);

  const same = await reports.compareWithDatabase({
    reportId, performer: ro,
    witnessEmail: ro.email, witnessPassword: secrets.results_officer.password,
    witnessCode: totp.generate(secrets.results_officer.secret, Date.now() + 30_000), ip: IP
  });
  assert.strictEqual(same.ok, false);
  assert.match(same.error, /different person/);

  const badPassword = await reports.compareWithDatabase({
    reportId, performer: ro, witnessEmail: eo.email, witnessPassword: "wrong", witnessCode: witnessCode(), ip: IP
  });
  assert.strictEqual(badPassword.ok, false);

  const badCode = await reports.compareWithDatabase({
    reportId, performer: ro, witnessEmail: eo.email, witnessPassword: secrets.electoral_officer.password, witnessCode: "000000", ip: IP
  });
  assert.strictEqual(badCode.ok, false);

  const techWitness = await reports.compareWithDatabase({
    reportId, performer: ro, witnessEmail: ts.email, witnessPassword: secrets.technical_support.password,
    witnessCode: totp.generate(secrets.technical_support.secret, Date.now() + 30_000), ip: IP
  });
  assert.strictEqual(techWitness.ok, false, "Technical Support may not witness a results comparison");

  const good = await reports.compareWithDatabase({
    reportId, performer: ro, witnessEmail: eo.email, witnessPassword: secrets.electoral_officer.password,
    witnessCode: witnessCode(), ip: IP
  });
  assert.ok(good.ok, JSON.stringify(good));
  assert.strictEqual(good.outcome, "match");
  assert.deepStrictEqual(good.differences, []);

  const stored = reports.listComparisons();
  assert.strictEqual(stored.length, 1);
  assert.strictEqual(stored[0].performedBy, ro.email);
  assert.strictEqual(stored[0].witnessBy, eo.email);
  assert.throws(() => d.run("DELETE FROM report_comparisons"), /append-only/);
  assert.ok(published);
});

test("if the database is altered after publication, the comparison reports a MISMATCH", async () => {
  const reportId = d.get("SELECT id FROM result_reports WHERE status = 'published'").id;

  // Someone with raw access removes one stored vote (rehearsal mode has no delete guard).
  const victim = d.get("SELECT ballotId, officeId FROM ballot_selections LIMIT 1");
  d.run("DELETE FROM ballot_selections WHERE ballotId = ? AND officeId = ?", victim.ballotId, victim.officeId);

  // (A real witness would simply wait for the next 30-second code; the test rewinds the replay marker instead.)
  d.run("UPDATE admins SET totpLastStep = 0 WHERE id = ?", eo.id);

  const result = await reports.compareWithDatabase({
    reportId, performer: ro, witnessEmail: eo.email, witnessPassword: secrets.electoral_officer.password,
    witnessCode: totp.generate(secrets.electoral_officer.secret, Date.now() + 30_000), ip: IP
  });

  assert.ok(result.ok, JSON.stringify(result));
  assert.strictEqual(result.outcome, "mismatch");
  assert.ok(result.differences.length >= 2, result.differences.join(" | "));
  assert.ok(result.differences.some((line) => /ballot-box digest/.test(line)));

  const log = audit.list({ category: "security" }).map((r) => r.message).join("\n");
  assert.match(log, /MISMATCH/);

  assert.strictEqual(reports.listComparisons()[0].outcome, "mismatch");
});

test("a pending report cannot be published if the database changed after it was prepared", () => {
  // Restore consistency first: this scenario starts from a fresh, untouched copy of the facts.
  const pending = reports.prepareReport(ro, "second report");
  assert.strictEqual(pending.ok, false, "the earlier tampering already blocks a new report");
  assert.ok(pending.problems.some((p) => /President: \d+ votes recorded but 5 ballots were cast/.test(p)), JSON.stringify(pending.problems));
});

test("unequal ballot/receipt counts block signing", () => {
  const receipt = d.get("SELECT codeHash FROM receipts LIMIT 1");
  d.run("DELETE FROM receipts WHERE codeHash = ?", receipt.codeHash);

  const blocked = reports.prepareReport(ro);
  assert.strictEqual(blocked.ok, false);
  assert.ok(blocked.problems.some((p) => /receipts/.test(p)));
});
