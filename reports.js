/*
  BOUESTI Vote — counting, signed tally reports, and independent verification.

  The count
    Tallies are computed from the ballot tables only (never from a cached
    figure). Officials can see them only once the election is CLOSED (in
    rehearsal mode they can also see a running tally, to test the screens).

  The report
    A frozen, canonical-JSON document containing every vote total, the
    ballot/turnout/receipt counts, a digest of the whole ballot box, and the
    head of the audit chain at that moment — signed with the server's
    Ed25519 key (keys.js). The signature covers every byte, so changing a
    single vote total invalidates it.

  Two-person publication
    The Results Officer PREPARES (counts and signs). A DIFFERENT
    administrator with results.approve (the Electoral Officer) PUBLISHES.
    The approval is itself signed (the "publication record").

  Independent checks
    * scripts/verify-report.js re-checks both signatures, the arithmetic,
      and — given an audit copy — re-counts the ballots from scratch.
    * compareWithDatabase() lets two officials, one witnessing the other,
      compare the live database to the published report. Each comparison is
      stored permanently.
*/

"use strict";

const crypto = require("crypto");
const d = require("./db");
const keys = require("./keys");
const audit = require("./audit");
const election = require("./election");
const admins = require("./admins");
const { can } = require("./permissions");

const REPORT_FORMAT = "bouesti-vote-result-report/1";
const PUBLICATION_FORMAT = "bouesti-vote-publication/1";
const REPORT_DOMAIN = "bouesti-vote/result-report/v1\n";
const PUBLICATION_DOMAIN = "bouesti-vote/publication/v1\n";

/* ---------- canonical JSON: sorted keys, so the same data always gives the same bytes ---------- */

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

/* ---------- counting ---------- */

function canSeeTally() {
  const current = election.getElection();
  return current.status === "closed" || current.mode === "rehearsal";
}

function computeTally() {
  const offices = election.getOffices();

  const counts = new Map(
    d.all("SELECT candidateId, COUNT(*) AS n FROM ballot_selections GROUP BY candidateId").map((row) => [row.candidateId, row.n])
  );

  const ballots = election.ballotCount();

  const result = offices.map((office) => {
    const candidates = office.candidates.map((candidate) => ({
      candidateId: candidate.id,
      name: candidate.name,
      votes: counts.get(candidate.id) || 0
    }));

    return {
      officeId: office.id,
      office: office.office,
      // Offices with an approved candidate were on every ballot, so each
      // must hold exactly one vote per ballot cast.
      onBallot: office.candidates.some((candidate) => candidate.status === "approved"),
      totalVotes: candidates.reduce((sum, candidate) => sum + candidate.votes, 0),
      candidates
    };
  });

  return {
    offices: result,
    ballotsCast: ballots,
    turnoutRecords: election.turnoutCount(),
    receiptsIssued: d.get("SELECT COUNT(*) AS n FROM receipts").n
  };
}

/* Digest of the entire ballot box: one line per ballot, sorted by its
   random id. Anyone holding the audit copy can recompute it. */
function ballotBoxDigest() {
  const hash = crypto.createHash("sha256");
  const rows = d.db.prepare(
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

function tallyDigest(offices) {
  return keys.sha256Hex(canonicalJson(offices));
}

/* Arithmetic the totals must satisfy. Used when preparing AND verifying. */
function consistencyProblems(figures) {
  const problems = [];
  const { ballotsCast, turnoutRecords, receiptsIssued, offices } = figures;

  if (ballotsCast !== turnoutRecords) {
    problems.push(`Ballots cast (${ballotsCast}) do not equal turnout records (${turnoutRecords}).`);
  }

  if (ballotsCast !== receiptsIssued) {
    problems.push(`Ballots cast (${ballotsCast}) do not equal receipts issued (${receiptsIssued}).`);
  }

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

/* ---------- views for officials ---------- */

function listReports() {
  return d.all(
    `SELECT id, reportHash, preparedBy, preparedAt, status, approvedBy, approvedAt, note
     FROM result_reports ORDER BY id DESC`
  );
}

function getReportRow(id) {
  return d.get("SELECT * FROM result_reports WHERE id = ?", Number(id)) || null;
}

function tallyView() {
  const current = election.getElection();

  if (!canSeeTally()) {
    return {
      available: false,
      reason: "Results stay sealed until voting closes. Only turnout statistics are available while the election is open.",
      status: current.status,
      mode: current.mode
    };
  }

  const tally = computeTally();

  return {
    available: true,
    status: current.status,
    mode: current.mode,
    provisional: current.status !== "closed",
    ...tally,
    problems: consistencyProblems(tally),
    reports: listReports(),
    resultsPublished: Boolean(current.resultsPublished)
  };
}

/* ---------- preparing a signed report (Results Officer) ---------- */

function prepareReport(admin, note = "") {
  const current = election.getElection();

  if (current.status !== "closed") {
    return { ok: false, error: "A report can only be prepared after voting has closed." };
  }

  const tally = computeTally();
  const problems = consistencyProblems(tally);

  if (problems.length) {
    return {
      ok: false,
      error: "The counts do not agree, so no report can be signed. Open an incident and investigate first.",
      problems
    };
  }

  const head = audit.head();
  const chainCheck = audit.verify();

  if (!chainCheck.ok) {
    return { ok: false, error: "The audit log failed verification, so no report can be signed. Open an incident." };
  }

  const sequence = d.get("SELECT COUNT(*) + 1 AS n FROM result_reports").n;
  const generatedAt = d.nowIso();

  const report = {
    format: REPORT_FORMAT,
    sequence,
    generatedAt,
    election: {
      name: current.electionName,
      school: current.schoolName,
      mode: current.mode,
      votingOpensAt: current.votingOpensAt,
      votingClosesAt: current.votingClosesAt,
      openedAt: current.openedAt,
      closedAt: current.closedAt
    },
    totals: {
      ballotsCast: tally.ballotsCast,
      turnoutRecords: tally.turnoutRecords,
      receiptsIssued: tally.receiptsIssued
    },
    offices: tally.offices,
    integrity: {
      ballotBoxDigest: ballotBoxDigest(),
      tallyDigest: tallyDigest(tally.offices),
      auditHeadId: head.id,
      auditHeadHash: head.hash,
      auditChainVerified: true
    },
    signer: {
      algorithm: "Ed25519",
      publicKey: keys.signingPublicKey(),
      fingerprint: keys.publicKeyFingerprint()
    }
  };

  const reportJson = canonicalJson(report);
  const signature = keys.sign(REPORT_DOMAIN + reportJson);

  const id = d.tx(() => {
    d.run("UPDATE result_reports SET status = 'superseded' WHERE status = 'pending'");

    const result = d.run(
      `INSERT INTO result_reports (reportJson, reportHash, signature, preparedBy, preparedAt, status, note)
       VALUES (?, ?, ?, ?, ?, 'pending', ?)`,
      reportJson, keys.sha256Hex(reportJson), signature, admin.email, generatedAt, String(note).slice(0, 300)
    );

    audit.append(
      audit.adminActor(admin), "report",
      `Prepared and signed result report #${sequence} (${tally.ballotsCast} ballots; hash ${keys.sha256Hex(reportJson).slice(0, 16)}…)`
    );
    audit.checkpoint("result report prepared");

    return Number(result.lastInsertRowid);
  });

  return { ok: true, id, sequence };
}

/* ---------- approving and publishing (a DIFFERENT administrator) ---------- */

function approveReport(reportId, admin) {
  const row = getReportRow(reportId);

  if (!row) return { ok: false, error: "Report not found." };
  if (row.status !== "pending") return { ok: false, error: `This report is ${row.status}, not waiting for approval.` };

  if (row.preparedBy.toLowerCase() === admin.email.toLowerCase()) {
    return { ok: false, error: "Two-person rule: the person who prepared a report cannot also publish it." };
  }

  if (!can(admin.role, "results.approve")) {
    return { ok: false, error: "Your role cannot approve results for publication." };
  }

  // The database must still say exactly what the report says.
  const report = JSON.parse(row.reportJson);
  const live = computeTally();

  if (
    tallyDigest(live.offices) !== report.integrity.tallyDigest ||
    ballotBoxDigest() !== report.integrity.ballotBoxDigest
  ) {
    return {
      ok: false,
      error: "The database no longer matches this report. Do not publish. Open an incident and prepare a new report."
    };
  }

  const approvedAt = d.nowIso();
  const publication = {
    format: PUBLICATION_FORMAT,
    reportId: row.id,
    reportSequence: report.sequence,
    reportHash: row.reportHash,
    preparedBy: row.preparedBy,
    preparedAt: row.preparedAt,
    approvedBy: admin.email,
    approvedAt
  };

  const publicationJson = canonicalJson(publication);
  const publicationSignature = keys.sign(PUBLICATION_DOMAIN + publicationJson);

  d.tx(() => {
    d.run("UPDATE result_reports SET status = 'superseded' WHERE status = 'published'");

    d.run(
      `UPDATE result_reports SET status = 'published', approvedBy = ?, approvedAt = ?,
         publicationJson = ?, publicationSignature = ? WHERE id = ?`,
      admin.email, approvedAt, publicationJson, publicationSignature, row.id
    );

    d.run("UPDATE election SET resultsPublished = 1, updatedAt = ?, updatedBy = ? WHERE id = 1", approvedAt, admin.email);

    audit.append(
      audit.adminActor(admin), "report",
      `Approved and PUBLISHED result report #${report.sequence}, prepared by ${row.preparedBy}`
    );
    audit.checkpoint("results published");
  });

  return { ok: true };
}

function rejectReport(reportId, admin, reason) {
  const row = getReportRow(reportId);
  if (!row) return { ok: false, error: "Report not found." };
  if (row.status !== "pending") return { ok: false, error: "Only a report waiting for approval can be rejected." };

  const text = String(reason ?? "").replace(/\s+/g, " ").trim();
  if (text.length < 5) return { ok: false, error: "Give a short reason for rejecting the report." };

  d.tx(() => {
    d.run("UPDATE result_reports SET status = 'rejected', note = ? WHERE id = ?", text.slice(0, 300), row.id);
    audit.append(audit.adminActor(admin), "report", `Rejected result report #${JSON.parse(row.reportJson).sequence}: ${text.slice(0, 200)}`);
  });

  return { ok: true };
}

/* ---------- the downloadable, verifiable package ---------- */

function envelopeFor(row) {
  if (!row) return null;

  return {
    format: "bouesti-vote-signed-tally/1",
    note: "Verify with: node scripts/verify-report.js <this file> [--audit-copy <audit-copy.db>]",
    report: JSON.parse(row.reportJson),
    reportJson: row.reportJson,
    reportSignature: row.signature,
    status: row.status,
    publication: row.publicationJson ? JSON.parse(row.publicationJson) : null,
    publicationJson: row.publicationJson,
    publicationSignature: row.publicationSignature,
    publicKey: keys.signingPublicKey(),
    publicKeyFingerprint: keys.publicKeyFingerprint()
  };
}

function getEnvelope(reportId) {
  return envelopeFor(getReportRow(reportId));
}

function getPublishedEnvelope() {
  const row = d.get("SELECT * FROM result_reports WHERE status = 'published' ORDER BY id DESC LIMIT 1");
  return envelopeFor(row);
}

/* Pure check of a downloaded package — no database needed. */
function verifyEnvelope(envelope, trustedPublicKey = null) {
  const checks = [];
  const add = (name, ok, detail = "") => checks.push({ name, ok: Boolean(ok), detail });

  try {
    const publicKey = trustedPublicKey || envelope.publicKey;

    add(
      "Signing key matches the one you trust",
      !trustedPublicKey || trustedPublicKey === envelope.publicKey,
      trustedPublicKey ? "" : "No trusted key supplied — compare the fingerprint with the one the officials announced."
    );

    add("Report text matches its parsed form", canonicalJson(JSON.parse(envelope.reportJson)) === envelope.reportJson);

    /*
      The file carries the report twice: the exact signed text, and a readable
      copy beside it. Only the text is signed, so a changed readable copy must be
      caught here, or a person reading the copy would see numbers nobody signed.
    */
    add(
      "The readable copy in the file is identical to the signed text",
      Boolean(envelope.report) && canonicalJson(envelope.report) === envelope.reportJson
    );

    add("Report signature is valid", keys.verifySignature(publicKey, REPORT_DOMAIN + envelope.reportJson, envelope.reportSignature));

    const report = JSON.parse(envelope.reportJson);

    add(
      "The key written in the file is the key inside the signed report",
      Boolean(report.signer) && report.signer.publicKey === envelope.publicKey &&
        envelope.publicKeyFingerprint === keys.publicKeyFingerprint(envelope.publicKey)
    );

    const problems = consistencyProblems({ ...report.totals, offices: report.offices });
    add("Totals are arithmetically consistent", problems.length === 0, problems.join(" "));
    add("Tally digest matches the vote totals", tallyDigest(report.offices) === report.integrity.tallyDigest);

    if (envelope.status === "published" || envelope.publicationJson) {
      const publication = JSON.parse(envelope.publicationJson);

      add("Publication record is signed", keys.verifySignature(publicKey, PUBLICATION_DOMAIN + envelope.publicationJson, envelope.publicationSignature));
      add(
        "Publication refers to this exact report",
        publication.reportHash === keys.sha256Hex(envelope.reportJson) && publication.reportSequence === report.sequence
      );
      add("Two-person rule: preparer and approver differ", publication.preparedBy.toLowerCase() !== publication.approvedBy.toLowerCase());
    } else {
      add("Publication record present", false, "This report has not been published.");
    }
  } catch (error) {
    add("Package could be read", false, error.message);
  }

  return { ok: checks.every((check) => check.ok), checks };
}

/* ---------- supervised comparison: live database vs published report ---------- */

async function compareWithDatabase({ reportId, performer, witnessEmail, witnessPassword, witnessCode, ip }) {
  const row = getReportRow(reportId);
  if (!row || row.status !== "published") {
    return { ok: false, error: "Only a published report can be compared. Publish one first." };
  }

  // The witness proves who they are with their own password and 2FA code.
  const witnessLogin = await admins.checkPassword(witnessEmail, witnessPassword, ip);
  if (!witnessLogin.ok) return { ok: false, error: "The witness's e-mail or password was not accepted." };

  const witness = witnessLogin.admin;

  if (witness.id === performer.id) {
    return { ok: false, error: "The witness must be a different person from the one running the comparison." };
  }

  if (!can(witness.role, "results.compare")) {
    return { ok: false, error: "The witness's role is not allowed to supervise a comparison." };
  }

  const second = admins.checkSecondFactor(witness, witnessCode, ip);
  if (!second.ok) return { ok: false, error: "The witness's 2FA code was not accepted." };

  const report = JSON.parse(row.reportJson);
  const live = computeTally();
  const differences = [];

  report.offices.forEach((office) => {
    const liveOffice = live.offices.find((o) => o.officeId === office.officeId);

    if (!liveOffice) {
      differences.push(`${office.office}: position missing from the database.`);
      return;
    }

    office.candidates.forEach((candidate) => {
      const liveCandidate = liveOffice.candidates.find((c) => c.candidateId === candidate.candidateId);

      if (!liveCandidate) differences.push(`${office.office} / ${candidate.name}: candidate missing from the database.`);
      else if (liveCandidate.votes !== candidate.votes) {
        differences.push(`${office.office} / ${candidate.name}: report ${candidate.votes}, database ${liveCandidate.votes}.`);
      }
    });
  });

  if (live.ballotsCast !== report.totals.ballotsCast) {
    differences.push(`Ballots cast: report ${report.totals.ballotsCast}, database ${live.ballotsCast}.`);
  }

  if (live.turnoutRecords !== report.totals.turnoutRecords) {
    differences.push(`Turnout records: report ${report.totals.turnoutRecords}, database ${live.turnoutRecords}.`);
  }

  if (ballotBoxDigest() !== report.integrity.ballotBoxDigest) {
    differences.push("The ballot-box digest differs: the stored ballots are not the ones that were counted.");
  }

  const anchor = d.get("SELECT hash FROM audit_log WHERE id = ?", report.integrity.auditHeadId);
  if (!anchor || anchor.hash !== report.integrity.auditHeadHash) {
    differences.push("The audit log no longer contains the entry the report was anchored to.");
  }

  const chain = audit.verify();
  if (!chain.ok) differences.push("The audit chain fails verification.");

  const outcome = differences.length === 0 ? "match" : "mismatch";
  const detail = {
    reportSequence: report.sequence,
    ballotsCast: live.ballotsCast,
    differences
  };

  d.tx(() => {
    d.run(
      `INSERT INTO report_comparisons (reportId, performedBy, witnessBy, at, outcome, detailJson)
       VALUES (?, ?, ?, ?, ?, ?)`,
      row.id, performer.email, witness.email, d.nowIso(), outcome, JSON.stringify(detail)
    );

    audit.append(
      audit.adminActor(performer), "report",
      `Supervised comparison of database against published report #${report.sequence}, witnessed by ${witness.email}: ${outcome.toUpperCase()}` +
        (differences.length ? ` (${differences.length} difference(s))` : "")
    );

    if (outcome === "mismatch") {
      audit.append("system", "security", "A supervised comparison found a MISMATCH between the database and the published report");
    }
  });

  return { ok: true, outcome, differences, witness: witness.email };
}

function listComparisons(limit = 30) {
  return d.all(
    `SELECT c.id, c.reportId, c.performedBy, c.witnessBy, c.at, c.outcome, c.detailJson
     FROM report_comparisons c ORDER BY c.id DESC LIMIT ?`,
    limit
  ).map((row) => ({ ...row, detail: JSON.parse(row.detailJson), detailJson: undefined }));
}

module.exports = {
  REPORT_DOMAIN,
  PUBLICATION_DOMAIN,
  canonicalJson,
  canSeeTally,
  computeTally,
  ballotBoxDigest,
  tallyDigest,
  consistencyProblems,
  tallyView,
  listReports,
  getReportRow,
  prepareReport,
  approveReport,
  rejectReport,
  getEnvelope,
  getPublishedEnvelope,
  verifyEnvelope,
  compareWithDatabase,
  listComparisons
};
