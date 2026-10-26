/*
  BOUESTI Vote — the voter's journey, and the roster behind it.

      sign in  ->  accept rules  ->  e-mail code  ->  ballot  ->  submit

  Every step is decided HERE, on the server. The browser only displays
  what this file says:

    stage "login"     matric (digits only) + the one shared password
    stage "rules"     election rules accepted        => student is REGISTERED
    stage "verified"  e-mail code entered correctly  => student is VERIFIED
    ballot accepted   session is deleted

  Ballot privacy (see schema.js for the tables):
    * turnout stores HMAC(matric) only — "this person has voted";
    * ballots / selections / receipts store NO voter reference and NO time;
    * both are written in ONE transaction, then nothing links them.
*/

"use strict";

const crypto = require("crypto");
const d = require("./db");
const config = require("./config");
const keys = require("./keys");
const audit = require("./audit");
const election = require("./election");
const sessions = require("./sessions");
const ratelimit = require("./ratelimit");
const mailer = require("./mailer");

const RECEIPT_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const EMAIL_PATTERN = /^[^\s@<>"]+@[^\s@<>"]+\.[^\s@<>"]+$/;

function fail(status, code, error, extra = {}) {
  return { ok: false, status, code, error, ...extra };
}

function tooMany(limit) {
  return fail(
    429, "rate-limited",
    `Too many attempts. Please wait ${ratelimit.waitText(limit.retryAfterSec)} and try again.`,
    { retryAfterSec: limit.retryAfterSec }
  );
}

function closedOutcome(state) {
  return state.reason === "upcoming"
    ? {
        ok: true, outcome: "upcoming",
        message: "Voting hasn't opened yet for this election. Please check back once the Electoral Committee opens voting."
      }
    : {
        ok: true, outcome: "closed",
        message: "Voting has closed for this election. Thank you to everyone who participated — results will be announced by the Electoral Committee."
      };
}

/* ---------- identity helpers ---------- */

/* Item 1: digits only. "152637", "1257", "173637" pass; "matric 152637" fails. */
function validateMatric(value) {
  const text = String(value ?? "").trim();

  if (!text) return fail(400, "matric-required", "Enter your matriculation number.");

  if (!config.MATRIC_PATTERN.test(text)) {
    return fail(
      400, "matric-format",
      "Enter your matriculation number as digits only (e.g. 152637) — no letters, spaces or prefix."
    );
  }

  return { ok: true, matric: text };
}

function turnoutHash(matric) {
  return keys.hmacHex("turnout-hmac", matric);
}

function hasVoted(matric) {
  return Boolean(d.get("SELECT 1 AS yes FROM turnout WHERE voterHash = ?", turnoutHash(matric)));
}

function getStudent(matric) {
  return d.get("SELECT * FROM students WHERE matric = ?", matric) || null;
}

function maskEmail(email) {
  const [name, domain] = String(email).split("@");
  return `${name.slice(0, 2)}${"•".repeat(Math.max(2, name.length - 2))}@${domain}`;
}

/* ---------- step 1: sign in ---------- */

function login({ matric: rawMatric, password, ip }) {
  const checked = validateMatric(rawMatric);
  if (!checked.ok) return checked;

  const matric = checked.matric;
  const tag = audit.voterTag(matric);

  const byIp = ratelimit.take("voterLoginIp", ip);
  if (!byIp.allowed) return tooMany(byIp);

  const byMatric = ratelimit.take("voterLoginMatric", tag, { auditLabel: tag });
  if (!byMatric.allowed) return tooMany(byMatric);

  // Item 2: exactly one password is accepted — the shared student password.
  if (!keys.safeEqual(String(password ?? ""), config.VOTER_PASSWORD)) {
    audit.append("voter-portal", "voter", `Failed sign-in for ${tag}: wrong password`);
    return fail(401, "bad-password", "Incorrect student-account password.");
  }

  const state = election.votingState();
  if (!state.open) return closedOutcome(state);

  const student = getStudent(matric);
  const rosterMode = election.getElection().rosterMode;
  const eligible = rosterMode === "closed" ? Boolean(student && student.active) : !student || Boolean(student.active);

  if (!eligible) {
    audit.append("voter-portal", "voter", `Sign-in refused for ${tag}: ${student ? "account deactivated" : "not on the voter roll"}`);
    return {
      ok: true, outcome: "not_eligible",
      message: "This matric number isn't eligible to vote in this election. Please contact the Electoral Committee."
    };
  }

  if (hasVoted(matric)) {
    audit.append("voter-portal", "voter", `${tag} signed in again after voting; access to the ballot refused`);
    return {
      ok: true, outcome: "already_voted",
      message: "Your vote has already been recorded. Please remain calm — the election results will be out soon."
    };
  }

  // Signing in again on the same device or another one ends any earlier session.
  sessions.revokeAllFor("voter", matric, "superseded");
  const created = sessions.create({ kind: "voter", subject: matric, stage: "login" });

  audit.append("voter-portal", "voter", `${tag} signed in`);
  return { ok: true, outcome: "signed_in", token: created.token, session: created.session };
}

/* What the browser needs to draw the right screen (also used to resume
   after a page refresh). */
function describe(session) {
  const now = Date.now();
  const otp = session.data.otp;

  return {
    stage: session.stage,
    matric: session.subject,
    sessionExpiresInSec: Math.max(0, Math.floor((Math.min(session.idleExpiresAt, session.absoluteExpiresAt) - now) / 1000)),
    otp: otp
      ? {
          maskedEmail: otp.masked,
          expiresInSec: Math.max(0, Math.floor((otp.expiresAt - now) / 1000)),
          resendInSec: Math.max(0, Math.ceil((otp.sentAt + config.OTP_RESEND_COOLDOWN_SEC * 1000 - now) / 1000))
        }
      : null,
    rehearsal: config.OTP_MODE === "demo"
  };
}

/* ---------- step 2: election rules  =>  REGISTERED ---------- */

function acceptRules(session) {
  const state = election.votingState();
  if (!state.open) return fail(403, "closed", closedOutcome(state).message);

  if (session.stage === "verified") return { ok: true, session, alreadyDone: true };

  const matric = session.subject;
  const rosterMode = election.getElection().rosterMode;
  const student = getStudent(matric);

  if (rosterMode === "closed" && (!student || !student.active)) {
    return fail(403, "not-eligible", "This matric number isn't eligible to vote in this election.");
  }

  const now = d.nowIso();

  d.tx(() => {
    d.run(
      `INSERT INTO students (matric, registered, registeredAt, addedAt) VALUES (?, 1, ?, ?)
       ON CONFLICT(matric) DO UPDATE SET registered = 1, registeredAt = COALESCE(registeredAt, excluded.registeredAt)`,
      matric, now, now
    );
    audit.append("voter-portal", "voter", `${audit.voterTag(matric)} accepted the election rules (registered)`);
  });

  return { ok: true, session: sessions.update(session, { stage: "rules" }) };
}

/* ---------- step 3: e-mail one-time code  =>  VERIFIED ---------- */

function otpDigest(session, code) {
  // Bound to this session, so a code cannot be carried to another login.
  return keys.hmacHex("otp-hmac", `${session.tokenHash}:${code}`);
}

async function requestOtp(session, emailInput, ip) {
  if (session.stage === "login") return fail(403, "rules-required", "Accept the election rules first.");
  if (session.stage === "verified") return fail(409, "already-verified", "You are already verified.");

  const state = election.votingState();
  if (!state.open) return fail(403, "closed", closedOutcome(state).message);

  const matric = session.subject;
  const tag = audit.voterTag(matric);
  const email = String(emailInput ?? "").trim().toLowerCase();

  if (!EMAIL_PATTERN.test(email) || !email.endsWith(`@${config.UNIVERSITY_EMAIL_DOMAIN}`)) {
    return fail(400, "email-domain", `Use your university-registered @${config.UNIVERSITY_EMAIL_DOMAIN} email address.`);
  }

  const student = getStudent(matric);
  const rosterMode = election.getElection().rosterMode;
  const onFile = student && student.email ? student.email.toLowerCase() : "";

  if (onFile && onFile !== email) {
    return fail(
      400, "email-mismatch",
      "That is not the university email on record for this matric number. Check it, or contact the Electoral Committee."
    );
  }

  if (!onFile && rosterMode === "closed") {
    return fail(
      403, "no-email-on-file",
      "No university email is on file for your matric number. Please contact the Electoral Committee."
    );
  }

  const byIp = ratelimit.take("otpRequestIp", ip);
  if (!byIp.allowed) return tooMany(byIp);

  const byMatric = ratelimit.take("otpRequestMatric", tag, { auditLabel: tag });
  if (!byMatric.allowed) return tooMany(byMatric);

  const now = Date.now();
  const prior = session.data.otp;

  if (prior && now - prior.sentAt < config.OTP_RESEND_COOLDOWN_SEC * 1000) {
    const wait = Math.ceil((prior.sentAt + config.OTP_RESEND_COOLDOWN_SEC * 1000 - now) / 1000);
    return fail(429, "cooldown", `Please wait ${wait} seconds before requesting another code.`, { retryAfterSec: wait });
  }

  if (prior && prior.sends >= config.OTP_MAX_SENDS_PER_SESSION) {
    return fail(429, "too-many-sends", "You have requested too many codes. Please sign in again to start over.");
  }

  const code = config.OTP_MODE === "demo"
    ? config.DEMO_OTP
    : String(crypto.randomInt(0, 1_000_000)).padStart(6, "0");

  const minutes = Math.round(config.OTP_TTL_SEC / 60);

  if (config.OTP_MODE !== "demo") {
    try {
      await mailer.send({
        to: email,
        subject: "Your BOUESTI Vote verification code",
        text:
          `Your BOUESTI SUG election verification code is: ${code}\n\n` +
          `It expires in ${minutes} minutes and works only once. ` +
          "If you did not try to vote, ignore this message — nobody can vote without this code.\n\n" +
          "Never share this code with anyone, including election officials."
      });
    } catch (error) {
      console.error("OTP e-mail failed:", error.message);
      audit.append("system", "system", `Could not send a verification e-mail for ${tag}`);
      return fail(502, "mail-failed", "We couldn't send the email right now. Please try again in a minute.");
    }
  }

  const sentAt = Date.now();
  const otp = {
    digest: otpDigest(session, code),
    sentAt,
    expiresAt: sentAt + config.OTP_TTL_SEC * 1000,
    attempts: 0,
    sends: (prior ? prior.sends : 0) + 1,
    masked: maskEmail(email)
  };

  const updated = sessions.update(session, { data: { ...session.data, otp } });

  if (!onFile) {
    d.run(
      `INSERT INTO students (matric, email, addedAt) VALUES (?, ?, ?)
       ON CONFLICT(matric) DO UPDATE SET email = CASE WHEN email = '' THEN excluded.email ELSE email END`,
      matric, email, d.nowIso()
    );
  }

  audit.append("voter-portal", "voter", `Verification code issued for ${tag} (send ${otp.sends})`);

  return {
    ok: true,
    session: updated,
    maskedEmail: otp.masked,
    expiresInSec: config.OTP_TTL_SEC,
    resendInSec: config.OTP_RESEND_COOLDOWN_SEC,
    demoHint: config.OTP_MODE === "demo" ? `Rehearsal mode: use the code ${config.DEMO_OTP}.` : undefined
  };
}

function verifyOtp(session, codeInput, ip) {
  if (session.stage === "verified") return { ok: true, session, alreadyDone: true };
  if (session.stage !== "rules") return fail(403, "rules-required", "Accept the election rules first.");

  const state = election.votingState();
  if (!state.open) return fail(403, "closed", closedOutcome(state).message);

  const tag = audit.voterTag(session.subject);

  const blocked = ratelimit.peek("otpVerifyMatric", tag);
  if (!blocked.allowed) return tooMany(blocked);

  const byIp = ratelimit.take("otpVerifyIp", ip);
  if (!byIp.allowed) return tooMany(byIp);

  const otp = session.data.otp;
  if (!otp) return fail(400, "no-code", "Request a verification code first.");

  if (Date.now() > otp.expiresAt) {
    return fail(400, "expired", "Your OTP has expired. Request a new code.");
  }

  const code = String(codeInput ?? "").replace(/\s/g, "");
  if (!/^\d{6}$/.test(code)) return fail(400, "bad-code", "Enter the 6-digit code.");

  if (!keys.safeEqual(otpDigest(session, code), otp.digest)) {
    // Only WRONG guesses count against the per-voter allowance.
    ratelimit.take("otpVerifyMatric", tag, { auditLabel: tag });

    const attempts = otp.attempts + 1;
    const left = config.OTP_MAX_ATTEMPTS - attempts;

    if (left <= 0) {
      sessions.update(session, { data: { ...session.data, otp: null } });
      audit.append("voter-portal", "voter", `${tag} entered ${attempts} wrong codes; the code was cancelled`);
      return fail(400, "code-cancelled", "Too many wrong codes. Request a new code.");
    }

    sessions.update(session, { data: { ...session.data, otp: { ...otp, attempts } } });
    audit.append("voter-portal", "voter", `${tag} entered a wrong verification code (${attempts}/${config.OTP_MAX_ATTEMPTS})`);

    return fail(400, "wrong-code", `That code is incorrect. Try again or request a new code. (${left} attempt${left === 1 ? "" : "s"} left)`);
  }

  d.run("UPDATE students SET verified = 1, verifiedAt = ? WHERE matric = ?", d.nowIso(), session.subject);

  // New token on every privilege change; the old one stops working.
  const upgraded = sessions.rotate(session, { stage: "verified", data: {}, preserveAbsolute: true });

  audit.append("voter-portal", "voter", `${tag} verified by e-mail code`);
  return { ok: true, token: upgraded.token, session: upgraded.session };
}

/* ---------- step 4: ballot ---------- */

function guardBallotAccess(session) {
  if (session.stage !== "verified") {
    return fail(403, "not-verified", "Complete the rules and e-mail verification before voting.");
  }

  const state = election.votingState();
  if (!state.open) return fail(403, "closed", closedOutcome(state).message);

  const student = getStudent(session.subject);
  if (!student || !student.active || !student.registered || !student.verified) {
    return fail(403, "not-eligible", "This matric number isn't eligible to vote right now.");
  }

  if (hasVoted(session.subject)) {
    return fail(409, "already-voted", "Your vote has already been recorded. Please remain calm — the results will be out soon.");
  }

  return null;
}

function getBallot(session) {
  const blocked = guardBallotAccess(session);
  if (blocked) return blocked;

  return { ok: true, offices: election.getBallotStructure() };
}

function newReceiptCode() {
  let body = "";
  for (let index = 0; index < 10; index += 1) {
    body += RECEIPT_ALPHABET[crypto.randomInt(RECEIPT_ALPHABET.length)];
  }
  return `BOUESTI-${new Date().getFullYear()}-${body.slice(0, 5)}-${body.slice(5)}`;
}

function normaliseReceipt(value) {
  return String(value ?? "").toUpperCase().replace(/\s/g, "");
}

function validateChoices(choices) {
  const offices = election.getBallotStructure();

  if (!choices || typeof choices !== "object" || Array.isArray(choices)) {
    return fail(400, "bad-ballot", "Your ballot could not be read. Please try again.");
  }

  const submittedKeys = Object.keys(choices);
  const picked = [];

  for (const office of offices) {
    const raw = choices[String(office.id)];
    const candidateId = typeof raw === "number" ? raw : Number(raw);

    if (raw === undefined || raw === null || raw === "") {
      return fail(400, "incomplete", `Choose a candidate for ${office.office}.`);
    }

    if (!Number.isInteger(candidateId) || !office.candidates.some((c) => c.id === candidateId)) {
      return fail(400, "invalid-choice", "One or more selections aren't valid candidates.");
    }

    picked.push({ officeId: office.id, candidateId });
  }

  if (submittedKeys.length !== offices.length) {
    return fail(400, "invalid-choice", "One or more selections aren't valid positions.");
  }

  return { ok: true, picked };
}

function castVote(session, choices, ip) {
  const byIp = ratelimit.take("ballotIp", ip);
  if (!byIp.allowed) return tooMany(byIp);

  const tag = audit.voterTag(session.subject);
  const byMatric = ratelimit.take("ballotMatric", tag, { auditLabel: tag });
  if (!byMatric.allowed) return tooMany(byMatric);

  const blocked = guardBallotAccess(session);
  if (blocked) return blocked;

  const checked = validateChoices(choices);
  if (!checked.ok) return checked;

  const voterHash = turnoutHash(session.subject);
  const ballotId = crypto.randomBytes(16).toString("hex");
  const receipt = newReceiptCode();
  const hour = new Date().toISOString().slice(0, 13);

  const outcome = d.tx(() => {
    // Re-check inside the transaction: nothing can change between check and write.
    if (!election.votingState().open) return { error: "closed" };

    try {
      // The primary key makes a second ballot from the same person impossible.
      d.run("INSERT INTO turnout (voterHash) VALUES (?)", voterHash);
    } catch (error) {
      if (/constraint|unique/i.test(error.message)) return { error: "already-voted" };
      throw error;
    }

    d.run("INSERT INTO ballots (ballotId) VALUES (?)", ballotId);

    checked.picked.forEach(({ officeId, candidateId }) => {
      d.run(
        "INSERT INTO ballot_selections (ballotId, officeId, candidateId) VALUES (?, ?, ?)",
        ballotId, officeId, candidateId
      );
    });

    d.run("INSERT INTO receipts (codeHash) VALUES (?)", keys.sha256Hex(normaliseReceipt(receipt)));

    d.run(
      `INSERT INTO turnout_hourly (hour, count) VALUES (?, 1)
       ON CONFLICT(hour) DO UPDATE SET count = count + 1`,
      hour
    );

    // Records THAT this voter voted. Never what, and never which ballot.
    audit.append("voter-portal", "voting", `Ballot accepted for ${tag}`);
    return { ok: true };
  });

  if (outcome.error === "closed") {
    return fail(403, "closed", closedOutcome({ reason: "closed" }).message);
  }

  if (outcome.error === "already-voted") {
    return fail(409, "already-voted", "Your vote has already been recorded. Please remain calm — the results will be out soon.");
  }

  sessions.destroy(session.tokenHash);
  return { ok: true, receipt };
}

/* A receipt proves a ballot was accepted. It is NOT linked to the ballot's
   contents, so it cannot be used to prove (or sell) how someone voted. */
function checkReceipt(codeInput) {
  const code = normaliseReceipt(codeInput);
  if (code.length < 8 || code.length > 40) return { found: false };

  return { found: Boolean(d.get("SELECT 1 AS yes FROM receipts WHERE codeHash = ?", keys.sha256Hex(code))) };
}

function logout(session) {
  sessions.revoke(session.tokenHash, "logout");
  audit.append("voter-portal", "voter", `${audit.voterTag(session.subject)} signed out`);
}

/* ---------- students reporting a problem ---------- */

const PROBLEM_CATEGORIES = ["login", "otp", "ballot", "other"];

function submitProblem({ category, message, contact, matric }, ip) {
  const limit = ratelimit.take("problemIp", ip);
  if (!limit.allowed) return tooMany(limit);

  const text = String(message ?? "").replace(/\s+/g, " ").trim();
  if (text.length < 10 || text.length > 1000) {
    return fail(400, "bad-message", "Please describe the problem in 10–1000 characters.");
  }

  const cleanCategory = PROBLEM_CATEGORIES.includes(category) ? category : "other";
  const cleanContact = String(contact ?? "").trim().slice(0, 120);
  const cleanMatric = config.MATRIC_PATTERN.test(String(matric ?? "").trim()) ? String(matric).trim() : "";

  d.run(
    "INSERT INTO student_reports (receivedAt, category, message, contact, matric) VALUES (?, ?, ?, ?, ?)",
    d.nowIso(), cleanCategory, text, cleanContact, cleanMatric
  );

  audit.append("voter-portal", "system", `A student reported a problem (${cleanCategory})`);
  return { ok: true };
}

/* ---------- roster management (administrators) ---------- */

function validStudentFields({ matric, name, email }) {
  const checked = validateMatric(matric);
  if (!checked.ok) return { error: checked.error };

  const cleanName = String(name ?? "").replace(/\s+/g, " ").trim();
  if (cleanName.length < 2 || cleanName.length > 100) return { error: "Enter the student's full name." };

  const cleanEmail = String(email ?? "").trim().toLowerCase();
  if (cleanEmail && (!EMAIL_PATTERN.test(cleanEmail) || !cleanEmail.endsWith(`@${config.UNIVERSITY_EMAIL_DOMAIN}`))) {
    return { error: `A student's email must end in @${config.UNIVERSITY_EMAIL_DOMAIN}.` };
  }

  return { matric: checked.matric, name: cleanName, email: cleanEmail };
}

function addStudent(input, admin) {
  const fields = validStudentFields(input);
  if (fields.error) return { ok: false, error: fields.error };

  if (getStudent(fields.matric)) return { ok: false, error: "That matric number is already on the roster." };

  d.tx(() => {
    d.run(
      "INSERT INTO students (matric, name, email, addedAt) VALUES (?, ?, ?, ?)",
      fields.matric, fields.name, fields.email, d.nowIso()
    );
    audit.append(audit.adminActor(admin), "voters", `Added ${audit.voterTag(fields.matric)} to the roster`);
  });

  return { ok: true };
}

/* Lines of "matric,name,email" (email optional). A header row is skipped. */
function importStudents(lines, admin) {
  const rows = Array.isArray(lines) ? lines.slice(0, 20_000) : [];
  const problems = [];
  let added = 0;
  let skipped = 0;

  d.tx(() => {
    rows.forEach((line, index) => {
      const text = String(line ?? "").trim();
      if (!text) return;

      const [matric, name, email] = text.split(/[,\t;]/).map((part) => (part || "").trim());

      if (index === 0 && /^[a-z]/i.test(matric || "") && !config.MATRIC_PATTERN.test(matric || "")) return; // header row

      const fields = validStudentFields({ matric, name, email });

      if (fields.error) {
        skipped += 1;
        if (problems.length < 25) problems.push({ line: index + 1, reason: fields.error });
        return;
      }

      if (getStudent(fields.matric)) {
        skipped += 1;
        if (problems.length < 25) problems.push({ line: index + 1, reason: "Already on the roster." });
        return;
      }

      d.run(
        "INSERT INTO students (matric, name, email, addedAt) VALUES (?, ?, ?, ?)",
        fields.matric, fields.name, fields.email, d.nowIso()
      );
      added += 1;
    });

    audit.append(audit.adminActor(admin), "voters", `Roster import: ${added} added, ${skipped} skipped`);
  });

  return { ok: true, added, skipped, problems };
}

function toggleStudent(matric, admin) {
  const student = getStudent(String(matric));
  if (!student) return { ok: false, error: "Student not found." };

  const next = student.active ? 0 : 1;

  d.tx(() => {
    d.run("UPDATE students SET active = ? WHERE matric = ?", next, student.matric);
    sessions.revokeAllFor("voter", student.matric, "deactivated");
    audit.append(audit.adminActor(admin), "voters", `${next ? "Activated" : "Deactivated"} ${audit.voterTag(student.matric)}`);
  });

  return { ok: true, active: Boolean(next) };
}

function removeStudent(matric, admin) {
  const student = getStudent(String(matric));
  if (!student) return { ok: false, error: "Student not found." };

  d.tx(() => {
    d.run("DELETE FROM students WHERE matric = ?", student.matric);
    sessions.revokeAllFor("voter", student.matric, "removed");
    audit.append(audit.adminActor(admin), "voters", `Removed ${audit.voterTag(student.matric)} from the roster`);
  });

  return { ok: true };
}

function studentCounts() {
  const totals = d.get(
    `SELECT COUNT(*) AS total,
            COALESCE(SUM(active), 0) AS active,
            COALESCE(SUM(registered), 0) AS registered,
            COALESCE(SUM(verified), 0) AS verified
     FROM students`
  );

  return {
    total: totals.total,
    active: totals.active,
    inactive: totals.total - totals.active,
    registered: totals.registered,
    verified: totals.verified,
    voted: election.turnoutCount()
  };
}

/* The roster with each student's progress. "Voted" is worked out by
   hashing each matric and looking it up in turnout — the roster itself
   never records a vote. */
function rosterRows() {
  const votedSet = new Set(d.all("SELECT voterHash FROM turnout").map((row) => row.voterHash));

  return d.all("SELECT * FROM students ORDER BY addedAt DESC, matric").map((row) => ({
    matric: row.matric,
    name: row.name,
    email: row.email,
    registered: Boolean(row.registered),
    verified: Boolean(row.verified),
    active: Boolean(row.active),
    voted: votedSet.has(turnoutHash(row.matric)),
    addedAt: row.addedAt
  }));
}

/* Every student with their progress (for the CSV export). */
function allStudents() {
  return rosterRows();
}

function listStudents({ search = "", filter = "all", limit = 200, offset = 0 } = {}) {
  const needle = String(search).trim().toLowerCase();

  let rows = rosterRows();

  if (needle) {
    rows = rows.filter((row) =>
      row.matric.includes(needle) || row.name.toLowerCase().includes(needle) || row.email.includes(needle)
    );
  }

  const filters = {
    registered: (row) => row.registered && !row.verified && !row.voted,
    verified: (row) => row.verified && !row.voted,
    voted: (row) => row.voted,
    pending: (row) => !row.registered && !row.verified && !row.voted,
    inactive: (row) => !row.active
  };

  if (filters[filter]) rows = rows.filter(filters[filter]);

  const safeLimit = Math.min(Math.max(Number(limit) || 200, 1), 1000);

  return {
    total: rows.length,
    students: rows.slice(Math.max(Number(offset) || 0, 0), Math.max(Number(offset) || 0, 0) + safeLimit)
  };
}

function statistics() {
  const counts = studentCounts();
  const rosterMode = election.getElection().rosterMode;

  const hourly = d.all("SELECT hour, count FROM turnout_hourly ORDER BY hour").map((row) => ({
    hour: row.hour,
    voted: row.count
  }));

  const stages = d.all(
    `SELECT substr(registeredAt, 1, 13) AS hour, COUNT(*) AS n FROM students
     WHERE registeredAt IS NOT NULL GROUP BY hour ORDER BY hour`
  );
  const verifiedStages = d.all(
    `SELECT substr(verifiedAt, 1, 13) AS hour, COUNT(*) AS n FROM students
     WHERE verifiedAt IS NOT NULL GROUP BY hour ORDER BY hour`
  );

  return {
    rosterMode,
    ...counts,
    turnoutPercent: rosterMode === "closed" && counts.active > 0 ? Math.round((counts.voted / counts.active) * 1000) / 10 : null,
    hourly,
    registeredByHour: stages.map((row) => ({ hour: row.hour, count: row.n })),
    verifiedByHour: verifiedStages.map((row) => ({ hour: row.hour, count: row.n }))
  };
}

module.exports = {
  validateMatric,
  turnoutHash,
  hasVoted,
  getStudent,
  login,
  describe,
  acceptRules,
  requestOtp,
  verifyOtp,
  getBallot,
  castVote,
  checkReceipt,
  logout,
  submitProblem,
  addStudent,
  importStudents,
  toggleStudent,
  removeStudent,
  studentCounts,
  listStudents,
  allStudents,
  statistics
};
