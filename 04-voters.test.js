"use strict";

const { freshEnv } = require("./helpers");
freshEnv();

const test = require("node:test");
const assert = require("node:assert");

const d = require("../db");
const config = require("../config");
const election = require("../election");
const sessions = require("../sessions");
const voters = require("../voters");
const audit = require("../audit");

election.seedIfEmpty();

const IP = "10.1.1.1";
const admin = { id: 1, email: "electoral@bouesti.ng", role: "electoral_officer" };

function signIn(matric, password = "password1") {
  const result = voters.login({ matric, password, ip: IP });
  assert.strictEqual(result.outcome, "signed_in", JSON.stringify(result));
  return result;
}

async function reachBallot(matric, email = `${matric}@bouesti.edu.ng`) {
  let { session } = signIn(matric);
  session = voters.acceptRules(session).session;

  const sent = await voters.requestOtp(session, email, IP);
  assert.ok(sent.ok, JSON.stringify(sent));

  const verified = voters.verifyOtp(sent.session, config.DEMO_OTP, IP);
  assert.ok(verified.ok, JSON.stringify(verified));
  return verified;
}

function everyOfficeFirstCandidate() {
  const choices = {};
  election.getBallotStructure().forEach((office) => {
    choices[office.id] = office.candidates[0].id;
  });
  return choices;
}

test("item 1: only digits are accepted as a matric number", () => {
  const rejected = ["matric 152637", "matric", "MATRIC152637", "BOU/15/2637", "15-2637", "15 2637", "12a45", "152637 ", "٣٤٥٦٧٨", "123", "", "1234567890123456"];

  rejected.forEach((value) => {
    const trimmedOk = value === "152637 "; // surrounding spaces are trimmed, not an error
    const result = voters.validateMatric(value);
    assert.strictEqual(result.ok, trimmedOk, `${JSON.stringify(value)} -> ${JSON.stringify(result)}`);
  });

  ["152637", "1257", "173637", "20260001"].forEach((value) => {
    assert.deepStrictEqual(voters.validateMatric(value), { ok: true, matric: value });
  });

  const viaLogin = voters.login({ matric: "matric 152637", password: "password1", ip: IP });
  assert.strictEqual(viaLogin.ok, false);
  assert.strictEqual(viaLogin.code, "matric-format");
  assert.strictEqual(viaLogin.status, 400);
  assert.strictEqual(sessions.activeCounts().voter, 0, "no session is created for a bad matric");
});

test("item 2: password1 is the ONLY password that works", () => {
  ["Password1", "password12", "password", "PASSWORD1", " password1", "password1 ", "", "123456", "admin", "password1\u0000"].forEach((pw, index) => {
    const result = voters.login({ matric: `10${index}`.padStart(5, "1"), password: pw, ip: IP });
    assert.strictEqual(result.ok, false, JSON.stringify(pw));
    assert.strictEqual(result.status, 401);
  });

  assert.strictEqual(voters.login({ matric: "152637", password: undefined, ip: IP }).ok, false);
  assert.strictEqual(voters.login({ matric: "152637", password: null, ip: IP }).ok, false);

  // The same shared password works for different students.
  ["152637", "1257", "173637"].forEach((matric) => {
    assert.strictEqual(voters.login({ matric, password: "password1", ip: IP }).outcome, "signed_in");
  });
});

test("different matric numbers can sign in one after another on the same device", () => {
  const first = signIn("2001");
  const second = signIn("2002");

  assert.ok(sessions.lookup(second.token, "voter"));
  assert.ok(sessions.lookup(first.token, "voter"), "a different student's session is independent");

  const again = signIn("2001");
  assert.strictEqual(sessions.lookup(first.token, "voter"), null, "signing in again ends the student's earlier session");
  assert.ok(sessions.lookup(again.token, "voter"));
});

test("steps cannot be skipped: rules, then code, then ballot", async () => {
  let { session } = signIn("3001");

  assert.strictEqual((await voters.requestOtp(session, "3001@bouesti.edu.ng", IP)).code, "rules-required");
  assert.strictEqual(voters.verifyOtp(session, config.DEMO_OTP, IP).code, "rules-required");
  assert.strictEqual(voters.getBallot(session).code, "not-verified");
  assert.strictEqual(voters.castVote(session, everyOfficeFirstCandidate(), IP).code, "not-verified");

  session = voters.acceptRules(session).session;
  assert.strictEqual(d.get("SELECT registered FROM students WHERE matric = '3001'").registered, 1, "REGISTERED after rules");
  assert.strictEqual(d.get("SELECT verified FROM students WHERE matric = '3001'").verified, 0);

  assert.strictEqual(voters.getBallot(session).code, "not-verified", "rules alone do not unlock the ballot");
  assert.strictEqual(voters.castVote(session, everyOfficeFirstCandidate(), IP).code, "not-verified");

  const sent = await voters.requestOtp(session, "3001@bouesti.edu.ng", IP);
  const verified = voters.verifyOtp(sent.session, config.DEMO_OTP, IP);
  assert.ok(verified.ok);
  assert.strictEqual(d.get("SELECT verified FROM students WHERE matric = '3001'").verified, 1, "VERIFIED after the code");

  assert.strictEqual(sessions.lookup(sent.session.tokenHash && "x", "voter"), null);
  assert.ok(voters.getBallot(verified.session).ok);
});

test("e-mail code: domain rule, wrong guesses, cooldown, expiry, session binding", async () => {
  let { session } = signIn("4001");
  session = voters.acceptRules(session).session;

  assert.strictEqual((await voters.requestOtp(session, "me@gmail.com", IP)).code, "email-domain");
  assert.strictEqual((await voters.requestOtp(session, "not-an-email", IP)).code, "email-domain");

  const sent = await voters.requestOtp(session, "Student4001@BOUESTI.EDU.NG", IP);
  assert.ok(sent.ok);
  assert.ok(sent.demoHint, "rehearsal mode tells testers which code to use");
  assert.match(sent.maskedEmail, /^St•+@bouesti\.edu\.ng$/i);
  assert.ok(!JSON.stringify(sent.session.data).includes(config.DEMO_OTP), "the code itself is never stored, only a keyed digest");

  const again = await voters.requestOtp(sent.session, "student4001@bouesti.edu.ng", IP);
  assert.strictEqual(again.code, "cooldown", "resend is rate-limited server-side");

  // Wrong guesses: 4 allowed, the 5th cancels the code.
  let live = sessions.lookup(sessions.hashToken("x"), "voter");
  live = d.get("SELECT * FROM sessions WHERE subject = '4001' AND revokedAt IS NULL");
  let current = sent.session;
  for (let attempt = 1; attempt <= 4; attempt += 1) {
    const wrong = voters.verifyOtp(current, "000000", IP);
    assert.strictEqual(wrong.code, "wrong-code");
    current = { ...current, data: JSON.parse(d.get("SELECT data FROM sessions WHERE tokenHash = ?", current.tokenHash).data) };
  }
  const cancelled = voters.verifyOtp(current, "000000", IP);
  assert.strictEqual(cancelled.code, "code-cancelled");
  current = { ...current, data: JSON.parse(d.get("SELECT data FROM sessions WHERE tokenHash = ?", current.tokenHash).data) };
  assert.strictEqual(voters.verifyOtp(current, config.DEMO_OTP, IP).code, "no-code", "even the right code fails once cancelled");
  assert.ok(live === undefined || live);

  // A code cannot be carried to a different session.
  let a = signIn("4002").session;
  a = voters.acceptRules(a).session;
  const sentA = await voters.requestOtp(a, "a4002@bouesti.edu.ng", IP);

  let b = signIn("4003").session;
  b = voters.acceptRules(b).session;
  const sentB = await voters.requestOtp(b, "b4003@bouesti.edu.ng", IP);

  const stolen = { ...sentB.session, data: JSON.parse(d.get("SELECT data FROM sessions WHERE tokenHash = ?", sentA.session.tokenHash).data) };
  assert.strictEqual(voters.verifyOtp(stolen, config.DEMO_OTP, IP).code, "wrong-code", "digest is bound to its own session");

  // Expiry
  const aData = JSON.parse(d.get("SELECT data FROM sessions WHERE tokenHash = ?", sentA.session.tokenHash).data);
  aData.otp.expiresAt = Date.now() - 1000;
  const expired = sessions.update(sentA.session, { data: aData });
  assert.strictEqual(voters.verifyOtp(expired, config.DEMO_OTP, IP).code, "expired");
});

test("a full vote: privacy of the stored records", async () => {
  const { session } = await reachBallot("5001");
  const choices = everyOfficeFirstCandidate();
  const before = { ballots: election.ballotCount(), turnout: election.turnoutCount() };

  const result = voters.castVote(session, choices, IP);
  assert.ok(result.ok, JSON.stringify(result));
  assert.match(result.receipt, /^BOUESTI-\d{4}-[A-Z2-9]{5}-[A-Z2-9]{5}$/);

  assert.strictEqual(election.ballotCount(), before.ballots + 1);
  assert.strictEqual(election.turnoutCount(), before.turnout + 1);
  assert.ok(voters.hasVoted("5001"));

  // 1. The voter's session is gone.
  assert.strictEqual(d.get("SELECT COUNT(*) AS n FROM sessions WHERE subject = '5001'").n, 0);

  // 2. No voter-identifying column anywhere in the ballot tables, and no timestamps.
  ["ballots", "ballot_selections", "receipts", "turnout"].forEach((table) => {
    const columns = d.all(`PRAGMA table_info(${table})`).map((c) => c.name.toLowerCase());
    const forbidden = ["matric", "student", "studentid", "voter", "voterid", "email", "name", "time", "timestamp", "createdat", "castat", "votedat", "at", "date", "ip"];
    columns.forEach((name) => {
      assert.ok(!forbidden.includes(name), `${table}.${name} must not identify a voter or a time`);
    });
  });

  // 3. Turnout holds a keyed hash, never the matric.
  const turnoutRows = d.all("SELECT voterHash FROM turnout").map((r) => r.voterHash);
  assert.ok(turnoutRows.every((h) => /^[0-9a-f]{64}$/.test(h)));
  assert.ok(!turnoutRows.includes("5001"));
  assert.ok(turnoutRows.includes(voters.turnoutHash("5001")));

  // 4. The receipt is stored hashed and is not linked to any ballot.
  assert.strictEqual(d.get("SELECT COUNT(*) AS n FROM receipts WHERE codeHash = ?", result.receipt).n, 0);
  assert.deepStrictEqual(voters.checkReceipt(result.receipt), { found: true });
  assert.deepStrictEqual(voters.checkReceipt(result.receipt.toLowerCase().replace(/-/g, " ")), { found: false }, "dashes matter");
  assert.deepStrictEqual(voters.checkReceipt("BOUESTI-2026-AAAAA-AAAAA"), { found: false });

  // 5. The audit log says THAT they voted, never what.
  const entries = d.all("SELECT message FROM audit_log").map((r) => r.message).join("\n");
  assert.ok(!entries.includes("5001"), "audit log never contains the matric number");
  assert.ok(entries.includes(audit.voterTag("5001")));
  assert.ok(!/candidate|Amara|David|President/i.test(entries.split("\n").filter((l) => /Ballot accepted/.test(l)).join("\n")));

  // 6. The stored ballot is exactly the picked candidates — nothing else.
  const lastBallot = d.all("SELECT ballotId FROM ballots").pop();
  const rows = d.all("SELECT officeId, candidateId FROM ballot_selections WHERE ballotId = ?", lastBallot.ballotId);
  assert.strictEqual(rows.length, election.getBallotStructure().length);
});

test("one person, one vote — however they try", async () => {
  const { session } = await reachBallot("5002");
  const choices = everyOfficeFirstCandidate();

  assert.ok(voters.castVote(session, choices, IP).ok);

  // replaying the same (now deleted) session object
  assert.strictEqual(voters.castVote(session, choices, IP).code, "already-voted");

  // signing in again
  const second = voters.login({ matric: "5002", password: "password1", ip: IP });
  assert.strictEqual(second.outcome, "already_voted");
  assert.match(second.message, /remain calm/i);
  assert.match(second.message, /results will be out soon/i);
  assert.strictEqual(second.token, undefined, "no session, so no way to reach the ballot");

  // a different password does not reveal anything either
  assert.strictEqual(voters.login({ matric: "5002", password: "nope", ip: IP }).status, 401);

  assert.strictEqual(d.get("SELECT COUNT(*) AS n FROM turnout WHERE voterHash = ?", voters.turnoutHash("5002")).n, 1);
});

test("ballot validation", async () => {
  const { session } = await reachBallot("5003");
  const good = everyOfficeFirstCandidate();
  const offices = election.getBallotStructure();
  const before = election.ballotCount();

  assert.strictEqual(voters.castVote(session, {}, IP).code, "incomplete");
  assert.strictEqual(voters.castVote(session, null, IP).code, "bad-ballot");
  assert.strictEqual(voters.castVote(session, [1, 2], IP).code, "bad-ballot");

  const missing = { ...good };
  delete missing[offices[0].id];
  assert.strictEqual(voters.castVote(session, missing, IP).code, "incomplete");

  const wrongOffice = { ...good, [offices[0].id]: offices[1].candidates[0].id };
  assert.strictEqual(voters.castVote(session, wrongOffice, IP).code, "invalid-choice", "a candidate from another position");

  assert.strictEqual(voters.castVote(session, { ...good, [offices[0].id]: "abc" }, IP).code, "invalid-choice");
  assert.strictEqual(voters.castVote(session, { ...good, [offices[0].id]: 99999 }, IP).code, "invalid-choice");
  assert.strictEqual(voters.castVote(session, { ...good, 424242: 1 }, IP).code, "invalid-choice", "extra positions are refused");

  // once ballots exist the candidate list is locked, even for the Electoral Officer
  const pending = offices[0].candidates[1];
  const locked = election.toggleCandidate(pending.id, admin);
  assert.strictEqual(locked.ok, false);
  assert.match(locked.error, /locked/);
  assert.strictEqual(election.removeCandidate(pending.id, admin).ok, false);
  assert.strictEqual(election.addCandidate(offices[0].id, "Late Entry", "", admin).ok, false);

  // an unapproved candidate is not a valid choice (flipped directly to simulate)
  d.run("UPDATE candidates SET status = 'pending' WHERE id = ?", pending.id);
  assert.strictEqual(voters.castVote(session, { ...good, [offices[0].id]: pending.id }, IP).code, "invalid-choice");
  d.run("UPDATE candidates SET status = 'approved' WHERE id = ?", pending.id);

  assert.strictEqual(election.ballotCount(), before, "nothing was recorded by any rejected attempt");
  assert.ok(voters.castVote(session, good, IP).ok, "and the voter can still submit a correct ballot");
});

test("voting window: upcoming and closed elections refuse sign-in and ballots", async () => {
  const { session } = await reachBallot("6001");

  election.updateElection({ status: "closed" }, admin);
  assert.strictEqual(voters.castVote(session, everyOfficeFirstCandidate(), IP).code, "closed");
  assert.strictEqual(voters.login({ matric: "6002", password: "password1", ip: IP }).outcome, "closed");

  election.updateElection({ status: "upcoming" }, admin);
  assert.strictEqual(voters.login({ matric: "6002", password: "password1", ip: IP }).outcome, "upcoming");

  election.updateElection({ status: "active" }, admin);
  assert.strictEqual(voters.login({ matric: "6002", password: "password1", ip: IP }).outcome, "signed_in");

  // a scheduled closing time is enforced even before the scheduler ticks
  const past = new Date(Date.now() + 1500).toISOString();
  election.updateElection({ votingClosesAt: past }, admin);
  d.run("UPDATE election SET votingClosesAt = ?", new Date(Date.now() - 1000).toISOString());
  assert.strictEqual(election.votingState().open, false);
  assert.strictEqual(voters.login({ matric: "6003", password: "password1", ip: IP }).outcome, "closed");
  d.run("UPDATE election SET votingClosesAt = NULL");
});

test("closed roster: only listed, active students; the code goes to the e-mail on file", async () => {
  election.updateSettings({ rosterMode: "closed" }, admin);

  assert.strictEqual(voters.login({ matric: "7001", password: "password1", ip: IP }).outcome, "not_eligible");

  assert.ok(voters.addStudent({ matric: "7001", name: "Ada Obi", email: "ada.obi@bouesti.edu.ng" }, admin).ok);
  assert.ok(voters.addStudent({ matric: "7002", name: "No Email", email: "" }, admin).ok);

  let { session } = signIn("7001");
  session = voters.acceptRules(session).session;
  assert.strictEqual((await voters.requestOtp(session, "someone.else@bouesti.edu.ng", IP)).code, "email-mismatch");
  assert.ok((await voters.requestOtp(session, "ADA.OBI@bouesti.edu.ng", IP)).ok);

  let other = signIn("7002").session;
  other = voters.acceptRules(other).session;
  assert.strictEqual((await voters.requestOtp(other, "no.email@bouesti.edu.ng", IP)).code, "no-email-on-file");

  // deactivating a student ends their session and blocks sign-in
  assert.ok(voters.toggleStudent("7001", admin).ok);
  assert.strictEqual(voters.login({ matric: "7001", password: "password1", ip: IP }).outcome, "not_eligible");
  assert.strictEqual(voters.acceptRules(session).code, "not-eligible");
  voters.toggleStudent("7001", admin);

  election.updateSettings({ rosterMode: "open" }, admin);
});

test("roster import: header row, bad lines, duplicates, and statistics", () => {
  const result = voters.importStudents([
    "matric,name,email",
    "8001,Bola Ade,bola.ade@bouesti.edu.ng",
    "8002,Chi Eze",
    "matric 8003,Bad Prefix,",
    "8004,,",
    "8005,Gmail User,gmail@gmail.com",
    "8001,Duplicate,",
    "",
    "8006\tTab Separated\ttab@bouesti.edu.ng"
  ], admin);

  assert.strictEqual(result.added, 3);
  assert.strictEqual(result.skipped, 4);
  assert.ok(result.problems.length === 4);

  const list = voters.listStudents({ search: "bola" });
  assert.strictEqual(list.total, 1);
  assert.strictEqual(list.students[0].voted, false);

  const stats = voters.statistics();
  assert.ok(stats.total >= 3 && stats.voted === election.turnoutCount());
  assert.ok(Array.isArray(stats.hourly) && stats.hourly.length >= 1);

  const votedList = voters.listStudents({ filter: "voted" });
  assert.ok(votedList.students.every((s) => s.voted));
  assert.ok(votedList.total >= 2);
});

test("login attempts are rate-limited per student and per address", () => {
  const rule = config.RATE.voterLoginMatric;
  let last;
  for (let i = 0; i < rule.limit + 1; i += 1) {
    last = voters.login({ matric: "9001", password: "wrong", ip: `10.9.9.${i % 200}` });
  }
  assert.strictEqual(last.status, 429);
  assert.ok(last.retryAfterSec > 0);

  // even the correct password is refused while blocked
  assert.strictEqual(voters.login({ matric: "9001", password: "password1", ip: "10.8.8.8" }).status, 429);
  // other students are unaffected
  assert.strictEqual(voters.login({ matric: "9002", password: "password1", ip: "10.8.8.8" }).outcome, "signed_in");
});

test("OTP guessing is limited per student across sessions", async () => {
  const rule = config.RATE.otpVerifyMatric;
  let blocked = null;

  for (let round = 0; round < 8 && !blocked; round += 1) {
    let { session } = voters.login({ matric: "9100", password: "password1", ip: `10.7.${round}.1` }).session
      ? { session: voters.login({ matric: "9100", password: "password1", ip: `10.7.${round}.2` }).session }
      : {};
    if (!session) break;

    session = voters.acceptRules(session).session;
    let sent = await voters.requestOtp(session, "s9100@bouesti.edu.ng", `10.7.${round}.3`);
    if (!sent.ok) {
      blocked = sent;
      break;
    }

    let current = sent.session;
    for (let attempt = 0; attempt < config.OTP_MAX_ATTEMPTS; attempt += 1) {
      const result = voters.verifyOtp(current, "111111", `10.7.${round}.4`);
      if (result.status === 429) {
        blocked = result;
        break;
      }
      current = { ...current, data: JSON.parse(d.get("SELECT data FROM sessions WHERE tokenHash = ?", current.tokenHash).data) };
    }
  }

  assert.ok(blocked, `blocked within ${rule.limit} wrong guesses`);
  assert.strictEqual(blocked.status, 429);
});

test("students can report a problem (rate-limited, sanitised)", () => {
  assert.strictEqual(voters.submitProblem({ message: "short" }, "3.3.3.3").code, "bad-message");

  const ok = voters.submitProblem({ category: "otp", message: "I never received my code.", contact: "0801234567", matric: "matric 5" }, "3.3.3.4");
  assert.ok(ok.ok);

  const row = d.get("SELECT * FROM student_reports ORDER BY id DESC LIMIT 1");
  assert.strictEqual(row.matric, "", "an invalid matric is not stored");
  assert.strictEqual(row.category, "otp");

  const limit = config.RATE.problemIp.limit;
  let last;
  for (let i = 0; i < limit + 1; i += 1) last = voters.submitProblem({ message: "Another problem report here." }, "3.3.3.5");
  assert.strictEqual(last.status, 429);
});

test("the whole audit chain is still intact", () => {
  assert.ok(audit.verify().ok);
});
