/*
  BOUESTI Vote — routes for students and the public.

    GET  /api/public/state           what the home page shows (no counts)
    GET  /api/public/results         published results, once officials publish
    POST /api/public/receipt         "was my ballot accepted?"
    POST /api/public/problem         "I have a problem" form

    POST /api/voter/login            matric (digits only) + the one password
    GET  /api/voter/session          where am I in the journey? (page refresh)
    POST /api/voter/rules            accept the election rules  -> registered
    POST /api/voter/otp/request      e-mail me a code
    POST /api/voter/otp/verify       enter the code             -> verified
    GET  /api/voter/ballot           the candidates
    POST /api/voter/vote             submit the ballot
    POST /api/voter/logout

  The server decides every step (voters.js). These handlers only translate
  between HTTP and that module.
*/

"use strict";

const express = require("express");
const config = require("./config");
const election = require("./election");
const voters = require("./voters");
const reports = require("./reports");
const sessions = require("./sessions");
const ratelimit = require("./ratelimit");
const { voterSession, requireVoter } = require("./middleware");
const { sendFailure, text } = require("./http");

const router = express.Router();

/* ---------- public ---------- */

router.get("/public/state", (req, res) => {
  const current = election.getElection();
  const state = election.votingState();

  res.json({
    electionName: current.electionName,
    schoolName: current.schoolName,
    phase: state.open ? "open" : state.reason, // open | upcoming | closed
    votingOpensAt: current.votingOpensAt,
    votingClosesAt: current.votingClosesAt,
    resultsPublished: Boolean(current.resultsPublished),
    rehearsal: current.mode === "rehearsal",
    demoCode: config.OTP_MODE === "demo",
    announcement: election.latestAnnouncement(),
    serverTime: Date.now()
  });
});

/* What anyone may see once the Electoral Officer has approved publication:
   the totals and a fingerprint. The full signed file (with officials'
   names) goes to officials only. */
router.get("/public/results", (req, res) => {
  const current = election.getElection();
  const envelope = current.resultsPublished ? reports.getPublishedEnvelope() : null;

  if (!envelope) return res.json({ published: false });

  const report = envelope.report;

  res.json({
    published: true,
    election: { name: report.election.name, school: report.election.school, closedAt: report.election.closedAt },
    totals: { ballotsCast: report.totals.ballotsCast },
    offices: report.offices.map((office) => ({
      office: office.office,
      totalVotes: office.totalVotes,
      candidates: office.candidates.map((candidate) => ({ name: candidate.name, votes: candidate.votes }))
    })),
    publishedAt: envelope.publication ? envelope.publication.approvedAt : null,
    signature: {
      algorithm: "Ed25519",
      fingerprint: envelope.publicKeyFingerprint,
      note: "The Electoral Committee holds the signed report and can show it to anyone who wants to verify these figures."
    }
  });
});

router.post("/public/receipt", ratelimit.byIp("receiptIp"), (req, res) => {
  res.json(voters.checkReceipt(req.body.code));
});

router.post("/public/problem", (req, res) => {
  const result = voters.submitProblem(
    {
      category: text(req.body.category, 20),
      message: text(req.body.message, 2000),
      contact: text(req.body.contact, 200),
      matric: text(req.body.matric, 30)
    },
    ratelimit.clientIp(req)
  );

  if (!result.ok) return sendFailure(res, result);
  res.json({ ok: true, message: "Thank you. The Electoral Committee has received your report." });
});

/* ---------- the voter's journey ---------- */

router.post("/voter/login", voterSession, (req, res) => {
  const result = voters.login({
    matric: text(req.body.matric, 40),
    password: text(req.body.password, 100),
    ip: ratelimit.clientIp(req)
  });

  if (!result.ok) return sendFailure(res, result);

  // A different student signing in on this device ends the earlier student's
  // session, so one shared computer can serve many voters one after another.
  if (req.voterSession) sessions.revoke(req.voterSession.tokenHash, "replaced");

  if (result.outcome !== "signed_in") {
    if (req.voterToken) sessions.clearSessionCookie(res, config.VOTER_COOKIE);
    return res.json({ outcome: result.outcome, message: result.message });
  }

  sessions.setSessionCookie(res, config.VOTER_COOKIE, result.token, result.session);
  res.json({ outcome: "signed_in", state: voters.describe(result.session) });
});

router.get("/voter/session", voterSession, (req, res) => {
  if (!req.voterSession) {
    if (req.voterToken) sessions.clearSessionCookie(res, config.VOTER_COOKIE);
    return res.json({ signedIn: false });
  }

  const session = sessions.touch(req.voterSession);
  res.json({ signedIn: true, state: voters.describe(session) });
});

router.post("/voter/rules", voterSession, requireVoter, (req, res) => {
  const result = voters.acceptRules(req.voterSession);
  if (!result.ok) return sendFailure(res, result);

  res.json({ ok: true, state: voters.describe(result.session) });
});

/* A mail server can be slow; do not let one voter start two sends at once. */
const sending = new Set();

router.post("/voter/otp/request", voterSession, requireVoter, async (req, res) => {
  const key = req.voterSession.tokenHash;

  if (sending.has(key)) {
    return res.status(429).json({ error: "Your code is already being sent. Please wait a moment.", code: "busy" });
  }

  sending.add(key);

  try {
    const result = await voters.requestOtp(req.voterSession, text(req.body.email, 200), ratelimit.clientIp(req));
    if (!result.ok) return sendFailure(res, result);

    res.json({
      ok: true,
      maskedEmail: result.maskedEmail,
      expiresInSec: result.expiresInSec,
      resendInSec: result.resendInSec,
      demoHint: result.demoHint,
      state: voters.describe(result.session)
    });
  } finally {
    sending.delete(key);
  }
});

router.post("/voter/otp/verify", voterSession, requireVoter, (req, res) => {
  const result = voters.verifyOtp(req.voterSession, text(req.body.code, 20), ratelimit.clientIp(req));
  if (!result.ok) return sendFailure(res, result);

  // Verification issues a fresh token; the one used so far stops working.
  if (result.token) sessions.setSessionCookie(res, config.VOTER_COOKIE, result.token, result.session);

  res.json({ ok: true, state: voters.describe(result.session) });
});

router.get("/voter/ballot", voterSession, requireVoter, ratelimit.byIp("ballotIp"), (req, res) => {
  const result = voters.getBallot(req.voterSession);
  if (!result.ok) return sendFailure(res, result);

  res.json({ offices: result.offices });
});

router.post("/voter/vote", voterSession, requireVoter, (req, res) => {
  const result = voters.castVote(req.voterSession, req.body.choices, ratelimit.clientIp(req));
  if (!result.ok) return sendFailure(res, result);

  // The session was deleted with the ballot; remove the browser's cookie too.
  sessions.clearSessionCookie(res, config.VOTER_COOKIE);
  res.json({ ok: true, receipt: result.receipt });
});

router.post("/voter/logout", voterSession, (req, res) => {
  if (req.voterSession) voters.logout(req.voterSession);

  sessions.clearSessionCookie(res, config.VOTER_COOKIE);
  res.json({ ok: true });
});

module.exports = router;
