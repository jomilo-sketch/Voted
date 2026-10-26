/*
  BOUESTI Vote — the election itself: name, dates, status, offices,
  candidates, announcements, and the rehearsal / live switch.

  Rehearsal vs live
  -----------------
  A fresh install is in REHEARSAL mode: demo OTP allowed, open roster,
  test data can be wiped. "Going live" is a one-way door, enforced by
  database triggers (schema.js): ballots can no longer be deleted, the
  election cannot return to rehearsal, and a closed election cannot be
  reopened. Going live wipes every rehearsal ballot first.
*/

"use strict";

const { EventEmitter } = require("events");
const d = require("./db");
const audit = require("./audit");
const sessions = require("./sessions");

const events = new EventEmitter();

const STATUSES = ["upcoming", "active", "closed"];

const DEFAULT_OFFICES = [
  ["President", "Amara Okafor", "David Mensah"],
  ["Vice President", "Zainab Bello", "Tobi Adeyemi"],
  ["General Secretary", "Kemi Adebayo", "Samuel Ajayi"],
  ["Assistant General Secretary", "Tomisin Afolabi", "Grace Eze"],
  ["Treasurer", "Ifeoluwa Ojo", "Daniel Nwachukwu"],
  ["Financial Secretary", "Rukayat Sanni", "Chidera Okeke"],
  ["Director of Sports", "Ayo Falade", "Blessing Nwosu"],
  ["Director of Social", "Favour Oladipo", "Emmanuel Umeh"],
  ["Welfare Director", "Mariam Yusuf", "Victor Adekunle"]
];

function getElection() {
  return d.get("SELECT * FROM election WHERE id = 1");
}

function seedIfEmpty() {
  if (getElection()) return false;

  d.tx(() => {
    d.run(
      `INSERT INTO election (id, electionName, schoolName, status, mode, rosterMode, updatedAt, openedAt)
       VALUES (1, ?, ?, 'active', 'rehearsal', 'open', ?, ?)`,
      "BOUESTI SUG Election 2026",
      "Bamidele Olumilua University of Education, Science and Technology",
      d.nowIso(), d.nowIso()
    );

    DEFAULT_OFFICES.forEach(([office, ...names], index) => {
      const result = d.run("INSERT INTO offices (office, sortOrder) VALUES (?, ?)", office, index);
      names.forEach((name) => {
        d.run(
          "INSERT INTO candidates (officeId, name, photoUrl, status) VALUES (?, ?, '', 'approved')",
          Number(result.lastInsertRowid), name
        );
      });
    });

    audit.append("system", "election", "Election created in rehearsal mode with sample offices and candidates");
  });

  return true;
}

/* ---------- counts ---------- */

function ballotCount() {
  return d.get("SELECT COUNT(*) AS n FROM ballots").n;
}

function turnoutCount() {
  return d.get("SELECT COUNT(*) AS n FROM turnout").n;
}

/* ---------- offices and candidates ---------- */

function getOffices({ approvedOnly = false } = {}) {
  const offices = d.all("SELECT id, office FROM offices ORDER BY sortOrder, id");
  const candidates = d.all("SELECT id, officeId, name, photoUrl, status FROM candidates ORDER BY id");

  return offices
    .map((office) => ({
      id: office.id,
      office: office.office,
      candidates: candidates
        .filter((c) => c.officeId === office.id && (!approvedOnly || c.status === "approved"))
        .map((c) => ({ id: c.id, name: c.name, photoUrl: c.photoUrl, status: c.status }))
    }))
    .filter((office) => !approvedOnly || office.candidates.length > 0);
}

/* What a voter is shown: only offices with approved candidates, and no
   internal status fields. */
function getBallotStructure() {
  return getOffices({ approvedOnly: true }).map((office) => ({
    id: office.id,
    office: office.office,
    candidates: office.candidates.map((c) => ({ id: c.id, name: c.name, photoUrl: c.photoUrl }))
  }));
}

function structureLock() {
  const election = getElection();

  if (ballotCount() > 0) {
    return "Ballots have already been cast, so the candidate list is locked.";
  }

  if (election.mode === "live" && election.status !== "upcoming") {
    return "In a live election the candidate list is locked once voting has opened.";
  }

  return null;
}

function cleanName(value, label, min = 2, max = 80) {
  const text = String(value ?? "").replace(/\s+/g, " ").trim();
  if (text.length < min || text.length > max) {
    return { error: `${label} must be ${min}–${max} characters.` };
  }
  return { value: text };
}

/* Candidate photos: an http(s) link, or a small embedded image. Anything
   else (javascript:, file:, huge blobs) is refused. */
function cleanPhoto(value) {
  const text = String(value ?? "").trim();
  if (!text) return { value: "" };

  if (/^https?:\/\/[^\s"'<>]{4,490}$/i.test(text)) return { value: text };

  if (/^data:image\/(png|jpeg|jpg|webp|gif);base64,[A-Za-z0-9+/=]+$/.test(text) && text.length <= 420_000) {
    return { value: text };
  }

  return { error: "Use a normal image link (https://…) or upload a small PNG/JPEG/WebP image." };
}

function addOfficeWithCandidate(officeInput, candidateInput, photoInput, admin) {
  const lock = structureLock();
  if (lock) return { ok: false, error: lock };

  const office = cleanName(officeInput, "The position name");
  const candidate = cleanName(candidateInput, "The candidate name");
  const photo = cleanPhoto(photoInput);

  if (office.error || candidate.error || photo.error) {
    return { ok: false, error: office.error || candidate.error || photo.error };
  }

  if (d.get("SELECT id FROM offices WHERE office = ? COLLATE NOCASE", office.value)) {
    return { ok: false, error: "A position with that name already exists." };
  }

  d.tx(() => {
    const next = d.get("SELECT COALESCE(MAX(sortOrder), -1) + 1 AS n FROM offices").n;
    const created = d.run("INSERT INTO offices (office, sortOrder) VALUES (?, ?)", office.value, next);

    d.run(
      "INSERT INTO candidates (officeId, name, photoUrl, status) VALUES (?, ?, ?, 'approved')",
      Number(created.lastInsertRowid), candidate.value, photo.value
    );

    touch(admin);
    audit.append(audit.adminActor(admin), "election", `Added position "${office.value}" with candidate "${candidate.value}"`);
  });

  return { ok: true };
}

function addCandidate(officeId, candidateInput, photoInput, admin) {
  const lock = structureLock();
  if (lock) return { ok: false, error: lock };

  const office = d.get("SELECT * FROM offices WHERE id = ?", Number(officeId));
  if (!office) return { ok: false, error: "Position not found." };

  const candidate = cleanName(candidateInput, "The candidate name");
  const photo = cleanPhoto(photoInput);
  if (candidate.error || photo.error) return { ok: false, error: candidate.error || photo.error };

  if (d.get("SELECT id FROM candidates WHERE officeId = ? AND name = ? COLLATE NOCASE", office.id, candidate.value)) {
    return { ok: false, error: "That candidate is already listed for this position." };
  }

  d.tx(() => {
    d.run(
      "INSERT INTO candidates (officeId, name, photoUrl, status) VALUES (?, ?, ?, 'approved')",
      office.id, candidate.value, photo.value
    );
    touch(admin);
    audit.append(audit.adminActor(admin), "election", `Added candidate "${candidate.value}" to "${office.office}"`);
  });

  return { ok: true };
}

function toggleCandidate(candidateId, admin) {
  const lock = structureLock();
  if (lock) return { ok: false, error: lock };

  const candidate = d.get("SELECT * FROM candidates WHERE id = ?", Number(candidateId));
  if (!candidate) return { ok: false, error: "Candidate not found." };

  const next = candidate.status === "approved" ? "pending" : "approved";

  d.tx(() => {
    d.run("UPDATE candidates SET status = ? WHERE id = ?", next, candidate.id);
    touch(admin);
    audit.append(audit.adminActor(admin), "election", `Candidate "${candidate.name}" set to ${next}`);
  });

  return { ok: true, status: next };
}

function removeCandidate(candidateId, admin) {
  const lock = structureLock();
  if (lock) return { ok: false, error: lock };

  const candidate = d.get("SELECT * FROM candidates WHERE id = ?", Number(candidateId));
  if (!candidate) return { ok: false, error: "Candidate not found." };

  d.tx(() => {
    d.run("DELETE FROM candidates WHERE id = ?", candidate.id);
    touch(admin);
    audit.append(audit.adminActor(admin), "election", `Removed candidate "${candidate.name}"`);
  });

  return { ok: true };
}

function removeOffice(officeId, admin) {
  const lock = structureLock();
  if (lock) return { ok: false, error: lock };

  const office = d.get("SELECT * FROM offices WHERE id = ?", Number(officeId));
  if (!office) return { ok: false, error: "Position not found." };

  d.tx(() => {
    d.run("DELETE FROM offices WHERE id = ?", office.id);
    touch(admin);
    audit.append(audit.adminActor(admin), "election", `Removed position "${office.office}" and its candidates`);
  });

  return { ok: true };
}

/* ---------- election details and status ---------- */

function touch(admin) {
  d.run(
    "UPDATE election SET updatedAt = ?, updatedBy = ? WHERE id = 1",
    d.nowIso(), admin ? admin.email : "system"
  );
}

function parseDate(value, label) {
  if (value === null || value === undefined || value === "") return { value: null };

  const ms = Date.parse(String(value));
  const year = new Date(ms).getUTCFullYear();

  if (!Number.isFinite(ms) || year < 2020 || year > 2100) {
    return { error: `${label} is not a valid date and time.` };
  }

  return { value: new Date(ms).toISOString() };
}

function votingState() {
  const election = getElection();

  if (election.status === "closed") return { open: false, reason: "closed" };
  if (election.status === "upcoming") return { open: false, reason: "upcoming" };

  if (election.votingClosesAt && Date.now() >= Date.parse(election.votingClosesAt)) {
    return { open: false, reason: "closed" };
  }

  return { open: true };
}

function updateElection(input, admin) {
  const current = getElection();

  if (current.mode === "live" && current.status === "closed") {
    return { ok: false, error: "This live election is closed and its record is frozen." };
  }

  const name = cleanName(input.electionName ?? current.electionName, "The election name", 3, 120);
  if (name.error) return { ok: false, error: name.error };

  const status = input.status ?? current.status;
  if (!STATUSES.includes(status)) return { ok: false, error: "Choose upcoming, active or closed." };

  const opens = parseDate(input.votingOpensAt === undefined ? current.votingOpensAt : input.votingOpensAt, "The opening time");
  const closes = parseDate(input.votingClosesAt === undefined ? current.votingClosesAt : input.votingClosesAt, "The closing time");
  if (opens.error || closes.error) return { ok: false, error: opens.error || closes.error };

  if (opens.value && closes.value && Date.parse(closes.value) <= Date.parse(opens.value)) {
    return { ok: false, error: "The closing time must be after the opening time." };
  }

  if (status === "active" && closes.value && Date.parse(closes.value) <= Date.now()) {
    return { ok: false, error: "That closing time has already passed. Choose a later closing time before opening voting." };
  }

  if (status === "active" && getBallotStructure().length === 0) {
    return { ok: false, error: "Add at least one position with an approved candidate before opening voting." };
  }

  const changes = [];
  if (name.value !== current.electionName) changes.push(`name "${current.electionName}" → "${name.value}"`);
  if (status !== current.status) changes.push(`status ${current.status} → ${status}`);
  if (opens.value !== current.votingOpensAt) changes.push(`opens ${current.votingOpensAt || "unset"} → ${opens.value || "unset"}`);
  if (closes.value !== current.votingClosesAt) changes.push(`closes ${current.votingClosesAt || "unset"} → ${closes.value || "unset"}`);

  const becameClosed = status === "closed" && current.status !== "closed";
  const firstOpen = status === "active" && !current.openedAt;

  /* The server opens voting by itself only when the election is left
     UPCOMING with an opening time that is still ahead (or that was already
     waiting and has not changed). Pausing an election that was running — its
     opening time is in the past — is therefore never undone by the schedule. */
  const waiting = Boolean(current.autoOpen) && current.status === "upcoming" && opens.value === current.votingOpensAt;
  const autoOpen = status === "upcoming" && Boolean(opens.value) && (Date.parse(opens.value) > Date.now() || waiting) ? 1 : 0;

  if (autoOpen !== Number(current.autoOpen)) {
    changes.push(autoOpen ? "voting will open by itself at the opening time" : "voting will not open by itself");
  }

  d.tx(() => {
    d.run(
      `UPDATE election SET electionName = ?, status = ?, votingOpensAt = ?, votingClosesAt = ?, autoOpen = ?,
         openedAt = COALESCE(openedAt, ?), closedAt = ?, updatedAt = ?, updatedBy = ? WHERE id = 1`,
      name.value, status, opens.value, closes.value, autoOpen,
      firstOpen ? d.nowIso() : null,
      becameClosed ? d.nowIso() : (status === "closed" ? current.closedAt : null),
      d.nowIso(), admin ? admin.email : "system"
    );

    audit.append(
      admin ? audit.adminActor(admin) : "system",
      "election",
      changes.length ? `Election details saved: ${changes.join("; ")}` : "Election details saved (no changes)"
    );

    if (becameClosed) {
      sessions.revokeAllForKind("voter", "election-closed");
      audit.checkpoint("election closed");
    }
  });

  if (becameClosed) events.emit("closed", { by: admin ? admin.email : "system" });

  const notice =
    status === "upcoming" && opens.value && !autoOpen
      ? "The opening time has already passed, so voting will not open by itself. Press Active when you are ready to open it."
      : null;

  return { ok: true, notice };
}

/* Is the server waiting to open voting at the scheduled time? */
function opensByItself(election = getElection()) {
  return Boolean(election.autoOpen) && election.status === "upcoming" && Boolean(election.votingOpensAt);
}

/* Called every few seconds by the scheduler. Opens an election that an
   officer left "upcoming" with an opening time in the future, once that time
   arrives; and closes an open election at its closing time. A manual pause
   is never auto-resumed (see updateElection). */
function applySchedule() {
  const election = getElection();
  if (!election) return null;

  const now = Date.now();

  if (
    opensByItself(election) &&
    now >= Date.parse(election.votingOpensAt) &&
    (!election.votingClosesAt || now < Date.parse(election.votingClosesAt)) &&
    getBallotStructure().length > 0
  ) {
    d.tx(() => {
      d.run(
        "UPDATE election SET status = 'active', autoOpen = 0, openedAt = COALESCE(openedAt, ?), updatedAt = ?, updatedBy = 'system' WHERE id = 1",
        d.nowIso(), d.nowIso()
      );
      audit.append("system", "election", "Voting opened automatically at the scheduled time");
    });
    return "opened";
  }

  if (election.status === "active" && election.votingClosesAt && now >= Date.parse(election.votingClosesAt)) {
    updateElection({ status: "closed" }, null);
    return "closed";
  }

  return null;
}

function updateSettings({ schoolName, rosterMode }, admin) {
  const current = getElection();
  const changes = [];
  let nextSchool = current.schoolName;
  let nextRoster = current.rosterMode;

  if (schoolName !== undefined) {
    const school = cleanName(schoolName, "The school name", 3, 150);
    if (school.error) return { ok: false, error: school.error };
    nextSchool = school.value;
    if (nextSchool !== current.schoolName) changes.push("school name");
  }

  if (rosterMode !== undefined) {
    if (!["open", "closed"].includes(rosterMode)) return { ok: false, error: "Roster mode must be open or closed." };

    if (current.mode === "live" && rosterMode === "open") {
      return { ok: false, error: "A live election must use the closed roster." };
    }

    nextRoster = rosterMode;
    if (nextRoster !== current.rosterMode) changes.push(`roster mode ${current.rosterMode} → ${nextRoster}`);
  }

  d.tx(() => {
    d.run(
      "UPDATE election SET schoolName = ?, rosterMode = ?, updatedAt = ?, updatedBy = ? WHERE id = 1",
      nextSchool, nextRoster, d.nowIso(), admin.email
    );
    audit.append(audit.adminActor(admin), "election", `Settings saved: ${changes.join(", ") || "no changes"}`);
  });

  return { ok: true };
}

/* ---------- announcements ---------- */

function latestAnnouncement() {
  const row = d.get("SELECT id, message, postedAt, hidden FROM announcements ORDER BY id DESC LIMIT 1");
  return row && !row.hidden ? { id: row.id, message: row.message, postedAt: row.postedAt } : null;
}

function listAnnouncements(limit = 30) {
  return d.all(
    "SELECT id, message, postedAt, postedBy, hidden FROM announcements ORDER BY id DESC LIMIT ?",
    limit
  ).map((row) => ({ ...row, hidden: Boolean(row.hidden) }));
}

function postAnnouncement(messageInput, admin) {
  const message = String(messageInput ?? "").replace(/\s+/g, " ").trim();

  if (message.length < 3 || message.length > 400) {
    return { ok: false, error: "An announcement must be 3–400 characters." };
  }

  d.tx(() => {
    d.run(
      "INSERT INTO announcements (message, postedAt, postedBy, hidden) VALUES (?, ?, ?, 0)",
      message, d.nowIso(), admin.email
    );
    audit.append(audit.adminActor(admin), "election", "Posted a student announcement");
  });

  return { ok: true };
}

function clearAnnouncement(admin) {
  const latest = d.get("SELECT id, hidden FROM announcements ORDER BY id DESC LIMIT 1");

  if (!latest || latest.hidden) return { ok: false, error: "There is no banner showing right now." };

  d.tx(() => {
    d.run("UPDATE announcements SET hidden = 1 WHERE id = ?", latest.id);
    audit.append(audit.adminActor(admin), "election", "Cleared the student announcement banner");
  });

  return { ok: true };
}

/* ---------- rehearsal data and going live ---------- */

function wipeBallotData() {
  const counts = {
    ballots: ballotCount(),
    turnout: turnoutCount(),
    receipts: d.get("SELECT COUNT(*) AS n FROM receipts").n
  };

  d.run("DELETE FROM ballot_selections");
  d.run("DELETE FROM ballots");
  d.run("DELETE FROM receipts");
  d.run("DELETE FROM turnout");
  d.run("DELETE FROM turnout_hourly");
  d.run("UPDATE students SET registered = 0, registeredAt = NULL, verified = 0, verifiedAt = NULL");
  d.run("DELETE FROM sessions WHERE kind = 'voter'");

  return counts;
}

function resetRehearsal(admin) {
  const election = getElection();
  if (election.mode !== "rehearsal") {
    return { ok: false, error: "Only a rehearsal can be reset. A live election's record is permanent." };
  }

  const counts = d.tx(() => {
    const wiped = wipeBallotData();
    d.run(
      "UPDATE election SET status = 'active', autoOpen = 0, openedAt = ?, closedAt = NULL, resultsPublished = 0, updatedAt = ?, updatedBy = ? WHERE id = 1",
      d.nowIso(), d.nowIso(), admin.email
    );
    d.run("UPDATE result_reports SET status = 'superseded' WHERE status IN ('pending', 'published')");

    audit.append(
      audit.adminActor(admin), "election",
      `Rehearsal reset: removed ${wiped.ballots} test ballot(s) and ${wiped.turnout} turnout record(s)`
    );
    return wiped;
  });

  return { ok: true, removed: counts };
}

/* One-way. The route checks readiness and confirmations first. */
function goLive(admin) {
  const election = getElection();
  if (election.mode === "live") return { ok: false, error: "This election is already live." };

  const counts = d.tx(() => {
    const wiped = wipeBallotData();
    d.run("UPDATE result_reports SET status = 'superseded' WHERE status IN ('pending', 'published')");
    d.run(
      `UPDATE election SET mode = 'live', rosterMode = 'closed', status = 'upcoming', autoOpen = 0, openedAt = NULL,
         closedAt = NULL, resultsPublished = 0, wentLiveAt = ?, updatedAt = ?, updatedBy = ? WHERE id = 1`,
      d.nowIso(), d.nowIso(), admin.email
    );

    audit.append(
      audit.adminActor(admin), "election",
      `ELECTION WENT LIVE. Rehearsal data wiped (${wiped.ballots} ballot(s), ${wiped.turnout} turnout record(s)). ` +
        "Roster closed; voting set to upcoming; ballots can no longer be deleted."
    );
    audit.checkpoint("election went live");
    return wiped;
  });

  return { ok: true, removed: counts };
}

module.exports = {
  events,
  STATUSES,
  getElection,
  seedIfEmpty,
  ballotCount,
  turnoutCount,
  getOffices,
  getBallotStructure,
  structureLock,
  addOfficeWithCandidate,
  addCandidate,
  toggleCandidate,
  removeCandidate,
  removeOffice,
  votingState,
  updateElection,
  opensByItself,
  applySchedule,
  updateSettings,
  latestAnnouncement,
  listAnnouncements,
  postAnnouncement,
  clearAnnouncement,
  resetRehearsal,
  goLive
};
