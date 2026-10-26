/*
  BOUESTI Vote — database schema.

  Kept free of any connection logic so the same definition can be applied
  to the live database (db.js) and inspected by the verification scripts.

  Where the privacy and integrity guarantees live
  -----------------------------------------------
  * students   eligibility + progress (who may vote, how far they got).
               NO column here says what anyone voted for.
  * turnout    one row per person who has used their vote. The key is an
               HMAC of the matric number (never the matric itself) and the
               row carries no timestamp, so it proves "this person voted"
               without saying when or for whom.
  * ballots / ballot_selections / receipts
               carry NO voter reference and NO timestamp. They are
               WITHOUT ROWID tables keyed by random values, so even the
               physical row order does not reveal who voted first.
  * audit_log  append-only, hash-chained. It never contains a ballot choice.
  * Triggers   make the audit log, ballots, turnout and signed reports
               immutable at the database level, not just in application code.
*/

"use strict";

const SCHEMA_VERSION = 1;

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
) WITHOUT ROWID;

/* ------------------------------------------------------------------ */
/* Election definition                                                 */
/* ------------------------------------------------------------------ */

CREATE TABLE IF NOT EXISTS election (
  id               INTEGER PRIMARY KEY CHECK (id = 1),
  electionName     TEXT NOT NULL,
  schoolName       TEXT NOT NULL,
  status           TEXT NOT NULL DEFAULT 'active'
                   CHECK (status IN ('upcoming', 'active', 'closed')),
  mode             TEXT NOT NULL DEFAULT 'rehearsal'
                   CHECK (mode IN ('rehearsal', 'live')),
  rosterMode       TEXT NOT NULL DEFAULT 'open'
                   CHECK (rosterMode IN ('open', 'closed')),
  votingOpensAt    TEXT,
  votingClosesAt   TEXT,
  openedAt         TEXT,
  /* 1 = the server opens voting by itself at votingOpensAt. Set only when an
     officer saves an UPCOMING election whose opening time is still ahead, so
     a manual pause (opening time already past) is never auto-resumed. */
  autoOpen         INTEGER NOT NULL DEFAULT 0 CHECK (autoOpen IN (0, 1)),
  closedAt         TEXT,
  wentLiveAt       TEXT,
  resultsPublished INTEGER NOT NULL DEFAULT 0 CHECK (resultsPublished IN (0, 1)),
  updatedAt        TEXT NOT NULL,
  updatedBy        TEXT NOT NULL DEFAULT 'system'
);

CREATE TABLE IF NOT EXISTS offices (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  office    TEXT NOT NULL UNIQUE,
  sortOrder INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS candidates (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  officeId INTEGER NOT NULL REFERENCES offices(id) ON DELETE CASCADE,
  name     TEXT NOT NULL,
  photoUrl TEXT NOT NULL DEFAULT '',
  status   TEXT NOT NULL DEFAULT 'approved' CHECK (status IN ('approved', 'pending'))
);

CREATE TABLE IF NOT EXISTS announcements (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  message  TEXT NOT NULL,
  postedAt TEXT NOT NULL,
  postedBy TEXT NOT NULL DEFAULT 'system',
  hidden   INTEGER NOT NULL DEFAULT 0
);

/* ------------------------------------------------------------------ */
/* Eligibility (who may vote). Contains no ballot information.         */
/* ------------------------------------------------------------------ */

CREATE TABLE IF NOT EXISTS students (
  matric       TEXT PRIMARY KEY
               CHECK (length(matric) BETWEEN 4 AND 15 AND matric NOT GLOB '*[^0-9]*'),
  name         TEXT NOT NULL DEFAULT '',
  email        TEXT NOT NULL DEFAULT '',
  registered   INTEGER NOT NULL DEFAULT 0,
  registeredAt TEXT,
  verified     INTEGER NOT NULL DEFAULT 0,
  verifiedAt   TEXT,
  active       INTEGER NOT NULL DEFAULT 1,
  addedAt      TEXT NOT NULL
) WITHOUT ROWID;

/* ------------------------------------------------------------------ */
/* Turnout and ballots — deliberately NOT linked to each other.        */
/* ------------------------------------------------------------------ */

CREATE TABLE IF NOT EXISTS turnout (
  voterHash TEXT PRIMARY KEY
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS turnout_hourly (
  hour  TEXT PRIMARY KEY,
  count INTEGER NOT NULL DEFAULT 0
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS ballots (
  ballotId TEXT PRIMARY KEY
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS ballot_selections (
  ballotId    TEXT    NOT NULL REFERENCES ballots(ballotId),
  officeId    INTEGER NOT NULL REFERENCES offices(id),
  candidateId INTEGER NOT NULL REFERENCES candidates(id),
  PRIMARY KEY (ballotId, officeId)
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS idx_selections_candidate ON ballot_selections(candidateId);

CREATE TABLE IF NOT EXISTS receipts (
  codeHash TEXT PRIMARY KEY
) WITHOUT ROWID;

/* ------------------------------------------------------------------ */
/* Audit trail                                                          */
/* ------------------------------------------------------------------ */

CREATE TABLE IF NOT EXISTS audit_log (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  occurredAt TEXT NOT NULL,
  actor      TEXT NOT NULL,
  category   TEXT NOT NULL,
  message    TEXT NOT NULL,
  prevHash   TEXT NOT NULL,
  hash       TEXT NOT NULL UNIQUE
);

CREATE INDEX IF NOT EXISTS idx_audit_category ON audit_log(category, id);

CREATE TABLE IF NOT EXISTS audit_checkpoints (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  auditId   INTEGER NOT NULL,
  auditHash TEXT NOT NULL,
  reason    TEXT NOT NULL,
  createdAt TEXT NOT NULL,
  signature TEXT NOT NULL
);

/* ------------------------------------------------------------------ */
/* Sessions and rate limits — persistent, so a restart changes nothing */
/* ------------------------------------------------------------------ */

CREATE TABLE IF NOT EXISTS sessions (
  tokenHash         TEXT PRIMARY KEY,
  kind              TEXT NOT NULL CHECK (kind IN ('voter', 'admin')),
  subject           TEXT NOT NULL,
  stage             TEXT NOT NULL,
  data              TEXT NOT NULL DEFAULT '{}',
  createdAt         INTEGER NOT NULL,
  lastActiveAt      INTEGER NOT NULL,
  idleExpiresAt     INTEGER NOT NULL,
  absoluteExpiresAt INTEGER NOT NULL,
  revokedAt         INTEGER,
  revokedReason     TEXT,
  ip                TEXT,
  userAgent         TEXT
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS idx_sessions_subject ON sessions(kind, subject);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(absoluteExpiresAt);

CREATE TABLE IF NOT EXISTS rate_limits (
  bucket       TEXT PRIMARY KEY,
  windowStart  INTEGER NOT NULL,
  count        INTEGER NOT NULL,
  blockedUntil INTEGER NOT NULL DEFAULT 0
) WITHOUT ROWID;

/* ------------------------------------------------------------------ */
/* Administrators                                                       */
/* ------------------------------------------------------------------ */

CREATE TABLE IF NOT EXISTS admins (
  id                 INTEGER PRIMARY KEY AUTOINCREMENT,
  email              TEXT NOT NULL UNIQUE COLLATE NOCASE,
  displayName        TEXT NOT NULL,
  role               TEXT NOT NULL
                     CHECK (role IN ('electoral_officer', 'results_officer', 'technical_support')),
  passwordHash       TEXT NOT NULL,
  mustChangePassword INTEGER NOT NULL DEFAULT 1,
  passwordChangedAt  TEXT,
  totpSecretEnc      TEXT,
  totpEnabled        INTEGER NOT NULL DEFAULT 0,
  totpLastStep       INTEGER NOT NULL DEFAULT 0,
  failedAttempts     INTEGER NOT NULL DEFAULT 0,
  lockedUntil        INTEGER NOT NULL DEFAULT 0,
  disabled           INTEGER NOT NULL DEFAULT 0,
  lastLoginAt        TEXT,
  createdAt          TEXT NOT NULL,
  createdBy          TEXT NOT NULL DEFAULT 'system'
);

CREATE TABLE IF NOT EXISTS admin_recovery_codes (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  adminId  INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
  codeHash TEXT NOT NULL,
  usedAt   TEXT
);

CREATE TABLE IF NOT EXISTS password_resets (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  adminId   INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
  codeHash  TEXT NOT NULL,
  issuedBy  TEXT NOT NULL,
  issuedAt  INTEGER NOT NULL,
  expiresAt INTEGER NOT NULL,
  usedAt    INTEGER,
  status    TEXT NOT NULL DEFAULT 'pending'
            CHECK (status IN ('pending', 'used', 'expired', 'cancelled'))
);

CREATE TABLE IF NOT EXISTS admin_login_history (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  adminId INTEGER,
  email   TEXT NOT NULL,
  at      TEXT NOT NULL,
  ip      TEXT,
  outcome TEXT NOT NULL,
  detail  TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_login_history_admin ON admin_login_history(adminId, id);

/* ------------------------------------------------------------------ */
/* Signed results                                                       */
/* ------------------------------------------------------------------ */

CREATE TABLE IF NOT EXISTS result_reports (
  id                   INTEGER PRIMARY KEY AUTOINCREMENT,
  reportJson           TEXT NOT NULL,
  reportHash           TEXT NOT NULL,
  signature            TEXT NOT NULL,
  preparedBy           TEXT NOT NULL,
  preparedAt           TEXT NOT NULL,
  status               TEXT NOT NULL DEFAULT 'pending'
                       CHECK (status IN ('pending', 'published', 'superseded', 'rejected')),
  approvedBy           TEXT,
  approvedAt           TEXT,
  publicationJson      TEXT,
  publicationSignature TEXT,
  note                 TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS report_comparisons (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  reportId    INTEGER NOT NULL REFERENCES result_reports(id),
  performedBy TEXT NOT NULL,
  witnessBy   TEXT NOT NULL,
  at          TEXT NOT NULL,
  outcome     TEXT NOT NULL CHECK (outcome IN ('match', 'mismatch')),
  detailJson  TEXT NOT NULL
);

/* ------------------------------------------------------------------ */
/* Operations: backups, restoration drills, audit copies, incidents    */
/* ------------------------------------------------------------------ */

CREATE TABLE IF NOT EXISTS backup_runs (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  startedAt  TEXT NOT NULL,
  finishedAt TEXT,
  trigger    TEXT NOT NULL,
  file       TEXT,
  sizeBytes  INTEGER,
  sha256     TEXT,
  status     TEXT NOT NULL,
  detail     TEXT NOT NULL DEFAULT '',
  prunedAt   TEXT
);

CREATE TABLE IF NOT EXISTS drill_runs (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  startedAt  TEXT NOT NULL,
  durationMs INTEGER,
  backupFile TEXT,
  trigger    TEXT NOT NULL,
  status     TEXT NOT NULL,
  checksJson TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS audit_copies (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  createdAt     TEXT NOT NULL,
  file          TEXT NOT NULL,
  sha256        TEXT NOT NULL,
  sizeBytes     INTEGER NOT NULL,
  auditHeadId   INTEGER,
  auditHeadHash TEXT,
  reason        TEXT NOT NULL DEFAULT 'schedule',
  prunedAt      TEXT
);

CREATE TABLE IF NOT EXISTS incidents (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  openedAt   TEXT NOT NULL,
  openedBy   TEXT NOT NULL,
  severity   TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
  title      TEXT NOT NULL,
  details    TEXT NOT NULL DEFAULT '',
  status     TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'investigating', 'resolved')),
  resolvedAt TEXT,
  resolvedBy TEXT,
  resolution TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS student_reports (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  receivedAt TEXT NOT NULL,
  category   TEXT NOT NULL,
  message    TEXT NOT NULL,
  contact    TEXT NOT NULL DEFAULT '',
  matric     TEXT NOT NULL DEFAULT '',
  status     TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'seen', 'resolved')),
  handledBy  TEXT,
  handledAt  TEXT
);

/* ------------------------------------------------------------------ */
/* Immutability enforced by the database itself                         */
/* ------------------------------------------------------------------ */

CREATE TRIGGER IF NOT EXISTS trg_audit_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;

CREATE TRIGGER IF NOT EXISTS trg_audit_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;

CREATE TRIGGER IF NOT EXISTS trg_checkpoints_no_update BEFORE UPDATE ON audit_checkpoints
BEGIN SELECT RAISE(ABORT, 'audit_checkpoints is append-only'); END;

CREATE TRIGGER IF NOT EXISTS trg_checkpoints_no_delete BEFORE DELETE ON audit_checkpoints
BEGIN SELECT RAISE(ABORT, 'audit_checkpoints is append-only'); END;

CREATE TRIGGER IF NOT EXISTS trg_login_history_no_update BEFORE UPDATE ON admin_login_history
BEGIN SELECT RAISE(ABORT, 'admin_login_history is append-only'); END;

CREATE TRIGGER IF NOT EXISTS trg_login_history_no_delete BEFORE DELETE ON admin_login_history
BEGIN SELECT RAISE(ABORT, 'admin_login_history is append-only'); END;

CREATE TRIGGER IF NOT EXISTS trg_ballots_no_update BEFORE UPDATE ON ballots
BEGIN SELECT RAISE(ABORT, 'ballots cannot be modified'); END;

CREATE TRIGGER IF NOT EXISTS trg_ballots_no_delete BEFORE DELETE ON ballots
WHEN (SELECT mode FROM election WHERE id = 1) = 'live'
BEGIN SELECT RAISE(ABORT, 'ballots cannot be deleted in a live election'); END;

CREATE TRIGGER IF NOT EXISTS trg_selections_no_update BEFORE UPDATE ON ballot_selections
BEGIN SELECT RAISE(ABORT, 'ballot selections cannot be modified'); END;

CREATE TRIGGER IF NOT EXISTS trg_selections_no_delete BEFORE DELETE ON ballot_selections
WHEN (SELECT mode FROM election WHERE id = 1) = 'live'
BEGIN SELECT RAISE(ABORT, 'ballot selections cannot be deleted in a live election'); END;

CREATE TRIGGER IF NOT EXISTS trg_receipts_no_update BEFORE UPDATE ON receipts
BEGIN SELECT RAISE(ABORT, 'receipts cannot be modified'); END;

CREATE TRIGGER IF NOT EXISTS trg_receipts_no_delete BEFORE DELETE ON receipts
WHEN (SELECT mode FROM election WHERE id = 1) = 'live'
BEGIN SELECT RAISE(ABORT, 'receipts cannot be deleted in a live election'); END;

CREATE TRIGGER IF NOT EXISTS trg_turnout_no_update BEFORE UPDATE ON turnout
BEGIN SELECT RAISE(ABORT, 'turnout cannot be modified'); END;

CREATE TRIGGER IF NOT EXISTS trg_turnout_no_delete BEFORE DELETE ON turnout
WHEN (SELECT mode FROM election WHERE id = 1) = 'live'
BEGIN SELECT RAISE(ABORT, 'turnout cannot be deleted in a live election'); END;

CREATE TRIGGER IF NOT EXISTS trg_reports_no_delete BEFORE DELETE ON result_reports
BEGIN SELECT RAISE(ABORT, 'result reports cannot be deleted'); END;

CREATE TRIGGER IF NOT EXISTS trg_reports_frozen_content BEFORE UPDATE ON result_reports
WHEN OLD.reportJson != NEW.reportJson OR OLD.reportHash != NEW.reportHash
  OR OLD.signature != NEW.signature OR OLD.preparedBy != NEW.preparedBy
  OR OLD.preparedAt != NEW.preparedAt
BEGIN SELECT RAISE(ABORT, 'a signed report cannot be edited'); END;

CREATE TRIGGER IF NOT EXISTS trg_comparisons_no_update BEFORE UPDATE ON report_comparisons
BEGIN SELECT RAISE(ABORT, 'report_comparisons is append-only'); END;

CREATE TRIGGER IF NOT EXISTS trg_comparisons_no_delete BEFORE DELETE ON report_comparisons
BEGIN SELECT RAISE(ABORT, 'report_comparisons is append-only'); END;

CREATE TRIGGER IF NOT EXISTS trg_election_live_is_one_way BEFORE UPDATE OF mode ON election
WHEN OLD.mode = 'live' AND NEW.mode != 'live'
BEGIN SELECT RAISE(ABORT, 'a live election cannot be switched back to rehearsal'); END;

CREATE TRIGGER IF NOT EXISTS trg_election_closed_is_final BEFORE UPDATE OF status ON election
WHEN OLD.mode = 'live' AND OLD.status = 'closed' AND NEW.status != 'closed'
BEGIN SELECT RAISE(ABORT, 'a closed live election cannot be reopened'); END;
`;

module.exports = { SCHEMA_VERSION, SCHEMA_SQL };
