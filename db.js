/*
  BOUESTI Vote — the database connection.

  node:sqlite is built into Node 22.13+ (no native add-on to compile).
  This module opens election.db once, applies the schema, and exposes a
  few small helpers. Everything else (sessions, voters, admins, reports,
  backups...) is built on these.

  All statements are synchronous. That is deliberate: a vote is recorded
  in ONE synchronous transaction, so two requests can never interleave in
  the middle of it.
*/

"use strict";

const fs = require("fs");
const { DatabaseSync } = require("node:sqlite");
const config = require("./config");
const keys = require("./keys");
const { SCHEMA_SQL, SCHEMA_VERSION } = require("./schema");

function nowIso() {
  return new Date().toISOString();
}

/* Open any SQLite file with the safety settings this project relies on. */
function openDatabase(file, { readOnly = false } = {}) {
  const handle = new DatabaseSync(file, { readOnly });

  if (!readOnly) {
    handle.exec("PRAGMA journal_mode = WAL;");
    handle.exec("PRAGMA synchronous = FULL;");
    handle.exec("PRAGMA secure_delete = ON;");
  }

  handle.exec("PRAGMA foreign_keys = ON;");
  handle.exec("PRAGMA busy_timeout = 5000;");
  return handle;
}

/* ---------- start-up: never silently run with the wrong key ---------- */

fs.mkdirSync(config.DATA_DIR, { recursive: true, mode: 0o700 });

const databaseAlreadyExisted = fs.existsSync(config.DB_PATH);

if (databaseAlreadyExisted && !keys.masterKeyFileExists()) {
  throw new Error(
    "An election database exists but no master key was found.\n" +
      `Restore the saved key to ${config.KEY_DIR}/master.key (or set BOUESTI_MASTER_KEY).\n` +
      "A new key would make encrypted backups, 2FA secrets and the turnout record unreadable, " +
      "so the server refuses to invent one."
  );
}

const db = openDatabase(config.DB_PATH);
db.exec(SCHEMA_SQL);

/* A database made by an earlier build of this project may lack a column that
   the schema now defines. Columns are only ever ADDED here — never renamed,
   retyped or dropped — so an older database (or an older backup restored onto
   this build) simply gains what it is missing. */
function addMissingColumns() {
  const present = (table) => db.prepare(`PRAGMA table_info(${table})`).all().map((column) => column.name);

  if (!present("election").includes("autoOpen")) {
    db.exec("ALTER TABLE election ADD COLUMN autoOpen INTEGER NOT NULL DEFAULT 0 CHECK (autoOpen IN (0, 1))");
  }
}

addMissingColumns();

/* ---------- small helpers ---------- */

const statementCache = new Map();

function normaliseParam(value) {
  if (value === undefined) return null;
  if (typeof value === "boolean") return value ? 1 : 0;
  return value;
}

function statement(sql) {
  let prepared = statementCache.get(sql);
  if (!prepared) {
    prepared = db.prepare(sql);
    statementCache.set(sql, prepared);
  }
  return prepared;
}

function get(sql, ...params) {
  return statement(sql).get(...params.map(normaliseParam));
}

function all(sql, ...params) {
  return statement(sql).all(...params.map(normaliseParam));
}

function run(sql, ...params) {
  return statement(sql).run(...params.map(normaliseParam));
}

/* Run fn() inside one atomic transaction. fn must be synchronous. Calls
   may nest (inner calls become savepoints). */
let depth = 0;

function tx(fn) {
  const outermost = depth === 0;
  const savepoint = `sp${depth}`;

  db.exec(outermost ? "BEGIN IMMEDIATE" : `SAVEPOINT ${savepoint}`);
  depth += 1;

  let result;

  try {
    result = fn();

    if (result && typeof result.then === "function") {
      throw new Error("tx() callbacks must be synchronous — do not await inside a transaction.");
    }
  } catch (error) {
    depth -= 1;

    try {
      db.exec(outermost ? "ROLLBACK" : `ROLLBACK TO ${savepoint}; RELEASE ${savepoint}`);
    } catch (rollbackError) {
      /* the connection already discarded the transaction */
    }

    throw error;
  }

  depth -= 1;

  try {
    db.exec(outermost ? "COMMIT" : `RELEASE ${savepoint}`);
  } catch (commitError) {
    try {
      db.exec("ROLLBACK");
    } catch (rollbackError) {
      /* nothing to roll back */
    }
    throw commitError;
  }

  return result;
}

function getMeta(key) {
  const row = get("SELECT value FROM meta WHERE key = ?", key);
  return row ? row.value : null;
}

function setMeta(key, value) {
  run(
    "INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
    key,
    String(value)
  );
}

/* Record this database's key fingerprint on first use, and refuse to
   continue if a different key is supplied later. */
function ensureKeyMatches() {
  const stored = getMeta("key_fingerprint");
  const current = keys.fingerprint();

  if (!stored) {
    setMeta("key_fingerprint", current);
    setMeta("schema_version", SCHEMA_VERSION);
    setMeta("created_at", nowIso());
    return;
  }

  if (stored !== current) {
    throw new Error(
      "The master key does not match this database (key fingerprint differs).\n" +
        "Put the ORIGINAL master key back in data/keys/master.key (or BOUESTI_MASTER_KEY).\n" +
        "Do not delete the database — nothing has been changed."
    );
  }
}

ensureKeyMatches();

function integrityCheck() {
  const rows = db.prepare("PRAGMA integrity_check").all();
  const foreign = db.prepare("PRAGMA foreign_key_check").all();
  const messages = rows.map((row) => row.integrity_check);

  return {
    ok: messages.length === 1 && messages[0] === "ok" && foreign.length === 0,
    messages,
    foreignKeyViolations: foreign.length
  };
}

function close() {
  try {
    db.exec("PRAGMA wal_checkpoint(TRUNCATE);");
  } catch (error) {
    /* best effort */
  }
  db.close();
}

module.exports = {
  db,
  openDatabase,
  nowIso,
  get,
  all,
  run,
  tx,
  getMeta,
  setMeta,
  integrityCheck,
  close
};
