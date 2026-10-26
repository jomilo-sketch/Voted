/*
  BOUESTI Vote — backup files: encrypt, decrypt, inspect, restore.

  This module works on FILES ONLY. It never opens the live election
  database, which is why the offline scripts (restore, drill, verify) can
  use it safely while the server is stopped.

  File layout of a backup (.bvbak):

      "BVBAK001" (8 bytes) | IV (12) | AES-256-GCM ciphertext | auth tag (16)

  with a sidecar manifest (.manifest.json) that records the SHA-256 of the
  ciphertext, what the snapshot should contain, which key encrypted it, and
  an HMAC so the manifest cannot be edited without the master key.

  A backup you have not restored is only a hope. inspectBackup() performs
  a full test restore into a scratch directory and runs every integrity
  check we can think of; drills run it on a schedule.
*/

"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { DatabaseSync } = require("node:sqlite");
const config = require("./config");
const keys = require("./keys");
const chain = require("./chain");

const MAGIC = Buffer.from("BVBAK001");
const IV_LENGTH = 12;
const TAG_LENGTH = 16;
const CHUNK = 1024 * 1024;

function sortKeys(value) {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value && typeof value === "object") {
    return Object.keys(value).sort().reduce((out, key) => {
      out[key] = sortKeys(value[key]);
      return out;
    }, {});
  }
  return value;
}

function canonical(value) {
  return JSON.stringify(sortKeys(value));
}

/* ---------- encryption ---------- */

function encryptFile(plainPath, outPath) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv("aes-256-gcm", keys.deriveKey("backup-enc"), iv);
  cipher.setAAD(MAGIC);

  const hash = crypto.createHash("sha256");
  const input = fs.openSync(plainPath, "r");
  const output = fs.openSync(outPath, "w", 0o600);
  const buffer = Buffer.alloc(CHUNK);
  let plainBytes = 0;

  const emit = (data) => {
    if (data.length === 0) return;
    fs.writeSync(output, data);
    hash.update(data);
  };

  try {
    emit(MAGIC);
    emit(iv);

    let read;
    while ((read = fs.readSync(input, buffer, 0, CHUNK, null)) > 0) {
      plainBytes += read;
      emit(cipher.update(buffer.subarray(0, read)));
    }

    emit(cipher.final());
    emit(cipher.getAuthTag());
    fs.fsyncSync(output);
  } finally {
    fs.closeSync(input);
    fs.closeSync(output);
  }

  return { sha256: hash.digest("hex"), cipherSizeBytes: fs.statSync(outPath).size, plainSizeBytes: plainBytes };
}

/* Throws if the file is damaged, truncated, or was not encrypted with this key. */
function decryptFile(cipherPath, outPath) {
  const size = fs.statSync(cipherPath).size;

  if (size < MAGIC.length + IV_LENGTH + TAG_LENGTH) throw new Error("Backup file is too short.");

  const input = fs.openSync(cipherPath, "r");
  let output = null;

  try {
    const head = Buffer.alloc(MAGIC.length + IV_LENGTH);
    fs.readSync(input, head, 0, head.length, 0);

    if (!head.subarray(0, MAGIC.length).equals(MAGIC)) throw new Error("This is not a BOUESTI Vote backup file.");

    const tag = Buffer.alloc(TAG_LENGTH);
    fs.readSync(input, tag, 0, TAG_LENGTH, size - TAG_LENGTH);

    const decipher = crypto.createDecipheriv("aes-256-gcm", keys.deriveKey("backup-enc"), head.subarray(MAGIC.length));
    decipher.setAAD(MAGIC);
    decipher.setAuthTag(tag);

    output = fs.openSync(outPath, "w", 0o600);

    let position = head.length;
    const end = size - TAG_LENGTH;
    const buffer = Buffer.alloc(CHUNK);

    while (position < end) {
      const want = Math.min(CHUNK, end - position);
      const read = fs.readSync(input, buffer, 0, want, position);
      if (read <= 0) throw new Error("Unexpected end of backup file.");

      fs.writeSync(output, decipher.update(buffer.subarray(0, read)));
      position += read;
    }

    fs.writeSync(output, decipher.final()); // verifies the authentication tag
    fs.fsyncSync(output);
  } catch (error) {
    if (output !== null) {
      fs.closeSync(output);
      output = null;
      secureDelete(outPath);
    }

    if (/unable to authenticate|auth/i.test(error.message)) {
      throw new Error("The backup failed authentication: it is damaged, was altered, or was made with a different master key.");
    }
    throw error;
  } finally {
    fs.closeSync(input);
    if (output !== null) fs.closeSync(output);
  }
}

function sha256File(file) {
  const hash = crypto.createHash("sha256");
  const handle = fs.openSync(file, "r");
  const buffer = Buffer.alloc(CHUNK);

  try {
    let read;
    while ((read = fs.readSync(handle, buffer, 0, CHUNK, null)) > 0) hash.update(buffer.subarray(0, read));
  } finally {
    fs.closeSync(handle);
  }

  return hash.digest("hex");
}

/* Overwrite with zeros, then delete. (On SSDs and journaling file systems
   this is best-effort; the backups themselves are encrypted regardless.) */
function secureDelete(file) {
  try {
    if (!fs.existsSync(file)) return;
    const size = fs.statSync(file).size;
    const handle = fs.openSync(file, "r+");
    const zeros = Buffer.alloc(Math.min(CHUNK, Math.max(size, 1)));

    for (let written = 0; written < size; written += zeros.length) {
      fs.writeSync(handle, zeros, 0, Math.min(zeros.length, size - written), written);
    }

    fs.fsyncSync(handle);
    fs.closeSync(handle);
    fs.unlinkSync(file);
  } catch (error) {
    try {
      fs.unlinkSync(file);
    } catch (ignore) {
      /* nothing more to do */
    }
  }
}

function removeDirectory(dir) {
  try {
    fs.readdirSync(dir).forEach((name) => secureDelete(path.join(dir, name)));
    fs.rmSync(dir, { recursive: true, force: true });
  } catch (error) {
    /* best effort */
  }
}

/* ---------- manifest ---------- */

function signManifest(manifest) {
  const { mac, ...rest } = manifest;
  return { ...rest, mac: keys.hmacHex("backup-mac", canonical(rest)) };
}

function manifestIsAuthentic(manifest) {
  const { mac, ...rest } = manifest;
  return Boolean(mac) && keys.safeEqual(mac, keys.hmacHex("backup-mac", canonical(rest)));
}

function manifestPathFor(backupPath) {
  return backupPath.replace(/\.bvbak$/, ".manifest.json");
}

/* ---------- inspecting a snapshot ---------- */

/* What a snapshot contains, read straight from the file. */
function snapshotStats(dbPath) {
  const snapshot = new DatabaseSync(dbPath, { readOnly: true });

  try {
    const count = (table) => snapshot.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get().n;
    const head = snapshot.prepare("SELECT id, hash FROM audit_log ORDER BY id DESC LIMIT 1").get();
    const election = snapshot.prepare("SELECT mode, status FROM election WHERE id = 1").get();

    return {
      ballots: count("ballots"),
      turnout: count("turnout"),
      receipts: count("receipts"),
      students: count("students"),
      admins: count("admins"),
      auditEntries: count("audit_log"),
      auditHeadId: head ? head.id : 0,
      auditHeadHash: head ? head.hash : chain.GENESIS_HASH,
      mode: election ? election.mode : null,
      status: election ? election.status : null
    };
  } finally {
    snapshot.close();
  }
}

/* Every check we run on a restored copy. Each is { name, ok, detail }. */
function inspectSnapshot(dbPath, expected = null) {
  const checks = [];
  const add = (name, ok, detail = "") => checks.push({ name, ok: Boolean(ok), detail });
  let snapshot;

  try {
    snapshot = new DatabaseSync(dbPath, { readOnly: true });
    add("Restored database opens", true);
  } catch (error) {
    add("Restored database opens", false, error.message);
    return checks;
  }

  try {
    const integrity = snapshot.prepare("PRAGMA integrity_check").all().map((row) => row.integrity_check);
    add("SQLite integrity check", integrity.length === 1 && integrity[0] === "ok", integrity.slice(0, 3).join("; "));

    const foreign = snapshot.prepare("PRAGMA foreign_key_check").all();
    add("Foreign keys consistent", foreign.length === 0, foreign.length ? `${foreign.length} violation(s)` : "");

    const fingerprint = snapshot.prepare("SELECT value FROM meta WHERE key = 'key_fingerprint'").get();
    add("Master key matches this backup", fingerprint && fingerprint.value === keys.fingerprint());

    const iterator = snapshot
      .prepare("SELECT id, occurredAt, actor, category, message, prevHash, hash FROM audit_log ORDER BY id")
      .iterate();
    const audit = chain.verifyRows(iterator);
    add("Audit hash-chain intact", audit.ok, audit.ok ? `${audit.count} entries` : `broken at entry ${audit.brokenAtId}: ${audit.reason}`);

    const stats = snapshotStats(dbPath);
    add(
      "Ballots, turnout and receipts agree",
      stats.ballots === stats.turnout && stats.ballots === stats.receipts,
      `${stats.ballots} ballots / ${stats.turnout} turnout / ${stats.receipts} receipts`
    );

    const triggers = snapshot
      .prepare("SELECT name FROM sqlite_master WHERE type = 'trigger'")
      .all()
      .map((row) => row.name);
    add(
      "Immutability triggers present",
      ["trg_audit_no_update", "trg_audit_no_delete", "trg_ballots_no_update", "trg_turnout_no_update"].every((name) => triggers.includes(name))
    );

    const sealed = snapshot.prepare("SELECT totpSecretEnc FROM admins WHERE totpSecretEnc IS NOT NULL LIMIT 1").get();
    let decrypts = true;
    if (sealed) {
      try {
        keys.decryptString(sealed.totpSecretEnc, "totp-enc");
      } catch (error) {
        decrypts = false;
      }
    }
    add("Encrypted 2FA secrets can be read", decrypts, sealed ? "" : "no 2FA secrets yet");

    if (expected) {
      add(
        "Contents match the manifest",
        stats.ballots === expected.ballots && stats.turnout === expected.turnout &&
          stats.auditEntries === expected.auditEntries && stats.auditHeadHash === expected.auditHeadHash,
        `manifest: ${expected.ballots} ballots, ${expected.auditEntries} audit entries`
      );
    }
  } catch (error) {
    add("Inspection completed", false, error.message);
  } finally {
    snapshot.close();
  }

  return checks;
}

/*
  Full test restore of one backup file into a scratch directory.
  Returns { ok, checks, stats, restoredPath }. The caller removes workDir
  (use removeDirectory) unless it wants to keep the restored database.
*/
function verifyBackupFile(backupPath, workDir) {
  const checks = [];
  const add = (name, ok, detail = "") => checks.push({ name, ok: Boolean(ok), detail });

  fs.mkdirSync(workDir, { recursive: true, mode: 0o700 });
  const restoredPath = path.join(workDir, "restored.db");

  let manifest = null;
  const manifestPath = manifestPathFor(backupPath);

  try {
    manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    add("Manifest is present and untampered", manifestIsAuthentic(manifest));
  } catch (error) {
    add("Manifest is present and untampered", false, "manifest missing or unreadable");
  }

  if (manifest) {
    add("Ciphertext checksum matches the manifest", sha256File(backupPath) === manifest.ciphertextSha256);
    add("Backup was made with this master key", manifest.keyFingerprint === keys.fingerprint());
  }

  try {
    decryptFile(backupPath, restoredPath);
    add("Backup decrypts and authenticates", true);
  } catch (error) {
    add("Backup decrypts and authenticates", false, error.message);
    return { ok: false, checks, stats: null, restoredPath: null };
  }

  checks.push(...inspectSnapshot(restoredPath, manifest ? manifest.stats : null));

  let stats = null;
  try {
    stats = snapshotStats(restoredPath);
  } catch (error) {
    /* already reported by the checks above */
  }

  return { ok: checks.every((check) => check.ok), checks, stats, restoredPath };
}

/* ---------- restoring (offline: the server must be stopped) ---------- */

function restoreBackup(backupPath, { dataDir = config.DATA_DIR, dbPath = config.DB_PATH } = {}) {
  const work = path.join(dataDir, `restore-tmp-${Date.now()}`);
  const verdict = verifyBackupFile(backupPath, work);

  if (!verdict.ok) {
    removeDirectory(work);
    return { ok: false, checks: verdict.checks, error: "The backup failed verification, so nothing was changed." };
  }

  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const safety = path.join(dataDir, `pre-restore-${stamp}`);
  let keptSomething = false;

  // The current database is moved aside, never deleted. On a replacement
  // machine there is nothing to move, and no empty folder is left behind.
  ["", "-wal", "-shm"].forEach((suffix) => {
    if (!fs.existsSync(dbPath + suffix)) return;

    fs.mkdirSync(safety, { recursive: true, mode: 0o700 });
    fs.renameSync(dbPath + suffix, path.join(safety, path.basename(dbPath) + suffix));
    keptSomething = true;
  });

  fs.copyFileSync(verdict.restoredPath, dbPath);
  fs.chmodSync(dbPath, 0o600);
  removeDirectory(work);

  fs.writeFileSync(
    config.RESTORE_MARKER,
    JSON.stringify({
      restoredAt: new Date().toISOString(),
      backup: path.basename(backupPath),
      backupCreatedAt: JSON.parse(fs.readFileSync(manifestPathFor(backupPath), "utf8")).createdAt,
      previousDatabaseKeptIn: keptSomething ? safety : null,
      stats: verdict.stats
    }, null, 2),
    { mode: 0o600 }
  );

  return { ok: true, checks: verdict.checks, stats: verdict.stats, safetyCopy: keptSomething ? safety : null };
}

module.exports = {
  MAGIC,
  canonical,
  encryptFile,
  decryptFile,
  sha256File,
  secureDelete,
  removeDirectory,
  signManifest,
  manifestIsAuthentic,
  manifestPathFor,
  snapshotStats,
  inspectSnapshot,
  verifyBackupFile,
  restoreBackup
};
