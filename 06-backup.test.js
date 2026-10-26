"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const { freshEnv } = require("./helpers");

const mirror = fs.mkdtempSync(path.join(os.tmpdir(), "bouesti-mirror-"));
const dir = freshEnv({ BACKUP_RETENTION: 2, BACKUP_MIRROR_DIR: mirror });
process.on("exit", () => fs.rmSync(mirror, { recursive: true, force: true }));

const test = require("node:test");
const assert = require("node:assert");
const { execFileSync } = require("child_process");
const { DatabaseSync } = require("node:sqlite");

const d = require("../db");
const config = require("../config");
const keys = require("../keys");
const totp = require("../totp");
const election = require("../election");
const voters = require("../voters");
const admins = require("../admins");
const audit = require("../audit");
const backup = require("../backup");
const core = require("../backup-core");

election.seedIfEmpty();

const IP = "10.3.3.3";
let firstBackup;

async function vote(matric) {
  let { session } = voters.login({ matric, password: "password1", ip: IP });
  session = voters.acceptRules(session).session;
  const sent = await voters.requestOtp(session, `s${matric}@bouesti.edu.ng`, IP);
  const verified = voters.verifyOtp(sent.session, config.DEMO_OTP, IP);
  const choices = {};
  election.getBallotStructure().forEach((office) => { choices[office.id] = office.candidates[0].id; });
  assert.ok(voters.castVote(verified.session, choices, IP).ok);
}

test("setup: an enrolled administrator and some ballots", async () => {
  const seeded = await admins.seedInitialAdmins();
  const account = seeded[0];
  const row = admins.getByEmail(account.email);
  await admins.changeOwnPassword(row, account.temporaryPassword, "tulip-Harbor-47-Quartz-9");

  const setup = admins.beginTotpSetup(row);
  assert.ok(admins.confirmTotpSetup(row, setup.secret, totp.generate(setup.secret)).ok);

  await vote("2001");
  await vote("2002");
  await vote("2003");
});

test("a backup is encrypted, authenticated, and described by a signed manifest", () => {
  const result = backup.createBackup("manual", "admin:tech@bouesti.ng");
  assert.ok(result.ok, JSON.stringify(result));
  firstBackup = path.join(config.BACKUP_DIR, result.file);

  assert.strictEqual(fs.statSync(firstBackup).mode & 0o777, 0o600);

  const bytes = fs.readFileSync(firstBackup);
  assert.ok(bytes.subarray(0, 8).equals(core.MAGIC));
  assert.ok(!bytes.includes("SQLite format 3"), "the file is not a readable database");
  assert.ok(!bytes.includes("@bouesti.edu.ng"), "no e-mail address is visible in the file");
  assert.ok(!bytes.includes("password"), "no plaintext fragments");

  const manifest = JSON.parse(fs.readFileSync(core.manifestPathFor(firstBackup), "utf8"));
  assert.ok(core.manifestIsAuthentic(manifest));
  assert.strictEqual(manifest.stats.ballots, 3);
  assert.strictEqual(manifest.ciphertextSha256, core.sha256File(firstBackup));
  assert.strictEqual(manifest.keyFingerprint, keys.fingerprint());

  // an edited manifest is detected
  const edited = { ...manifest, stats: { ...manifest.stats, ballots: 99 } };
  assert.ok(!core.manifestIsAuthentic(edited));

  // no leftover plaintext snapshot
  assert.deepStrictEqual(fs.readdirSync(config.BACKUP_DIR).filter((n) => n.startsWith(".snapshot")), []);

  // a second location received a copy
  assert.ok(fs.existsSync(path.join(mirror, path.basename(firstBackup))));
  assert.ok(fs.existsSync(path.join(mirror, path.basename(core.manifestPathFor(firstBackup)))));
});

test("a restoration drill restores the backup and runs every check, then cleans up", () => {
  const drill = backup.runDrill("manual", "admin:tech@bouesti.ng");

  assert.ok(drill.ok, JSON.stringify(drill.checks.filter((c) => !c.ok)));
  assert.ok(drill.checks.length >= 10);
  ["SQLite integrity check", "Audit hash-chain intact", "Master key matches this backup", "Backup decrypts and authenticates"].forEach((name) => {
    assert.ok(drill.checks.find((c) => c.name === name && c.ok), name);
  });
  assert.ok(drill.checks.some((c) => /Recovery point/.test(c.name)));

  assert.deepStrictEqual(fs.readdirSync(config.DRILL_DIR), [], "the scratch restore is deleted");

  const recorded = backup.listDrills()[0];
  assert.strictEqual(recorded.status, "pass");
  assert.ok(recorded.durationMs >= 0);
  assert.ok(backup.status().lastPassingDrill);
});

test("damage, truncation, tampering and the wrong key are all caught", () => {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "bouesti-bad-"));
  const bad = path.join(work, "bad.bvbak");

  try {
    // flipped byte in the middle of the ciphertext
    const bytes = Buffer.from(fs.readFileSync(firstBackup));
    bytes[Math.floor(bytes.length / 2)] ^= 0xff;
    fs.writeFileSync(bad, bytes);
    fs.copyFileSync(core.manifestPathFor(firstBackup), core.manifestPathFor(bad));

    const flipped = core.verifyBackupFile(bad, path.join(work, "a"));
    assert.strictEqual(flipped.ok, false);
    assert.ok(flipped.checks.some((c) => /checksum/.test(c.name) && !c.ok));
    assert.ok(flipped.checks.some((c) => /authenticates/.test(c.name) && !c.ok));
    assert.ok(!fs.existsSync(path.join(work, "a", "restored.db")), "a bad backup leaves no half-restored database");

    // truncated
    fs.writeFileSync(bad, fs.readFileSync(firstBackup).subarray(0, 500));
    assert.strictEqual(core.verifyBackupFile(bad, path.join(work, "b")).ok, false);

    // manifest edited
    fs.copyFileSync(firstBackup, bad);
    const manifest = JSON.parse(fs.readFileSync(core.manifestPathFor(firstBackup), "utf8"));
    manifest.stats.ballots = 99;
    fs.writeFileSync(core.manifestPathFor(bad), JSON.stringify(manifest));
    const forged = core.verifyBackupFile(bad, path.join(work, "c"));
    assert.strictEqual(forged.ok, false);
    assert.ok(forged.checks.some((c) => /untampered/.test(c.name) && !c.ok));

    // a different master key cannot open it (separate process, own key)
    const script = `
      const core = require(${JSON.stringify(path.join(__dirname, "..", "backup-core.js"))});
      const result = core.verifyBackupFile(${JSON.stringify(firstBackup)}, ${JSON.stringify(path.join(work, "d"))});
      console.log(JSON.stringify({ ok: result.ok, failing: result.checks.filter(c => !c.ok).map(c => c.name) }));
    `;
    const out = execFileSync(process.execPath, ["--disable-warning=ExperimentalWarning", "-e", script], {
      env: { ...process.env, BOUESTI_MASTER_KEY: "11".repeat(32), DATA_DIR: path.join(work, "other-data") }
    }).toString();
    const verdict = JSON.parse(out.trim().split("\n").pop());
    assert.strictEqual(verdict.ok, false);
    assert.ok(verdict.failing.some((n) => /master key/i.test(n) || /authenticates/.test(n)));
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }
});

test("a failing drill is recorded loudly", () => {
  const stolen = path.join(config.BACKUP_DIR, "bouesti-corrupt-test.bvbak");
  fs.writeFileSync(stolen, Buffer.concat([core.MAGIC, Buffer.alloc(200, 7)]));
  fs.writeFileSync(core.manifestPathFor(stolen), "{}");

  const drill = backup.runDrill("manual", "admin:tech@bouesti.ng", path.basename(stolen));
  assert.strictEqual(drill.ok, false);
  assert.strictEqual(backup.listDrills()[0].status, "fail");

  const security = audit.list({ category: "security" }).map((r) => r.message).join("\n");
  assert.match(security, /Restoration drill FAILED/);
  fs.unlinkSync(stolen);
  fs.unlinkSync(core.manifestPathFor(stolen));
});

test("scheduled backups are pruned to the retention limit; milestone backups are kept", () => {
  for (let i = 0; i < 4; i += 1) assert.ok(backup.createBackup("schedule").ok);
  assert.ok(backup.createBackup("close").ok);

  const rows = backup.listBackups(100);
  const scheduled = rows.filter((r) => r.trigger === "schedule" && r.present);
  assert.strictEqual(scheduled.length, 2, "only the newest two scheduled backups remain");

  assert.ok(rows.filter((r) => r.trigger === "manual").every((r) => r.present), "manual backups are never pruned");
  assert.ok(rows.filter((r) => r.trigger === "close").every((r) => r.present), "the closing backup is never pruned");

  const onDisk = fs.readdirSync(config.BACKUP_DIR).filter((n) => n.endsWith(".bvbak"));
  assert.strictEqual(onDisk.length, 4);
});

test("an interrupted backup is marked failed at the next start", () => {
  d.run("INSERT INTO backup_runs (startedAt, trigger, status) VALUES (?, 'schedule', 'running')", d.nowIso());
  backup.markInterruptedRuns();
  assert.strictEqual(d.get("SELECT COUNT(*) AS n FROM backup_runs WHERE status = 'running'").n, 0);
});

test("offline restore: verifies first, keeps the old database, leaves a marker for the audit log", () => {
  const target = fs.mkdtempSync(path.join(os.tmpdir(), "bouesti-restore-"));
  const targetDb = path.join(target, "election.db");

  try {
    fs.writeFileSync(targetDb, "pretend this is the damaged database");

    const result = core.restoreBackup(firstBackup, { dataDir: target, dbPath: targetDb });
    assert.ok(result.ok, JSON.stringify(result));
    assert.ok(fs.existsSync(path.join(result.safetyCopy, "election.db")), "the previous database is kept, not destroyed");

    const restored = new DatabaseSync(targetDb, { readOnly: true });
    assert.strictEqual(restored.prepare("SELECT COUNT(*) AS n FROM ballots").get().n, 3);
    assert.strictEqual(restored.prepare("SELECT COUNT(*) AS n FROM turnout").get().n, 3);
    restored.close();

    assert.ok(fs.existsSync(config.RESTORE_MARKER));
    const marker = backup.applyRestoreMarker();
    assert.ok(marker && marker.backup === path.basename(firstBackup));
    assert.ok(!fs.existsSync(config.RESTORE_MARKER));
    assert.ok(audit.list({ category: "backup" }).some((r) => /DATABASE RESTORED/.test(r.message)));

    // restoring a damaged backup changes nothing
    const damaged = path.join(target, "damaged.bvbak");
    const bytes = Buffer.from(fs.readFileSync(firstBackup));
    bytes[100] ^= 1;
    fs.writeFileSync(damaged, bytes);
    fs.copyFileSync(core.manifestPathFor(firstBackup), core.manifestPathFor(damaged));

    const before = fs.readFileSync(targetDb);
    const refused = core.restoreBackup(damaged, { dataDir: target, dbPath: targetDb });
    assert.strictEqual(refused.ok, false);
    assert.ok(fs.readFileSync(targetDb).equals(before), "a failed restore leaves the database untouched");
  } finally {
    fs.rmSync(target, { recursive: true, force: true });
  }
});

test("the read-only audit copy has the evidence but none of the personal data", () => {
  const result = backup.createAuditCopy("manual", "admin:tech@bouesti.ng");
  assert.ok(result.ok, JSON.stringify(result));

  const copyPath = path.join(config.AUDIT_COPY_DIR, result.file);
  assert.strictEqual(fs.statSync(copyPath).mode & 0o777, 0o444, "file-system read-only");

  const bytes = fs.readFileSync(copyPath);
  assert.ok(!bytes.includes("@bouesti.edu.ng"), "no e-mail addresses anywhere in the file");
  assert.ok(!bytes.includes("scrypt$"), "no password hashes");

  const copy = new DatabaseSync(copyPath, { readOnly: true });
  const tables = copy.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all().map((r) => r.name);

  ["students", "turnout", "admins", "sessions", "rate_limits", "admin_recovery_codes", "password_resets", "admin_login_history", "student_reports"].forEach((name) => {
    assert.ok(!tables.includes(name), `${name} must not be in the audit copy`);
  });

  ["ballots", "ballot_selections", "receipts", "audit_log", "audit_checkpoints", "result_reports", "election", "copy_meta"].forEach((name) => {
    assert.ok(tables.includes(name), `${name} should be in the audit copy`);
  });

  assert.strictEqual(copy.prepare("SELECT COUNT(*) AS n FROM ballots").get().n, 3);
  assert.strictEqual(copy.prepare("SELECT value FROM copy_meta WHERE key = 'turnoutRecords'").get().value, "3");
  assert.strictEqual(copy.prepare("SELECT value FROM copy_meta WHERE key = 'signingPublicKey'").get().value, keys.signingPublicKey());
  assert.throws(() => copy.exec("INSERT INTO ballots (ballotId) VALUES ('x')"), /readonly|read-only/i);
  copy.close();

  const manifest = JSON.parse(fs.readFileSync(`${copyPath}.manifest.json`, "utf8"));
  assert.ok(core.manifestIsAuthentic(manifest));
  assert.strictEqual(manifest.sha256, core.sha256File(copyPath));

  assert.ok(backup.auditCopyPathFor(result.file));
  assert.strictEqual(backup.auditCopyPathFor("../../etc/passwd"), null);
  assert.strictEqual(backup.backupPathFor("../election.db"), null);
});

test("status summary for the Operations page", () => {
  const status = backup.status();
  assert.ok(status.lastBackup && status.lastPassingDrill && status.lastAuditCopy);
  assert.ok(status.backupFiles >= 4);
  assert.ok(status.disk === null || status.disk.freeBytes > 0);
  assert.strictEqual(status.mirrorConfigured, true);
  assert.ok(audit.verify().ok);
  assert.ok(dir);
});
