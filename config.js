/*
  BOUESTI Vote — configuration.

  Every tunable lives here, in one place. Defaults are chosen so that
  `npm start` on a laptop gives a working REHEARSAL system (demo OTP,
  open roster). Anything that must be different for the real election is
  an environment variable — see README.md, "Going live".

  Nothing in this file is secret. Secrets (the master key) live in
  data/keys/ or in the BOUESTI_MASTER_KEY environment variable — see
  keys.js.
*/

"use strict";

const path = require("path");

const ROOT = __dirname;
const NODE_ENV = process.env.NODE_ENV || "development";
const PRODUCTION = NODE_ENV === "production";

function envString(name, fallback) {
  const value = process.env[name];
  return value === undefined || value === "" ? fallback : value;
}

function envInt(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return fallback;

  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed)) {
    throw new Error(`${name} must be a whole number (got "${raw}").`);
  }
  return parsed;
}

function envBool(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return fallback;
  return ["1", "true", "yes", "on"].includes(String(raw).toLowerCase());
}

const DATA_DIR = path.resolve(envString("DATA_DIR", path.join(ROOT, "data")));
const TLS_KEY_FILE = envString("TLS_KEY_FILE", "");
const TLS_CERT_FILE = envString("TLS_CERT_FILE", "");
// Cookies are Secure in production, and whenever the server itself speaks HTTPS.
const COOKIE_SECURE = envBool("COOKIE_SECURE", PRODUCTION || Boolean(TLS_KEY_FILE && TLS_CERT_FILE));

const RATE_IP_SCALE = Math.max(1, envInt("RATE_IP_SCALE", 1));

/* Only the flood-guard rules that name a client address are scaled. */
function scaleIpRules(rules) {
  const scaled = {};

  Object.entries(rules).forEach(([name, rule]) => {
    const voterFacing = /Ip$/.test(name) && !name.startsWith("admin");
    scaled[name] = voterFacing ? { ...rule, limit: rule.limit * RATE_IP_SCALE } : rule;
  });

  return scaled;
}

const config = {
  ROOT,
  NODE_ENV,
  PRODUCTION,

  /* ---------- network ---------- */
  HOST: envString("HOST", "127.0.0.1"),
  PORT: envInt("PORT", 3000),
  // "" = not behind a proxy. Behind nginx on the same machine use "loopback"
  // (or a hop count such as "1") so rate limits see real student IPs.
  TRUST_PROXY: envString("TRUST_PROXY", ""),
  // The address students type, e.g. https://vote.bouesti.edu.ng — when set,
  // browser requests must come from exactly this origin (CSRF defence).
  PUBLIC_ORIGIN: envString("PUBLIC_ORIGIN", "").replace(/\/+$/, ""),
  // Optional: serve HTTPS directly (no reverse proxy needed). Both must be set.
  TLS_KEY_FILE,
  TLS_CERT_FILE,
  PUBLIC_DIR: path.join(ROOT, "public"),

  /* ---------- storage ---------- */
  DATA_DIR,
  DB_PATH: path.join(DATA_DIR, "election.db"),
  KEY_DIR: path.join(DATA_DIR, "keys"),
  BACKUP_DIR: path.resolve(envString("BACKUP_DIR", path.join(DATA_DIR, "backups"))),
  AUDIT_COPY_DIR: path.resolve(envString("AUDIT_COPY_DIR", path.join(DATA_DIR, "audit-copy"))),
  // Optional second location (USB drive, network share) every backup is also copied to.
  BACKUP_MIRROR_DIR: envString("BACKUP_MIRROR_DIR", ""),
  DRILL_DIR: path.join(DATA_DIR, "drill-tmp"),
  CREDENTIALS_FILE: path.join(DATA_DIR, "INITIAL-ADMIN-CREDENTIALS.txt"),
  RESTORE_MARKER: path.join(DATA_DIR, "restore-marker.json"),
  // Written while the server runs, so offline tools (npm run restore) can refuse to touch a live database.
  PID_FILE: path.join(DATA_DIR, "server.pid"),

  /* ---------- cookies ---------- */
  COOKIE_SECURE,
  // The __Host- prefix makes browsers refuse the cookie unless it is Secure,
  // Path=/ and has no Domain — it cannot be planted from a sibling subdomain.
  COOKIE_PREFIX: COOKIE_SECURE ? "__Host-" : "",
  VOTER_COOKIE: (COOKIE_SECURE ? "__Host-" : "") + "bv_voter",
  ADMIN_COOKIE: (COOKIE_SECURE ? "__Host-" : "") + "bv_admin",

  /* ---------- voter policy ---------- */
  // Digits only. "matric 152637", "BOU/15/2637" etc. are rejected.
  MATRIC_PATTERN: /^\d{4,15}$/,
  // The single, shared student password. Exactly this value is accepted.
  VOTER_PASSWORD: envString("VOTER_PASSWORD", "password1"),
  UNIVERSITY_EMAIL_DOMAIN: "bouesti.edu.ng",

  // demo    = accept the fixed code below (rehearsal only; refused in production)
  // console = real random codes, printed to the server console (lab testing)
  // smtp    = real random codes, emailed through the SMTP server below
  OTP_MODE: envString("OTP_MODE", PRODUCTION ? "smtp" : "demo"),
  DEMO_OTP: "123456",
  OTP_TTL_SEC: 300,
  OTP_MAX_ATTEMPTS: 5,
  OTP_RESEND_COOLDOWN_SEC: 30,
  OTP_MAX_SENDS_PER_SESSION: 5,

  /* ---------- sessions (stored in the database, not in memory) ---------- */
  VOTER_IDLE_SEC: envInt("VOTER_IDLE_MIN", 15) * 60,
  VOTER_ABSOLUTE_SEC: envInt("VOTER_ABSOLUTE_MIN", 40) * 60,
  ADMIN_IDLE_SEC: envInt("ADMIN_IDLE_MIN", 15) * 60,
  ADMIN_ABSOLUTE_SEC: envInt("ADMIN_ABSOLUTE_MIN", 240) * 60,
  // Time allowed between a correct password and the 2FA / setup step.
  ADMIN_PENDING_SEC: 5 * 60,
  // Sensitive actions need a 2FA code entered within this window.
  STEP_UP_SEC: 5 * 60,

  /* ---------- admin accounts ---------- */
  ADMIN_MAX_FAILED: envInt("ADMIN_MAX_FAILED", 5),
  ADMIN_LOCK_SEC: envInt("ADMIN_LOCK_MIN", 15) * 60,
  RESET_CODE_TTL_SEC: 30 * 60,
  MIN_PASSWORD_LENGTH: 12,

  /* scrypt (memory-hard). Defaults follow OWASP: N=2^17, r=8, p=1. */
  SCRYPT_N: envInt("SCRYPT_N", 131072),
  SCRYPT_R: 8,
  SCRYPT_P: 1,

  /* ---------- rate limits (fixed window; blocked for blockSec once exceeded) ----------
     Per-PERSON limits (…Matric, …Email) stop guessing. Per-ADDRESS limits (…Ip)
     are only a flood guard, and are generous on purpose: on many campuses
     hundreds of students share ONE public address. Multiply them all with
     RATE_IP_SCALE (e.g. RATE_IP_SCALE=3) if students are being blocked
     together; the Operations page shows how often limits trip. */
  RATE: scaleIpRules({
    globalIp: { limit: 3000, windowSec: 60, blockSec: 60 },

    voterLoginIp: { limit: 800, windowSec: 600, blockSec: 300 },
    voterLoginMatric: { limit: 12, windowSec: 900, blockSec: 600 },

    otpRequestIp: { limit: 500, windowSec: 600, blockSec: 300 },
    otpRequestMatric: { limit: 10, windowSec: 3600, blockSec: 1800 },
    otpVerifyIp: { limit: 800, windowSec: 600, blockSec: 300 },
    otpVerifyMatric: { limit: 15, windowSec: 3600, blockSec: 3600 },

    ballotIp: { limit: 1500, windowSec: 600, blockSec: 300 },
    ballotMatric: { limit: 30, windowSec: 600, blockSec: 300 },

    receiptIp: { limit: 60, windowSec: 600, blockSec: 600 },
    problemIp: { limit: 20, windowSec: 3600, blockSec: 3600 },

    adminLoginIp: { limit: 25, windowSec: 900, blockSec: 900 },
    adminLoginEmail: { limit: 10, windowSec: 900, blockSec: 900 },
    adminTotpIp: { limit: 25, windowSec: 900, blockSec: 900 },
    adminResetIp: { limit: 10, windowSec: 900, blockSec: 900 },
    adminStepUp: { limit: 10, windowSec: 900, blockSec: 900 },
    adminWitness: { limit: 6, windowSec: 900, blockSec: 900 },
    adminTestMail: { limit: 5, windowSec: 600, blockSec: 600 },
    adminHeavy: { limit: 20, windowSec: 600, blockSec: 300 }
  }),

  /* ---------- operations ---------- */
  ENABLE_SCHEDULERS: envBool("ENABLE_SCHEDULERS", true),
  BACKUP_INTERVAL_MIN: envInt("BACKUP_INTERVAL_MIN", 30),
  BACKUP_RETENTION: envInt("BACKUP_RETENTION", 48),
  DRILL_INTERVAL_MIN: envInt("DRILL_INTERVAL_MIN", 360),
  AUDIT_COPY_INTERVAL_MIN: envInt("AUDIT_COPY_INTERVAL_MIN", 60),
  AUDIT_COPY_RETENTION: envInt("AUDIT_COPY_RETENTION", 6),
  SCHEDULE_TICK_SEC: 15,

  /* ---------- mail (OTP_MODE=smtp) ---------- */
  SMTP_HOST: envString("SMTP_HOST", ""),
  SMTP_PORT: envInt("SMTP_PORT", 587),
  SMTP_SECURE: envBool("SMTP_SECURE", false), // true = implicit TLS (port 465)
  // true = the connection MUST be upgraded with STARTTLS (a server that does not offer it is refused,
  // so nobody on the network can strip the encryption). Set false only for a trusted internal relay.
  SMTP_STARTTLS: envBool("SMTP_STARTTLS", true),
  SMTP_USER: envString("SMTP_USER", ""),
  SMTP_PASS: envString("SMTP_PASS", ""),
  SMTP_FROM: envString("SMTP_FROM", "BOUESTI Vote <no-reply@bouesti.edu.ng>"),
  // A PEM file with an extra certificate authority to trust, for a relay whose certificate was issued by the
  // institution's own authority. The certificate is still verified; this only adds one trusted issuer.
  SMTP_CA_FILE: envString("SMTP_CA_FILE", ""),
  SMTP_TIMEOUT_MS: envInt("SMTP_TIMEOUT_MS", 15_000),

  /* ---------- request size limits ---------- */
  PUBLIC_BODY_LIMIT: "16kb",
  ADMIN_BODY_LIMIT: "3mb"
};

/*
  Called once at start-up. Returns { errors, warnings }. Errors stop the
  server from starting; warnings are printed.
*/
config.validate = function validate() {
  const errors = [];
  const warnings = [];

  if (!["demo", "console", "smtp"].includes(config.OTP_MODE)) {
    errors.push(`OTP_MODE must be demo, console or smtp (got "${config.OTP_MODE}").`);
  }

  if (config.PRODUCTION && config.OTP_MODE === "demo") {
    errors.push(
      "OTP_MODE=demo accepts the fixed code 123456 and must never run in production. " +
        "Use OTP_MODE=smtp (or console for a lab test)."
    );
  }

  if (config.PUBLIC_ORIGIN && !/^https?:\/\/[^\s/]+$/.test(config.PUBLIC_ORIGIN)) {
    errors.push("PUBLIC_ORIGIN must look like https://vote.bouesti.edu.ng (no path).");
  }

  if (config.PRODUCTION && !config.PUBLIC_ORIGIN) {
    warnings.push("PUBLIC_ORIGIN is not set; requests are checked against the Host header instead. Set it to the address students use.");
  }

  if (Boolean(config.TLS_KEY_FILE) !== Boolean(config.TLS_CERT_FILE)) {
    errors.push("Set both TLS_KEY_FILE and TLS_CERT_FILE to serve HTTPS directly, or neither.");
  }

  if (config.OTP_MODE === "smtp" && !config.SMTP_HOST) {
    errors.push("OTP_MODE=smtp needs SMTP_HOST (and usually SMTP_USER / SMTP_PASS).");
  }

  if (config.PRODUCTION && !config.COOKIE_SECURE) {
    errors.push("Production requires Secure cookies. Serve over HTTPS and leave COOKIE_SECURE unset.");
  }

  if (!config.COOKIE_SECURE) {
    warnings.push("Cookies are not marked Secure (fine for http://localhost; never for a real election).");
  }

  if (config.OTP_MODE === "demo") {
    warnings.push("OTP_MODE=demo — anyone can use code 123456. Rehearsal only.");
  }

  if (config.VOTER_PASSWORD === "password1") {
    warnings.push(
      "The shared student password is the default (password1). It is known to everyone, " +
        "so the OTP sent to the student's university mailbox is the real proof of identity."
    );
  }

  if (config.SCRYPT_N < 16384) {
    warnings.push("SCRYPT_N is very low — only acceptable for automated tests.");
  }

  return { errors, warnings };
};

module.exports = config;
