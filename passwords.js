/*
  BOUESTI Vote — administrator password hashing.

  Passwords are never stored. Each is run through scrypt, a memory-hard
  key-derivation function, with its own random 16-byte salt:

      scrypt$N$r$p$salt$hash

  The cost parameters are stored inside the string, so they can be raised
  later without invalidating existing accounts (needsRehash()).

  Why scrypt and not Argon2id or bcrypt? Argon2id is the first choice in
  the OWASP guidance, but Node's built-in crypto only gained argon2 in
  Node 24.7 and this project deliberately uses no native add-ons. scrypt
  is OWASP's documented alternative (N=2^17, r=8, p=1 — the defaults
  here) and ships with every Node version. On Node 24.7+ an Argon2id
  option can be added in this one file without touching the rest.
*/

"use strict";

const crypto = require("crypto");
const config = require("./config");

const KEY_LENGTH = 32;
const MEMORY_HEADROOM = 64 * 1024 * 1024;

const COMMON_PASSWORDS = [
  "password", "password1", "password123", "passw0rd", "qwerty", "qwertyuiop", "letmein",
  "welcome", "admin", "administrator", "iloveyou", "monkey", "dragon", "football",
  "123456", "12345678", "123456789", "1234567890", "000000", "111111", "abc123",
  "bouesti", "bouesti2026", "election", "electoral", "results", "technical", "changeme"
];

function scryptAsync(password, salt, keyLength, options) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, keyLength, options, (error, key) => {
      if (error) reject(error);
      else resolve(key);
    });
  });
}

function scryptOptions(N, r, p) {
  return { N, r, p, maxmem: 128 * N * r + MEMORY_HEADROOM };
}

function normalise(password) {
  return String(password).normalize("NFKC");
}

async function hashPassword(password) {
  const { SCRYPT_N: N, SCRYPT_R: r, SCRYPT_P: p } = config;
  const salt = crypto.randomBytes(16);
  const hash = await scryptAsync(normalise(password), salt, KEY_LENGTH, scryptOptions(N, r, p));

  return ["scrypt", N, r, p, salt.toString("base64url"), hash.toString("base64url")].join("$");
}

async function verifyPassword(password, stored) {
  const parts = String(stored || "").split("$");
  if (parts.length !== 6 || parts[0] !== "scrypt") return false;

  const N = Number(parts[1]);
  const r = Number(parts[2]);
  const p = Number(parts[3]);
  const salt = Buffer.from(parts[4], "base64url");
  const expected = Buffer.from(parts[5], "base64url");

  if (!N || !r || !p || expected.length === 0) return false;

  const actual = await scryptAsync(normalise(password), salt, expected.length, scryptOptions(N, r, p));
  return crypto.timingSafeEqual(actual, expected);
}

function needsRehash(stored) {
  const parts = String(stored || "").split("$");
  return parts.length !== 6 || Number(parts[1]) < config.SCRYPT_N;
}

/* A real hash of a random password, used to spend the same time when the
   e-mail address does not exist — so response time does not reveal which
   accounts are real. */
let dummyHashPromise = null;

function dummyHash() {
  if (!dummyHashPromise) {
    dummyHashPromise = hashPassword(crypto.randomBytes(18).toString("base64url"));
  }
  return dummyHashPromise;
}

/* Returns a list of plain-language problems (empty = acceptable). */
function passwordProblems(password, { email = "", displayName = "" } = {}) {
  const problems = [];
  const text = String(password || "");
  const lower = text.toLowerCase();

  if (text.length < config.MIN_PASSWORD_LENGTH) {
    problems.push(`Use at least ${config.MIN_PASSWORD_LENGTH} characters.`);
  }

  if (text.length > 128) problems.push("Use at most 128 characters.");

  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((pattern) => pattern.test(text)).length;
  if (classes < 3 && text.length < 20) {
    problems.push("Mix at least three of: lower-case, upper-case, digits, symbols — or use a passphrase of 20+ characters.");
  }

  if (new Set(text).size < 5) problems.push("That password repeats too few different characters.");

  if (COMMON_PASSWORDS.some((word) => lower.includes(word))) {
    problems.push("That password contains a very common word. Choose something less guessable.");
  }

  const localPart = String(email).split("@")[0].toLowerCase();
  if (localPart.length >= 4 && lower.includes(localPart)) {
    problems.push("The password must not contain your e-mail name.");
  }

  const firstName = String(displayName).split(/\s+/)[0].toLowerCase();
  if (firstName.length >= 4 && lower.includes(firstName)) {
    problems.push("The password must not contain your name.");
  }

  return problems;
}

/* Hand-over passwords: 16 characters, no look-alike letters (no O/0, l/1/I). */
const TEMP_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789";

function randomFromAlphabet(length, alphabet) {
  let output = "";
  for (let index = 0; index < length; index += 1) {
    output += alphabet[crypto.randomInt(alphabet.length)];
  }
  return output;
}

function generateTemporaryPassword() {
  return [0, 1, 2, 3].map(() => randomFromAlphabet(4, TEMP_ALPHABET)).join("-");
}

/* One-time codes (password-reset codes, 2FA recovery codes). */
function generateCode(groups = 2, size = 5) {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  return Array.from({ length: groups }, () => randomFromAlphabet(size, alphabet)).join("-");
}

module.exports = {
  hashPassword,
  verifyPassword,
  needsRehash,
  dummyHash,
  passwordProblems,
  generateTemporaryPassword,
  generateCode
};
