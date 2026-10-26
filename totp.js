/*
  BOUESTI Vote — time-based one-time passwords (RFC 6238) and Base32
  (RFC 4648), implemented with Node's crypto module only, so there is no
  third-party code in the login path. Compatible with Google
  Authenticator, Microsoft Authenticator, Authy, 1Password, Aegis, etc.
*/

"use strict";

const crypto = require("crypto");

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const STEP_SECONDS = 30;
const DIGITS = 6;

function base32Encode(buffer) {
  let bits = 0;
  let value = 0;
  let output = "";

  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;

    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }

  return output;
}

function base32Decode(text) {
  const clean = String(text).replace(/[\s=-]/g, "").toUpperCase();
  let bits = 0;
  let value = 0;
  const bytes = [];

  for (const char of clean) {
    const index = BASE32_ALPHABET.indexOf(char);
    if (index === -1) throw new Error("Invalid Base32 character.");

    value = (value << 5) | index;
    bits += 5;

    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }

  return Buffer.from(bytes);
}

function generateSecret() {
  // 160 bits, the size RFC 4226 recommends.
  return base32Encode(crypto.randomBytes(20));
}

function counterBuffer(counter) {
  const buffer = Buffer.alloc(8);
  buffer.writeBigUInt64BE(BigInt(counter));
  return buffer;
}

function hotp(secretBuffer, counter, digits = DIGITS) {
  const hmac = crypto.createHmac("sha1", secretBuffer).update(counterBuffer(counter)).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  return String(binary % 10 ** digits).padStart(digits, "0");
}

function stepFor(timeMs) {
  return Math.floor(timeMs / 1000 / STEP_SECONDS);
}

function generate(secretBase32, timeMs = Date.now(), digits = DIGITS) {
  return hotp(base32Decode(secretBase32), stepFor(timeMs), digits);
}

/*
  Accepts the current 30-second step and one step either side (clock
  drift). Returns the matching step number, or null. The caller stores
  the returned step and rejects anything <= it afterwards, so a code
  that was shoulder-surfed or replayed cannot be used twice.
*/
function verify(secretBase32, token, timeMs = Date.now(), window = 1) {
  const clean = String(token || "").replace(/\s/g, "");
  if (!/^\d{6}$/.test(clean)) return null;

  const secret = base32Decode(secretBase32);
  const current = stepFor(timeMs);
  let match = null;

  // Check every step (no early exit) so timing does not reveal which matched.
  for (let offset = -window; offset <= window; offset += 1) {
    const step = current + offset;
    const candidate = Buffer.from(hotp(secret, step));
    const supplied = Buffer.from(clean);

    if (crypto.timingSafeEqual(candidate, supplied) && match === null) {
      match = step;
    }
  }

  return match;
}

function otpauthUri({ secret, account, issuer }) {
  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(account)}`;
  const params = new URLSearchParams({
    secret,
    issuer,
    algorithm: "SHA1",
    digits: String(DIGITS),
    period: String(STEP_SECONDS)
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}

function formatSecret(secret) {
  return secret.replace(/(.{4})/g, "$1 ").trim();
}

module.exports = {
  STEP_SECONDS,
  base32Encode,
  base32Decode,
  generateSecret,
  hotp,
  generate,
  verify,
  stepFor,
  otpauthUri,
  formatSecret
};
