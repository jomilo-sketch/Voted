/*
  BOUESTI Vote — rate limiting.

  Counters live in the database (rate_limits table), not in memory, so
  restarting the server does not hand an attacker a fresh allowance and a
  second server process would share the same counts.

  Fixed window: `limit` attempts per `windowSec`. The attempt that goes
  over the limit blocks that key for `blockSec`. Rules are defined in
  config.js (RATE).
*/

"use strict";

const d = require("./db");
const config = require("./config");
const audit = require("./audit");

/* Express gives IPv4 clients as "::ffff:10.0.0.5" on dual-stack sockets. */
function clientIp(req) {
  let ip = (req.ip || (req.socket && req.socket.remoteAddress) || "unknown").toString();
  if (ip.startsWith("::ffff:")) ip = ip.slice(7);
  return ip;
}

function ruleFor(name) {
  const rule = config.RATE[name];
  if (!rule) throw new Error(`Unknown rate-limit rule: ${name}`);
  return rule;
}

/* Is this key currently blocked? Does not count an attempt. */
function peek(name, id) {
  ruleFor(name);
  const row = d.get("SELECT blockedUntil FROM rate_limits WHERE bucket = ?", `${name}:${id}`);
  const now = Date.now();

  if (row && row.blockedUntil > now) {
    return { allowed: false, retryAfterSec: Math.ceil((row.blockedUntil - now) / 1000) };
  }

  return { allowed: true };
}

/* Count one attempt. Returns { allowed, retryAfterSec?, justBlocked? }. */
function take(name, id, { auditLabel } = {}) {
  const rule = ruleFor(name);
  const bucket = `${name}:${id}`;
  const now = Date.now();

  const outcome = d.tx(() => {
    const row = d.get("SELECT * FROM rate_limits WHERE bucket = ?", bucket);

    if (row && row.blockedUntil > now) {
      return { allowed: false, retryAfterSec: Math.ceil((row.blockedUntil - now) / 1000) };
    }

    let windowStart = row ? row.windowStart : now;
    let count = row ? row.count : 0;

    if (now - windowStart >= rule.windowSec * 1000) {
      windowStart = now;
      count = 0;
    }

    count += 1;
    const exceeded = count > rule.limit;
    const blockedUntil = exceeded ? now + rule.blockSec * 1000 : 0;

    d.run(
      `INSERT INTO rate_limits (bucket, windowStart, count, blockedUntil) VALUES (?, ?, ?, ?)
       ON CONFLICT(bucket) DO UPDATE SET
         windowStart = excluded.windowStart,
         count = excluded.count,
         blockedUntil = excluded.blockedUntil`,
      bucket, windowStart, exceeded ? 0 : count, blockedUntil
    );

    if (exceeded) {
      return { allowed: false, retryAfterSec: rule.blockSec, justBlocked: true };
    }

    return { allowed: true, remaining: rule.limit - count };
  });

  if (outcome.justBlocked) {
    audit.append("system", "security", `Rate limit "${name}" tripped for ${auditLabel || id}; blocked ${rule.blockSec}s`);
  }

  return outcome;
}

function reset(name, id) {
  d.run("DELETE FROM rate_limits WHERE bucket = ?", `${name}:${id}`);
}

function waitText(seconds) {
  if (seconds < 90) return `${seconds} seconds`;
  return `${Math.ceil(seconds / 60)} minutes`;
}

/* Express middleware: limit by client IP address. */
function byIp(name) {
  return (req, res, next) => {
    const result = take(name, clientIp(req));

    if (!result.allowed) {
      res.set("Retry-After", String(result.retryAfterSec));
      return res.status(429).json({
        error: `Too many attempts. Please wait ${waitText(result.retryAfterSec)} and try again.`,
        retryAfterSec: result.retryAfterSec
      });
    }

    next();
  };
}

/* Remove counters whose window and block have both passed. */
function sweep() {
  const now = Date.now();
  const longestWindow = Math.max(...Object.values(config.RATE).map((rule) => rule.windowSec)) * 1000;

  return d.run(
    "DELETE FROM rate_limits WHERE blockedUntil < ? AND windowStart < ?",
    now, now - longestWindow
  ).changes;
}

/* How many keys are blocked right now (shown on the Operations page). */
function currentlyBlocked() {
  return d.get("SELECT COUNT(*) AS n FROM rate_limits WHERE blockedUntil > ?", Date.now()).n;
}

module.exports = { clientIp, peek, take, reset, byIp, sweep, currentlyBlocked, waitText };
