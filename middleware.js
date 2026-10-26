/*
  BOUESTI Vote — the web layer's shared guards.

    securityHeaders   CSP (scripts only from this site), no framing, no
                      sniffing, HSTS over HTTPS
    apiNoStore        API answers are never cached by browsers or proxies
    csrfGuard         state-changing requests must carry our custom header
                      and come from our own origin (cookies are SameSite=Strict
                      as well — three independent defences)
    floodGuard        generous in-memory per-address ceiling for the whole API
    jsonBodies        size-limited JSON parsing (small for the public, larger
                      for administrators who upload a roster or a photo)
    voterSession /    read the session cookie and look the session up in the
    adminSession      DATABASE (sessions.js); nothing is kept in memory
    requireVoter /    refuse the request unless the right kind of session,
    requireAdmin      in the right stage, with the right permission (and, for
                      sensitive actions, a fresh two-factor confirmation)
*/

"use strict";

const express = require("express");
const config = require("./config");
const sessions = require("./sessions");
const ratelimit = require("./ratelimit");
const admins = require("./admins");
const audit = require("./audit");
const { can } = require("./permissions");

const CSRF_HEADER = "bouesti-vote";

/* ---------- headers ---------- */

function contentSecurityPolicy() {
  const directives = [
    "default-src 'self'",
    "script-src 'self'",
    // Inline style attributes are used for a few progress bars; scripts stay strict.
    "style-src 'self' 'unsafe-inline'",
    // Candidate photos may be https links or small embedded images.
    "img-src 'self' data: http: https:",
    "font-src 'self'",
    "connect-src 'self'",
    "media-src 'none'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "base-uri 'none'",
    "form-action 'self'"
  ];

  if (config.COOKIE_SECURE) directives.push("upgrade-insecure-requests");
  return directives.join("; ");
}

const CSP = contentSecurityPolicy();

function securityHeaders(req, res, next) {
  res.setHeader("Content-Security-Policy", CSP);
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  res.removeHeader("X-Powered-By");

  if (config.COOKIE_SECURE) {
    res.setHeader("Strict-Transport-Security", "max-age=31536000");
  }

  next();
}

function apiNoStore(req, res, next) {
  res.setHeader("Cache-Control", "no-store, max-age=0");
  res.setHeader("Pragma", "no-cache");
  next();
}

/* ---------- CSRF ---------- */

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

function csrfGuard(req, res, next) {
  if (SAFE_METHODS.has(req.method)) return next();

  const refuse = () =>
    res.status(403).json({
      error: "This request was blocked for your protection. Reload the page and try again.",
      code: "csrf"
    });

  if (req.get("x-requested-with") !== CSRF_HEADER) return refuse();

  const origin = req.get("origin");

  if (origin) {
    if (config.PUBLIC_ORIGIN) {
      if (origin !== config.PUBLIC_ORIGIN) return refuse();
    } else {
      let host;

      try {
        host = new URL(origin).host;
      } catch (error) {
        return refuse();
      }

      if (host !== req.get("host")) return refuse();
    }
  }

  const site = req.get("sec-fetch-site");
  if (site && site !== "same-origin" && site !== "none") return refuse();

  next();
}

/* ---------- flood guard (memory only: a safety net, not a security control) ---------- */

const floods = new Map();

function floodGuard(req, res, next) {
  const rule = config.RATE.globalIp;
  const ip = ratelimit.clientIp(req);
  const now = Date.now();

  let entry = floods.get(ip);

  if (!entry || now - entry.windowStart >= rule.windowSec * 1000) {
    entry = { windowStart: now, count: 0, blockedUntil: entry ? entry.blockedUntil : 0 };
    floods.set(ip, entry);
  }

  if (entry.blockedUntil > now) {
    res.set("Retry-After", String(Math.ceil((entry.blockedUntil - now) / 1000)));
    return res.status(429).json({ error: "Too many requests. Please wait a minute and try again.", code: "rate-limited" });
  }

  entry.count += 1;

  if (entry.count > rule.limit) {
    entry.blockedUntil = now + rule.blockSec * 1000;
    res.set("Retry-After", String(rule.blockSec));
    return res.status(429).json({ error: "Too many requests. Please wait a minute and try again.", code: "rate-limited" });
  }

  next();
}

const floodSweeper = setInterval(() => {
  const cutoff = Date.now() - 10 * 60 * 1000;

  floods.forEach((entry, ip) => {
    if (entry.windowStart < cutoff && entry.blockedUntil < Date.now()) floods.delete(ip);
  });
}, 60 * 1000);

floodSweeper.unref();

/* ---------- bodies ---------- */

function jsonBodies() {
  const options = (limit) => ({ limit, strict: true, type: "application/json" });

  return {
    admin: express.json(options(config.ADMIN_BODY_LIMIT)),
    pub: express.json(options(config.PUBLIC_BODY_LIMIT))
  };
}

/* req.body is always an object, even when nothing (or something odd) was sent. */
function ensureBody(req, res, next) {
  if (!req.body || typeof req.body !== "object" || Array.isArray(req.body)) req.body = {};
  next();
}

function bodyErrors(error, req, res, next) {
  const known = {
    "entity.too.large": [413, "That request is too large."],
    "entity.parse.failed": [400, "The request could not be read."],
    "encoding.unsupported": [415, "The request encoding is not supported."],
    "charset.unsupported": [415, "The request character set is not supported."],
    "request.aborted": [400, "The request was interrupted."]
  };

  if (error && known[error.type]) {
    const [status, message] = known[error.type];
    return res.status(status).json({ error: message, code: "bad-request" });
  }

  next(error);
}

/* ---------- sessions ---------- */

function voterSession(req, res, next) {
  const token = sessions.parseCookies(req.headers.cookie)[config.VOTER_COOKIE] || null;

  req.voterToken = token;
  req.voterSession = token ? sessions.lookup(token, "voter") : null;
  next();
}

function requireVoter(req, res, next) {
  if (!req.voterSession) {
    if (req.voterToken) sessions.clearSessionCookie(res, config.VOTER_COOKIE);

    return res.status(401).json({
      error: "Your session has ended. Please sign in again.",
      code: "session-ended"
    });
  }

  req.voterSession = sessions.touch(req.voterSession);
  next();
}

function adminSession(req, res, next) {
  const token = sessions.parseCookies(req.headers.cookie)[config.ADMIN_COOKIE] || null;

  req.adminToken = token;
  req.adminSession = null;
  req.admin = null;

  if (token) {
    const session = sessions.lookup(token, "admin");

    if (session) {
      const row = admins.getById(Number(session.subject));

      if (row && !row.disabled) {
        req.adminSession = session;
        req.admin = row;
      } else {
        sessions.revoke(session.tokenHash, "account-unavailable");
      }
    }
  }

  next();
}

/* One "permission denied" line per administrator and route per minute. */
const denials = new Map();

function noteDenied(req, needed) {
  const label = `${req.method} ${req.baseUrl}${req.route ? req.route.path : ""}`;
  const key = `${req.admin.id}:${label}`;
  const now = Date.now();

  if (now - (denials.get(key) || 0) < 60_000) return;

  denials.set(key, now);
  if (denials.size > 2000) denials.clear();

  audit.append(audit.adminActor(req.admin), "security", `Permission denied: ${label} needs ${needed.join(" or ")}`);
}

/*
  requireAdmin({ permission, stage, stepUp, passive })
    permission  one permission, or an array meaning "any of these"
    stage       which sign-in stage may call this ("full" = completely signed in)
    stepUp      needs a two-factor code entered within STEP_UP_SEC
    passive     background polling: does not extend the idle timer
*/
function requireAdmin({ permission = null, stage = "full", stepUp = false, passive = false } = {}) {
  const needed = permission === null ? [] : [].concat(permission);

  return (req, res, next) => {
    if (!req.adminSession) {
      if (req.adminToken) sessions.clearSessionCookie(res, config.ADMIN_COOKIE);

      return res.status(401).json({ error: "Please sign in to continue.", code: "unauthenticated" });
    }

    if (req.adminSession.stage !== stage) {
      return res.status(403).json({
        error: "That step is not available in your current sign-in state.",
        code: "wrong-stage",
        stage: req.adminSession.stage
      });
    }

    if (needed.length && !needed.some((permissionName) => can(req.admin.role, permissionName))) {
      noteDenied(req, needed);
      return res.status(403).json({ error: "Your role is not allowed to do that.", code: "forbidden" });
    }

    if (stepUp) {
      const at = Number(req.adminSession.data.stepUpAt || 0);

      if (at + config.STEP_UP_SEC * 1000 <= Date.now()) {
        return res.status(403).json({
          error: "Please confirm with a fresh two-factor code to continue.",
          code: "step-up-required"
        });
      }
    }

    if (!passive) req.adminSession = sessions.touch(req.adminSession);
    next();
  };
}

/* For routes where only SOME requests are sensitive (for example, changing
   the election status but not its name): run after requireAdmin(). */
function requireStepUp(req, res, next) {
  const at = Number(req.adminSession.data.stepUpAt || 0);

  if (at + config.STEP_UP_SEC * 1000 <= Date.now()) {
    return res.status(403).json({
      error: "Please confirm with a fresh two-factor code to continue.",
      code: "step-up-required"
    });
  }

  next();
}

function stepUpSecondsLeft(session) {
  const at = Number(session.data.stepUpAt || 0);
  return Math.max(0, Math.floor((at + config.STEP_UP_SEC * 1000 - Date.now()) / 1000));
}

module.exports = {
  CSRF_HEADER,
  securityHeaders,
  apiNoStore,
  csrfGuard,
  floodGuard,
  jsonBodies,
  ensureBody,
  bodyErrors,
  voterSession,
  requireVoter,
  adminSession,
  requireAdmin,
  requireStepUp,
  stepUpSecondsLeft
};
