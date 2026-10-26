/*
  BOUESTI Vote — the Express application (no listening, no start-up work),
  so the same app can be run by server.js and driven directly by the tests.
*/

"use strict";

const crypto = require("crypto");
const express = require("express");
const config = require("./config");
const audit = require("./audit");
const {
  securityHeaders,
  apiNoStore,
  csrfGuard,
  floodGuard,
  jsonBodies,
  ensureBody,
  bodyErrors,
  adminSession
} = require("./middleware");

const publicRoutes = require("./routes-public");
const authRoutes = require("./routes-admin-auth");
const electionRoutes = require("./routes-admin-election");
const resultsRoutes = require("./routes-admin-results");

function trustProxySetting(value) {
  if (!value) return false;
  if (/^\d+$/.test(value)) return Number(value);
  if (value === "true") return 1; // "true" would trust every hop and let clients forge their address
  return value; // "loopback", "10.0.0.0/8", ...
}

/* A bug that fails on every request must not flood the (permanent) audit log. */
let errorWindowStart = 0;
let errorsInWindow = 0;

function noteServerError(reference, route) {
  const now = Date.now();

  if (now - errorWindowStart > 60_000) {
    errorWindowStart = now;
    errorsInWindow = 0;
  }

  errorsInWindow += 1;

  if (errorsInWindow <= 10) {
    audit.append("system", "system", `Unexpected server error ${reference} on ${route}`);
  }
}

function createApp() {
  const app = express();

  app.disable("x-powered-by");
  app.set("trust proxy", trustProxySetting(config.TRUST_PROXY));

  app.use(securityHeaders);

  if (process.env.LOG_REQUESTS === "1") {
    app.use((req, res, next) => {
      const started = Date.now();

      // Only the route pattern is logged — never the real path, query or cookies.
      res.on("finish", () => {
        const route = req.route ? `${req.baseUrl}${req.route.path}` : "(static/unmatched)";
        console.log(`${req.method} ${route} ${res.statusCode} ${Date.now() - started}ms`);
      });

      next();
    });
  }

  /* ---------- API ---------- */

  const bodies = jsonBodies();

  app.use("/api", apiNoStore, floodGuard, csrfGuard);
  app.use("/api/admin", bodies.admin);
  app.use("/api", bodies.pub, ensureBody);

  app.get("/api/health", (req, res) => {
    res.json({ ok: true });
  });

  app.use("/api", publicRoutes);

  const adminApi = express.Router();
  adminApi.use(adminSession);
  adminApi.use(authRoutes);
  adminApi.use(electionRoutes);
  adminApi.use(resultsRoutes);
  app.use("/api/admin", adminApi);

  app.use("/api", (req, res) => {
    res.status(404).json({ error: "That address does not exist.", code: "not-found" });
  });

  /* ---------- pages ---------- */

  app.use(
    express.static(config.PUBLIC_DIR, {
      index: "index.html",
      extensions: ["html"],
      dotfiles: "ignore",
      etag: true,
      maxAge: 0,
      setHeaders(res) {
        res.setHeader("Cache-Control", "no-cache");
      }
    })
  );

  app.use((req, res) => {
    res.status(404).type("text/plain").send("Page not found.");
  });

  /* ---------- errors ---------- */

  app.use(bodyErrors);

  app.use((error, req, res, next) => {
    const reference = crypto.randomBytes(4).toString("hex");
    const route = `${req.method} ${req.baseUrl}${req.route ? req.route.path : ""}`;

    console.error(`[error ${reference}] ${route}\n${error && error.stack ? error.stack : error}`);

    try {
      noteServerError(reference, route);
    } catch (loggingError) {
      /* never let logging hide the original problem */
    }

    if (res.headersSent) return next(error);

    res.status(500).json({
      error: "Something went wrong on the server. Please try again in a moment.",
      code: "server-error",
      reference
    });
  });

  return app;
}

module.exports = { createApp };
