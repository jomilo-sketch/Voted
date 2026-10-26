/*
  BOUESTI Vote — start the server.

      npm start                       rehearsal: demo code 123456, open roster
      NODE_ENV=production npm start   the real election (see README.md)

  Order matters: configuration is checked FIRST, then the database is
  opened (which refuses to start with the wrong master key), then the
  starter data is created, and only then does the server accept requests.
*/

"use strict";

const fs = require("fs");
const http = require("http");
const https = require("https");
const config = require("./config");

function banner(lines) {
  const width = Math.max(...lines.map((line) => line.length)) + 4;
  const bar = "═".repeat(width);

  console.log(`\n╔${bar}╗`);
  lines.forEach((line) => console.log(`║  ${line.padEnd(width - 2)}║`));
  console.log(`╚${bar}╝\n`);
}

async function main() {
  const runtimeProblem = require("./runtime").versionProblem();

  if (runtimeProblem) {
    console.error(`\n  ✖ ${runtimeProblem}\n`);
    process.exit(1);
  }

  const { errors, warnings } = config.validate();

  warnings.forEach((warning) => console.warn(`  ! ${warning}`));

  if (errors.length) {
    errors.forEach((error) => console.error(`  ✖ ${error}`));
    console.error("\nThe server was not started. Fix the settings above and try again.\n");
    process.exit(1);
  }

  const keys = require("./keys");
  const firstRun = !keys.masterKeyFileExists() && !fs.existsSync(config.DB_PATH);

  let startup;

  try {
    startup = await require("./startup").bootstrap();
  } catch (error) {
    console.error(`\n  ✖ ${error.message}\n`);
    process.exit(1);
  }

  if (firstRun) {
    banner([
      "FIRST START — a new master key was created.",
      "",
      `It is the file:  ${config.KEY_DIR}/master.key`,
      "",
      "COPY IT NOW to two safe places held by different officers,",
      "and never keep it next to the backups. Without it the encrypted",
      "backups, 2FA secrets and signing key cannot be recovered."
    ]);
  }

  if (startup.createdAdmins) {
    banner([
      "STARTER ADMINISTRATOR ACCOUNTS (one-time passwords)",
      "",
      ...startup.createdAdmins.map((account) => `${account.email.padEnd(22)} ${account.temporaryPassword}`),
      "",
      "Each must choose a new password and set up 2FA at first sign-in.",
      `The same list is in ${config.CREDENTIALS_FILE}`,
      "(it deletes itself once all three accounts are set up)."
    ]);
  }

  if (startup.restored) {
    console.log(`  The database was restored from ${startup.restored.backup}; this is recorded in the audit log.\n`);
  }

  const { createApp } = require("./web");
  const scheduler = require("./scheduler");
  const database = require("./db");

  const app = createApp();
  const useTls = Boolean(config.TLS_KEY_FILE && config.TLS_CERT_FILE);

  const server = useTls
    ? https.createServer({ key: fs.readFileSync(config.TLS_KEY_FILE), cert: fs.readFileSync(config.TLS_CERT_FILE) }, app)
    : http.createServer(app);

  // Slow or stalled connections are cut off rather than held open forever.
  server.headersTimeout = 20_000;
  server.requestTimeout = 60_000;
  server.keepAliveTimeout = 5_000;

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(config.PORT, config.HOST, resolve);
  }).catch((error) => {
    console.error(
      error.code === "EADDRINUSE"
        ? `\n  ✖ Port ${config.PORT} is already in use. Stop the other program or set PORT.\n`
        : `\n  ✖ Could not start listening: ${error.message}\n`
    );
    process.exit(1);
  });

  scheduler.start();

  // Lets offline tools (npm run restore) refuse to replace a database that is in use.
  fs.writeFileSync(config.PID_FILE, `${process.pid}\n`, { mode: 0o600 });
  process.on("exit", () => {
    try {
      fs.unlinkSync(config.PID_FILE);
    } catch (error) {
      /* already gone */
    }
  });

  const scheme = useTls ? "https" : "http";
  const shownHost = config.HOST === "0.0.0.0" || config.HOST === "::" ? "localhost" : config.HOST;

  console.log("BOUESTI Vote is running.");
  console.log(`  Students:        ${scheme}://${shownHost}:${config.PORT}/`);
  console.log(`  Administrators:  ${scheme}://${shownHost}:${config.PORT}/admin`);
  console.log(`  Mode:            ${require("./election").getElection().mode} · codes by ${config.OTP_MODE} · ${config.NODE_ENV}`);
  console.log(`  Data folder:     ${config.DATA_DIR}\n`);

  /* ---------- stopping cleanly ---------- */

  let stopping = false;

  function shutdown(signal) {
    if (stopping) return;
    stopping = true;

    console.log(`\n${signal} received — finishing requests and closing the database…`);
    scheduler.stop();

    const force = setTimeout(() => {
      console.error("Forced exit after waiting 10 seconds.");
      process.exit(1);
    }, 10_000);
    force.unref();

    server.close(() => {
      try {
        require("./audit").append("system", "system", `Server stopped (${signal})`);
      } catch (error) {
        /* the database may already be closing */
      }

      database.close();
      process.exit(0);
    });

    server.closeIdleConnections();
  }

  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("SIGTERM", () => shutdown("SIGTERM"));

  process.on("uncaughtException", (error) => {
    console.error("Uncaught exception:", error);
    process.exit(1); // let the service manager restart a clean process
  });

  process.on("unhandledRejection", (reason) => {
    console.error("Unhandled promise rejection:", reason);
  });
}

if (require.main === module) {
  main();
}

module.exports = { main };
