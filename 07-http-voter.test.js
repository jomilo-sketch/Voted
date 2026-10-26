"use strict";

const { freshEnv } = require("./helpers");
freshEnv();

const test = require("node:test");
const assert = require("node:assert");

const { Client, startServer } = require("./http-client");
const d = require("../db");
const config = require("../config");

let app;
let base;

test.before(async () => {
  app = await startServer();
  base = app.base;
  config.OTP_RESEND_COOLDOWN_SEC = 0; // lets the resend test run without waiting 30 seconds
});

test.after(async () => {
  await app.stop();
});

/* Walk one student all the way to the ballot. Returns the Client holding their cookie. */
async function signInAndVerify(matric, email, client = new Client(base)) {
  const login = await client.post("/api/voter/login", { matric, password: "password1" });
  assert.strictEqual(login.status, 200, JSON.stringify(login.json));
  assert.strictEqual(login.json.outcome, "signed_in");

  const rules = await client.post("/api/voter/rules");
  assert.strictEqual(rules.status, 200, JSON.stringify(rules.json));
  assert.strictEqual(rules.json.state.stage, "rules");

  const sent = await client.post("/api/voter/otp/request", { email });
  assert.strictEqual(sent.status, 200, JSON.stringify(sent.json));

  const verified = await client.post("/api/voter/otp/verify", { code: "123456" });
  assert.strictEqual(verified.status, 200, JSON.stringify(verified.json));
  assert.strictEqual(verified.json.state.stage, "verified");

  return client;
}

async function castFirstChoices(client) {
  const ballot = await client.get("/api/voter/ballot");
  assert.strictEqual(ballot.status, 200, JSON.stringify(ballot.json));
  assert.ok(ballot.json.offices.length > 0);

  const choices = {};
  ballot.json.offices.forEach((office) => {
    choices[String(office.id)] = office.candidates[0].id;
  });

  return client.post("/api/voter/vote", { choices });
}

test("the public pages and security headers are served", async () => {
  const client = new Client(base);

  const state = await client.get("/api/public/state");
  assert.strictEqual(state.status, 200);
  assert.strictEqual(state.json.phase, "open");
  assert.strictEqual(state.json.rehearsal, true);

  for (const page of ["/", "/index.html", "/admin", "/admin.html", "/dashboard", "/dashboard.html", "/app.js", "/shared.js", "/admin.js", "/dashboard.js", "/styles.css", "/admin.css"]) {
    const response = await client.get(page, { csrf: false });
    assert.strictEqual(response.status, 200, `${page} should be served`);
  }

  const home = await client.get("/", { csrf: false });
  const csp = home.headers.get("content-security-policy");

  assert.match(csp, /script-src 'self'/);
  assert.doesNotMatch(csp, /script-src[^;]*unsafe-inline/, "no inline scripts are allowed");
  assert.match(csp, /frame-ancestors 'none'/);
  assert.strictEqual(home.headers.get("x-content-type-options"), "nosniff");
  assert.strictEqual(home.headers.get("x-frame-options"), "DENY");
  assert.match(state.headers.get("cache-control"), /no-store/);

  // no page may contain an inline <script> body or inline event handler (the CSP would block them)
  for (const page of ["/", "/admin", "/dashboard"]) {
    const html = (await client.get(page, { csrf: false })).text;
    assert.doesNotMatch(html, /<script(?![^>]*\ssrc=)[^>]*>/i, `${page} has an inline script`);
    assert.doesNotMatch(html, /\son(click|submit|change|load|error)=/i, `${page} has an inline event handler`);
  }
});

test("ITEM 1: only a digits-only matric number may sign in", async () => {
  const bad = [
    "matric 152637", "Matric 152637", "matric152637", "MATRIC:152637", "152637x", "x152637",
    "15 2637", "152-637", "abc", "12", "123", "1e5000", "152637; DROP TABLE students", "", "   "
  ];

  for (const matric of bad) {
    const client = new Client(base);
    const response = await client.post("/api/voter/login", { matric, password: "password1" });

    assert.strictEqual(response.status, 400, `"${matric}" must be refused`);
    assert.ok(["matric-format", "matric-required"].includes(response.json.code), `"${matric}" gave ${response.json.code}`);
    assert.strictEqual(client.jar.size, 0, "no session cookie for a refused matric");
  }

  for (const matric of ["152637", "1257", "173637"]) {
    const client = new Client(base);
    const response = await client.post("/api/voter/login", { matric, password: "password1" });

    assert.strictEqual(response.status, 200, `"${matric}" must be accepted`);
    assert.strictEqual(response.json.outcome, "signed_in");
    assert.strictEqual(response.json.state.matric, matric);
  }

  // the matric database column itself rejects non-digits (defence in depth)
  assert.throws(
    () => d.run("INSERT INTO students (matric, addedAt) VALUES ('matric 999999', ?)", d.nowIso()),
    /constraint/i
  );
});

test("ITEM 2: password1 is the ONLY password that works", async () => {
  const wrong = ["Password1", "PASSWORD1", "password", "password12", "password 1", " password1", "password1 ", "123456", "admin", "", "password1\u0000", "passw0rd1"];

  for (const password of wrong) {
    const client = new Client(base);
    // a different matric each time keeps the per-matric limiter out of the way
    const response = await client.post("/api/voter/login", { matric: String(210000 + wrong.indexOf(password)), password });

    assert.strictEqual(response.status, 401, `password ${JSON.stringify(password)} must be refused`);
    assert.strictEqual(response.json.code, "bad-password");
    assert.strictEqual(client.jar.size, 0);
  }

  const ok = await new Client(base).post("/api/voter/login", { matric: "219999", password: "password1" });
  assert.strictEqual(ok.status, 200);
  assert.strictEqual(ok.json.outcome, "signed_in");

  // the password is not in anything served to the browser
  const client = new Client(base);

  for (const file of ["/app.js", "/shared.js", "/index.html", "/api/public/state"]) {
    const body = (await client.get(file, { csrf: false })).text;
    assert.doesNotMatch(body, /password1/i, `${file} must not reveal the password`);
  }
});

test("session cookie is HttpOnly + SameSite=Strict and the token is stored only as a hash", async () => {
  const client = new Client(base);
  const login = await client.post("/api/voter/login", { matric: "220001", password: "password1" });

  assert.strictEqual(login.setCookies.length, 1);

  const cookie = login.setCookies[0];
  assert.match(cookie, /HttpOnly/i);
  assert.match(cookie, /SameSite=Strict/i);
  assert.match(cookie, /Path=\//i);
  assert.match(cookie, /Max-Age=\d+/i);

  const rawToken = decodeURIComponent(cookie.split(";")[0].split("=")[1]);
  const rows = d.all("SELECT tokenHash FROM sessions");

  assert.ok(rows.length > 0);
  rows.forEach((row) => assert.notStrictEqual(row.tokenHash, rawToken, "the raw token is never stored"));

  // the browser's script cannot read it, and the JSON never contains it
  assert.ok(!JSON.stringify(login.json).includes(rawToken));
});

test("full journey: login → rules (registered) → e-mail code (verified) → vote → blocked from voting twice", async () => {
  const matric = "300001";
  const email = "ada.obi@bouesti.edu.ng";
  const client = new Client(base);

  const login = await client.post("/api/voter/login", { matric, password: "password1" });
  assert.strictEqual(login.json.state.stage, "login");

  const session = await client.get("/api/voter/session");
  assert.strictEqual(session.json.signedIn, true);
  assert.strictEqual(session.json.state.stage, "login");

  // order is enforced by the server, not the page
  assert.strictEqual((await client.post("/api/voter/otp/request", { email })).status, 403);
  assert.notStrictEqual((await client.get("/api/voter/ballot")).status, 200);
  assert.strictEqual((await client.post("/api/voter/vote", { choices: {} })).status, 403);

  const rules = await client.post("/api/voter/rules");
  assert.strictEqual(rules.json.state.stage, "rules");

  const student = d.get("SELECT registered, verified FROM students WHERE matric = ?", matric);
  assert.strictEqual(student.registered, 1, "accepting the rules marks the student REGISTERED");
  assert.strictEqual(student.verified, 0);

  assert.strictEqual((await client.post("/api/voter/otp/request", { email: "ada@gmail.com" })).json.code, "email-domain");

  const sent = await client.post("/api/voter/otp/request", { email });
  assert.strictEqual(sent.status, 200);
  assert.match(sent.json.maskedEmail, /@bouesti\.edu\.ng$/);

  // RESEND (the very first request in the original brief)
  const resent = await client.post("/api/voter/otp/request", { email });
  assert.strictEqual(resent.status, 200, "a student can ask for a new code");

  const wrong = await client.post("/api/voter/otp/verify", { code: "000000" });
  assert.strictEqual(wrong.status, 400);
  assert.strictEqual(d.get("SELECT verified FROM students WHERE matric = ?", matric).verified, 0);

  const oldCookie = client.cookieHeader();
  const verified = await client.post("/api/voter/otp/verify", { code: "123456" });
  assert.strictEqual(verified.json.state.stage, "verified");
  assert.strictEqual(d.get("SELECT verified FROM students WHERE matric = ?", matric).verified, 1, "the code marks the student VERIFIED");

  // the token was rotated: the one used before verification is dead
  const stale = await new Client(base).get("/api/voter/session", { cookie: oldCookie });
  assert.strictEqual(stale.json.signedIn, false);

  const ballot = await client.get("/api/voter/ballot");
  assert.strictEqual(ballot.status, 200);
  assert.ok(ballot.json.offices.every((office) => office.candidates.length > 0));
  assert.ok(!JSON.stringify(ballot.json).includes('"status"'), "no internal fields reach the voter");

  // incomplete / forged ballots are refused
  assert.strictEqual((await client.post("/api/voter/vote", { choices: {} })).status, 400);
  assert.strictEqual((await client.post("/api/voter/vote", { choices: { 999999: 1 } })).status, 400);

  const vote = await castFirstChoices(client);
  assert.strictEqual(vote.status, 200, JSON.stringify(vote.json));
  assert.match(vote.json.receipt, /^BOUESTI-\d{4}-[A-Z2-9]{5}-[A-Z2-9]{5}$/);

  // the session is gone and the cookie was cleared
  assert.strictEqual(client.jar.size, 0);
  assert.strictEqual((await client.get("/api/voter/session")).json.signedIn, false);

  // signing in AGAIN is stopped at the door with the calm message
  const again = await client.post("/api/voter/login", { matric, password: "password1" });
  assert.strictEqual(again.status, 200);
  assert.strictEqual(again.json.outcome, "already_voted");
  assert.match(again.json.message, /remain calm/i);
  assert.strictEqual(client.jar.size, 0, "no session is created for someone who has voted");

  // the receipt proves acceptance but says nothing about the choices
  const receipt = await client.post("/api/public/receipt", { code: vote.json.receipt });
  assert.strictEqual(receipt.json.found, true);
  assert.strictEqual((await client.post("/api/public/receipt", { code: "BOUESTI-2026-AAAAA-BBBBB" })).json.found, false);
});

test("same device: one student after another, each with their own session", async () => {
  const client = new Client(base);

  await signInAndVerify("310001", "first.student@bouesti.edu.ng", client);
  assert.strictEqual((await castFirstChoices(client)).status, 200);

  // the very same browser now serves a different matric number
  await signInAndVerify("310002", "second.student@bouesti.edu.ng", client);
  assert.strictEqual((await client.get("/api/voter/session")).json.state.matric, "310002");
  assert.strictEqual((await castFirstChoices(client)).status, 200);

  // while a half-finished session exists, a different student signing in replaces it
  const half = await client.post("/api/voter/login", { matric: "310003", password: "password1" });
  assert.strictEqual(half.json.outcome, "signed_in");

  const firstCookie = client.cookieHeader();
  const next = await client.post("/api/voter/login", { matric: "310004", password: "password1" });
  assert.strictEqual(next.json.outcome, "signed_in");
  assert.strictEqual((await client.get("/api/voter/session")).json.state.matric, "310004");

  const replaced = await new Client(base).get("/api/voter/session", { cookie: firstCookie });
  assert.strictEqual(replaced.json.signedIn, false, "the earlier student's token no longer works");

  // an already-voted matric on a browser that holds someone else's session also clears that session
  const blocked = await client.post("/api/voter/login", { matric: "310001", password: "password1" });
  assert.strictEqual(blocked.json.outcome, "already_voted");
  assert.strictEqual((await client.get("/api/voter/session")).json.signedIn, false);

  // the ballot box holds exactly the ballots that were cast, with nothing linking them to a student:
  // these are the COMPLETE column lists, so any later change that adds a student reference or a time fails here
  const columns = (table) => d.all(`PRAGMA table_info(${table})`).map((column) => column.name);

  assert.deepStrictEqual(columns("ballots"), ["ballotId"]);
  assert.deepStrictEqual(columns("ballot_selections"), ["ballotId", "officeId", "candidateId"]);
  assert.deepStrictEqual(columns("turnout"), ["voterHash"]);
  assert.deepStrictEqual(columns("receipts"), ["codeHash"]);
  assert.strictEqual(d.get("SELECT COUNT(*) AS n FROM ballots").n, d.get("SELECT COUNT(*) AS n FROM turnout").n);
});

test("logout ends the session on the server, and a second device signs the first one out", async () => {
  const client = new Client(base);

  await client.post("/api/voter/login", { matric: "320001", password: "password1" });

  const cookie = client.cookieHeader();

  assert.strictEqual((await client.post("/api/voter/logout")).status, 200);
  assert.strictEqual((await new Client(base).get("/api/voter/session", { cookie })).json.signedIn, false, "the old token is invalidated, not just forgotten");

  const phone = new Client(base);
  const laptop = new Client(base);

  await phone.post("/api/voter/login", { matric: "320002", password: "password1" });
  await laptop.post("/api/voter/login", { matric: "320002", password: "password1" });

  assert.strictEqual((await phone.get("/api/voter/session")).json.signedIn, false);
  assert.strictEqual((await laptop.get("/api/voter/session")).json.signedIn, true);
});

test("upcoming and closed elections turn students away politely", async () => {
  const client = new Client(base);

  d.run("UPDATE election SET status = 'upcoming' WHERE id = 1");
  const upcoming = await client.post("/api/voter/login", { matric: "330001", password: "password1" });
  assert.strictEqual(upcoming.json.outcome, "upcoming");
  assert.strictEqual(client.jar.size, 0);
  assert.strictEqual((await client.get("/api/public/state")).json.phase, "upcoming");

  d.run("UPDATE election SET status = 'closed' WHERE id = 1");
  const closed = await client.post("/api/voter/login", { matric: "330001", password: "password1" });
  assert.strictEqual(closed.json.outcome, "closed");

  try {
    // a student who was already verified cannot carry on once voting closes
    d.run("UPDATE election SET status = 'active' WHERE id = 1");
    const live = new Client(base);
    await signInAndVerify("330002", "late.student@bouesti.edu.ng", live);

    d.run("UPDATE election SET status = 'closed' WHERE id = 1");
    assert.strictEqual((await live.get("/api/voter/ballot")).status, 403);
    assert.strictEqual((await live.post("/api/voter/vote", { choices: { 1: 1 } })).status, 403);
    assert.strictEqual(d.get("SELECT COUNT(*) AS n FROM turnout WHERE 1 = 1").n, d.get("SELECT COUNT(*) AS n FROM ballots").n);
  } finally {
    d.run("UPDATE election SET status = 'active' WHERE id = 1");
  }
});

test("a closed roster only admits students who are on it and enabled", async () => {
  d.run("UPDATE election SET rosterMode = 'closed' WHERE id = 1");

  try {
    d.run("INSERT INTO students (matric, name, email, addedAt) VALUES ('340001', 'On List', 'on.list@bouesti.edu.ng', ?)", d.nowIso());
    d.run("INSERT INTO students (matric, name, email, active, addedAt) VALUES ('340002', 'Disabled', 'off.list@bouesti.edu.ng', 0, ?)", d.nowIso());

    assert.strictEqual((await new Client(base).post("/api/voter/login", { matric: "340001", password: "password1" })).json.outcome, "signed_in");
    assert.strictEqual((await new Client(base).post("/api/voter/login", { matric: "340002", password: "password1" })).json.outcome, "not_eligible");
    assert.strictEqual((await new Client(base).post("/api/voter/login", { matric: "349999", password: "password1" })).json.outcome, "not_eligible");

    // the e-mail must be the one on record
    const client = new Client(base);
    await client.post("/api/voter/login", { matric: "340001", password: "password1" });
    await client.post("/api/voter/rules");

    assert.strictEqual((await client.post("/api/voter/otp/request", { email: "someone.else@bouesti.edu.ng" })).json.code, "email-mismatch");
    assert.strictEqual((await client.post("/api/voter/otp/request", { email: "on.list@bouesti.edu.ng" })).status, 200);
  } finally {
    d.run("UPDATE election SET rosterMode = 'open' WHERE id = 1");
  }
});

test("too many wrong codes cancel the code; too many wrong passwords block that matric only", async () => {
  const client = new Client(base);

  await client.post("/api/voter/login", { matric: "350001", password: "password1" });
  await client.post("/api/voter/rules");
  await client.post("/api/voter/otp/request", { email: "guess.me@bouesti.edu.ng" });

  let last;
  for (let attempt = 0; attempt < config.OTP_MAX_ATTEMPTS + 1; attempt += 1) {
    last = await client.post("/api/voter/otp/verify", { code: String(100000 + attempt) });
  }

  assert.ok([400, 429].includes(last.status));
  assert.strictEqual((await client.post("/api/voter/otp/verify", { code: "123456" })).status >= 400, true, "the code is cancelled after too many wrong tries");

  // wrong passwords: per-matric limit
  const target = "350002";
  let tripped = null;

  for (let attempt = 0; attempt < config.RATE.voterLoginMatric.limit + 2; attempt += 1) {
    const response = await new Client(base).post("/api/voter/login", { matric: target, password: `wrong-${attempt}` });
    if (response.status === 429) {
      tripped = response;
      break;
    }
  }

  assert.ok(tripped, "the matric number is blocked after repeated wrong passwords");
  assert.ok(Number(tripped.headers.get("retry-after")) > 0, "Retry-After tells the browser how long");

  // even the right password is refused while blocked…
  assert.strictEqual((await new Client(base).post("/api/voter/login", { matric: target, password: "password1" })).status, 429);
  // …but other students are unaffected
  assert.strictEqual((await new Client(base).post("/api/voter/login", { matric: "350003", password: "password1" })).status, 200);
});

test("requests without the browser header or from another site are refused (CSRF)", async () => {
  const client = new Client(base);

  const noHeader = await client.post("/api/voter/login", { matric: "360001", password: "password1" }, { csrf: false });
  assert.strictEqual(noHeader.status, 403);
  assert.strictEqual(noHeader.json.code, "csrf");

  const foreign = await client.post("/api/voter/login", { matric: "360001", password: "password1" }, { headers: { Origin: "https://evil.example" } });
  assert.strictEqual(foreign.status, 403);

  const crossSite = await client.post("/api/voter/login", { matric: "360001", password: "password1" }, { headers: { "Sec-Fetch-Site": "cross-site" } });
  assert.strictEqual(crossSite.status, 403);

  const sameSite = await client.post("/api/voter/login", { matric: "360001", password: "password1" }, { headers: { Origin: base, "Sec-Fetch-Site": "same-origin" } });
  assert.strictEqual(sameSite.status, 200);
});

test("students can report a problem, and the report reaches the inbox without ballots or choices", async () => {
  const client = new Client(base);

  const short = await client.post("/api/public/problem", { category: "otp", message: "help" });
  assert.strictEqual(short.status, 400);

  const sent = await client.post("/api/public/problem", { category: "otp", message: "My e-mail code has not arrived after ten minutes.", contact: "08000000000", matric: "370001" });
  assert.strictEqual(sent.status, 200);

  const row = d.get("SELECT category, status, matric FROM student_reports ORDER BY id DESC LIMIT 1");
  assert.deepStrictEqual({ ...row }, { category: "otp", status: "new", matric: "370001" });
});

test("unknown API paths and pages return clean errors, never a stack trace", async () => {
  const client = new Client(base);

  const api = await client.get("/api/nope");
  assert.strictEqual(api.status, 404);
  assert.strictEqual(api.json.code, "not-found");

  const page = await client.get("/no-such-page", { csrf: false });
  assert.strictEqual(page.status, 404);

  const bad = await client.request("POST", "/api/voter/login", { csrf: true, headers: { "Content-Type": "application/json" }, body: undefined });
  assert.ok(bad.status >= 400 && bad.status < 500);

  const malformed = await fetch(`${base}/api/voter/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Requested-With": "bouesti-vote" },
    body: "{not json"
  });
  assert.strictEqual(malformed.status, 400);
  assert.doesNotMatch(await malformed.text(), /at .*node_modules|Error:/);
});

test("the audit log records sign-ins by anonymous tag and never a choice or a matric number", async () => {
  const lines = d.all("SELECT message FROM audit_log").map((row) => row.message).join("\n");

  assert.doesNotMatch(lines, /\b300001\b|\b310001\b|\b152637\b/, "matric numbers are not written to the log");
  assert.match(lines, /accepted the election rules/);
  assert.match(lines, /Ballot accepted for/);
  assert.doesNotMatch(lines, /voted for|chose|selected candidate/i);
});
