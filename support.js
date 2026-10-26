/*
  Helpers for the real-browser check (tests/browser/run.js).

  Nothing here is part of the election system. It only starts a throw-away copy
  of the server, finds a browser to drive it with, and offers small helpers that
  do what a person would do on the pages: sign in, answer the "fresh code"
  dialog, open a section, read the pop-up messages.

  Two things a person cannot do from a script are done through the server's own
  database file, exactly as the HTTP tests do (they live in tests/real-server.js):

    freshCode()      a real authenticator never repeats a code, and the server
                     refuses a code from a 30-second step it already accepted.
                     A script signs in far faster than that, so the "last
                     accepted step" is moved back first — the equivalent of
                     waiting for the next code.
    expireStepUp()   pretend the last two-factor confirmation was long ago, so
                     the dashboard has to ask again.
*/

"use strict";

const { spawnSync } = require("node:child_process");
const path = require("node:path");

const realServer = require("../real-server");

const { ROOT } = realServer;

const PASSWORD = "Tr0ub4dor&3-Stapler-Moon";

/* ---------------------------------------------------------------------- */
/* Finding a browser                                                        */
/* ---------------------------------------------------------------------- */

/*
  Playwright is deliberately NOT a dependency of the project (the server needs
  only Express). This looks for it in the usual places, in this order:
    1. PLAYWRIGHT_MODULE            an explicit path, e.g. /opt/tools/node_modules/playwright
    2. the project's own node_modules   (npm install --no-save playwright)
    3. NODE_PATH
    4. the global npm folder
*/
function loadPlaywright() {
  const candidates = [];

  if (process.env.PLAYWRIGHT_MODULE) candidates.push(process.env.PLAYWRIGHT_MODULE);

  candidates.push("playwright", "playwright-core");

  const globalRoot = spawnSync("npm", ["root", "-g"], { encoding: "utf8" });

  if (globalRoot.status === 0 && globalRoot.stdout.trim()) {
    const root = globalRoot.stdout.trim();

    candidates.push(path.join(root, "playwright"), path.join(root, "playwright-core"));
  }

  for (const candidate of candidates) {
    try {
      const loaded = require(candidate);

      if (loaded && loaded.chromium) return loaded;
    } catch (error) {
      /* try the next place */
    }
  }

  return null;
}

async function launchChromium(playwright, { headed = false } = {}) {
  const options = { headless: !headed };

  if (process.env.CHROMIUM_PATH) options.executablePath = process.env.CHROMIUM_PATH;

  return playwright.chromium.launch(options);
}

/* ---------------------------------------------------------------------- */
/* A throw-away server                                                      */
/* ---------------------------------------------------------------------- */

/*
  The server itself, the starter-account file and the "fresh code" helpers live in
  tests/real-server.js, which the lifecycle test (tests/12) shares. Here only the
  browser check's defaults are added: a rehearsal-style server with the background
  schedulers off, so nothing happens behind the script's back.
*/
function startServer(extraEnvironment = {}) {
  return realServer.startRealServer({
    env: { NODE_ENV: "development", ENABLE_SCHEDULERS: "false", ...extraEnvironment }
  });
}

const { readCredentials, openDb, freshCode, expireStepUp, clearAdminLimits } = realServer;

/* ---------------------------------------------------------------------- */
/* Reporting                                                                */
/* ---------------------------------------------------------------------- */

class Reporter {
  constructor() {
    this.passes = 0;
    this.failures = [];
    this.unexpected = [];
    this.section_ = "";
  }

  section(title) {
    this.section_ = title;
    console.log(`\n${title}`);
  }

  check(name, ok, detail = "") {
    if (ok) {
      this.passes += 1;
      console.log(`  ✓ ${name}`);
    } else {
      this.failures.push({ section: this.section_, name, detail });
      console.log(`  ✗ ${name}${detail ? `\n      ${String(detail).replace(/\n/g, "\n      ")}` : ""}`);
    }

    return Boolean(ok);
  }

  equal(name, actual, expected) {
    const same = JSON.stringify(actual) === JSON.stringify(expected);

    return this.check(name, same, same ? "" : `expected ${JSON.stringify(expected)}\n  but got ${JSON.stringify(actual)}`);
  }

  info(text) {
    console.log(`    · ${text}`);
  }

  /* Something the browser reported that no step said to expect. */
  problem(text) {
    this.unexpected.push(text);
  }

  /* Turn everything unexpected since the last call into one check. */
  flush(label) {
    const list = this.unexpected.splice(0);

    this.check(`no unexpected browser errors while ${label}`, list.length === 0, list.join("\n"));
  }

  finish() {
    console.log(`\n${"=".repeat(60)}`);
    console.log(`${this.passes} checks passed, ${this.failures.length} failed.`);

    this.failures.forEach((failure) => {
      console.log(`\n  FAILED  [${failure.section}] ${failure.name}`);
      if (failure.detail) console.log(`          ${String(failure.detail).replace(/\n/g, "\n          ")}`);
    });

    return this.failures.length === 0 ? 0 : 1;
  }
}

/* ---------------------------------------------------------------------- */
/* Watching a page for trouble                                              */
/* ---------------------------------------------------------------------- */

/*
  Some error responses are the system working as designed. They are listed
  here with the reason, so anything else shows up as a failure:

    401 on the student login      a wrong student password is refused
    403 "step-up-required"        a sensitive action asks for a fresh 2FA code
                                  first; the dashboard shows the dialog
*/
function expectedFailure(status, pathname, body) {
  if (status === 401 && pathname === "/api/voter/login") return "a wrong student password is refused";

  if (status === 403 && pathname.startsWith("/api/admin/") && body && body.code === "step-up-required") {
    return "the dashboard asks for a fresh 2FA code";
  }

  return null;
}

/*
  A few steps deliberately make the server say no (for example, checking that
  the session really ended). They register what to expect, per page, here.
*/
const tolerated = new WeakMap();

function tolerate(page, status, pathPattern, { once = false } = {}) {
  const list = tolerated.get(page) || [];

  list.push({ status, pathPattern, once });
  tolerated.set(page, list);
}

function isTolerated(page, status, pathname) {
  const list = tolerated.get(page) || [];
  const index = list.findIndex((item) => item.status === status && item.pathPattern.test(pathname));

  if (index < 0) return false;
  if (list[index].once) list.splice(index, 1);

  return true;
}

/* The API calls each watched page has started and not yet finished (see settle() below). */
const runningCalls = new WeakMap();

function trackApiCalls(page) {
  const running = new Set();

  const isApiCall = (request) => {
    try {
      return new URL(request.url()).pathname.startsWith("/api/");
    } catch (error) {
      return false;
    }
  };

  page.on("request", (request) => {
    if (isApiCall(request)) running.add(request);
  });
  page.on("requestfinished", (request) => running.delete(request));
  page.on("requestfailed", (request) => running.delete(request));

  runningCalls.set(page, running);
}

function watchPage(page, label, reporter) {
  trackApiCalls(page);

  page.on("console", (message) => {
    const type = message.type();

    if (type !== "error" && type !== "warning") return;

    /* The browser prints one of these for every non-2xx response; the response hook below judges them. */
    if (/^Failed to load resource/.test(message.text())) return;

    reporter.problem(`${label}: console.${type}: ${message.text()}`);
  });

  page.on("pageerror", (error) => reporter.problem(`${label}: uncaught error: ${error.message}`));

  page.on("requestfailed", (request) => {
    const failure = request.failure();

    /* A reload or a page change cancels requests that were still in flight; that is not a fault. */
    if (failure && /ERR_ABORTED/.test(failure.errorText)) return;

    reporter.problem(`${label}: request failed: ${request.url()} (${failure && failure.errorText})`);
  });

  page.on("response", async (response) => {
    const status = response.status();

    if (status < 400) return;

    const { pathname } = new URL(response.url());

    if (pathname === "/favicon.ico") return;

    let body = null;

    try {
      body = JSON.parse(await response.text());
    } catch (error) {
      /* not JSON, or the page moved on before the body arrived */
    }

    if (expectedFailure(status, pathname, body) || isTolerated(page, status, pathname)) return;

    reporter.problem(`${label}: ${response.request().method()} ${pathname} answered ${status}${body && body.error ? ` — ${body.error}` : ""}`);
  });
}

/* ---------------------------------------------------------------------- */
/* Small page helpers                                                       */
/* ---------------------------------------------------------------------- */

/*
  The [hidden] attribute must really hide. A stylesheet rule such as
  `.banner { display: flex }` silently overrides it, which once left several
  banners showing on the voting page. Returns whatever is hidden "on paper"
  but still visible.
*/
function hiddenViolations(page) {
  return page.evaluate(() => [...document.querySelectorAll("[hidden]")]
    .filter((element) => getComputedStyle(element).display !== "none")
    .map((element) => `${element.tagName.toLowerCase()}${element.id ? `#${element.id}` : ""}`));
}

function horizontalOverflow(page) {
  return page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
}

async function toastTexts(page) {
  return page.$$eval("#toasts .toast", (items) => items.map((item) => ({
    text: item.textContent.trim(),
    error: item.classList.contains("toast--error")
  })));
}

/*
  Wait until the page has finished reacting to what it was just told to do.

  A pop-up such as "Candidate added." appears the moment the server answers, a beat
  BEFORE the dashboard fetches and redraws the list behind it. A person never notices
  that beat; a script that reads the list at that instant sees the old one. This waits
  until none of the page's API calls has been running for a short, steady moment.
*/
async function settle(page, { quietMs = 100, timeout = 8000 } = {}) {
  const running = runningCalls.get(page);

  if (!running) return;

  const deadline = Date.now() + timeout;
  let quietSince = null;

  while (Date.now() < deadline) {
    if (running.size === 0) {
      if (quietSince === null) quietSince = Date.now();
      if (Date.now() - quietSince >= quietMs) return;
    } else {
      quietSince = null;
    }

    await page.waitForTimeout(25);
  }
}

/*
  Wait for a pop-up message whose text matches, and remove it from the screen.
  Removing it matters: the same wording (for example "Election saved.") appears
  after every save, and an old message must not satisfy a later wait.
  Afterwards the page is given the moment it needs to redraw (see settle()).
*/
async function waitForToast(page, pattern, { timeout = 8000 } = {}) {
  await page.waitForFunction(
    ({ source, flags }) => {
      const found = [...document.querySelectorAll("#toasts .toast")].find((item) => new RegExp(source, flags).test(item.textContent));

      if (!found) return false;

      found.remove();
      return true;
    },
    { source: pattern.source, flags: pattern.flags },
    { timeout }
  );

  await settle(page);
}

/*
  Wait for a dialog to be open AND ready to be typed into.

  The dashboard puts the cursor in a dialog's first box about 30 ms after the dialog opens.
  A script that starts typing in that very instant can have the cursor pulled back to the
  first box in the middle of filling the second one, and the text lands in the wrong place.
  A person cannot type that fast, so only scripts need to wait the few extra milliseconds.
*/
async function waitForDialog(page, selector) {
  await page.waitForSelector(`${selector}[open]`);
  await page.waitForTimeout(100);
}

async function gotoView(page, id) {
  await page.click(`.admin-nav-button[data-view="${id}"]`);
  await page.waitForSelector(`#view-${id}.active-view`);
  await page.waitForLoadState("networkidle");
  await page.waitForTimeout(120);
}

/* The sign-in page, first time: temporary password → own password → 2FA set-up → recovery codes. */
async function adminFirstSignIn(browser, server, account, reporter, options = {}) {
  const context = await browser.newContext({
    viewport: { width: 1280, height: 900 },
    timezoneId: options.timezoneId || "Africa/Lagos",
    acceptDownloads: true
  });

  context.setDefaultTimeout(10_000);

  const page = await context.newPage();

  watchPage(page, account.role, reporter);

  clearAdminLimits(server);

  await page.goto(`${server.base}/admin.html`);
  await page.fill("#adminEmail", account.email);
  await page.fill("#adminPassword", account.temporaryPassword);
  await page.click("#signinButton");

  await page.waitForSelector("#passwordPanel:not([hidden])");
  await page.fill("#newPassword", PASSWORD);
  await page.fill("#newPasswordAgain", PASSWORD);
  await page.click("#passwordForm button[type=submit]");

  await page.waitForSelector("#enrollPanel:not([hidden])");
  await page.waitForFunction(() => document.getElementById("enrollSecret").textContent.replace(/[^A-Za-z2-7]/g, "").length >= 16);

  const secret = (await page.textContent("#enrollSecret")).trim();

  await page.fill("#enrollCode", freshCode(server, secret, account.email));
  await page.click("#enrollForm button[type=submit]");

  await page.waitForSelector("#recoveryPanel:not([hidden])");

  const recoveryCodes = await page.$$eval("#recoveryList li", (items) => items.map((item) => item.textContent.trim()));

  await page.check("#recoverySaved");
  await page.click("#recoveryContinue");

  await page.waitForURL("**/dashboard.html");
  await page.waitForSelector(".admin-nav-button[data-view]");

  return {
    context,
    page,
    base: server.base,
    role: account.role,
    email: account.email,
    password: PASSWORD,
    secret,
    recoveryCodes
  };
}

/* A later sign-in: password, then the current code. */
async function adminSignIn(browser, server, who, reporter, options = {}) {
  const context = await browser.newContext({
    viewport: { width: 1280, height: 900 },
    timezoneId: options.timezoneId || "Africa/Lagos",
    acceptDownloads: true
  });

  context.setDefaultTimeout(10_000);

  const page = await context.newPage();

  watchPage(page, `${who.role} (second sign-in)`, reporter);

  clearAdminLimits(server);

  await page.goto(`${server.base}/admin.html`);
  await page.fill("#adminEmail", who.email);
  await page.fill("#adminPassword", options.password || who.password);
  await page.click("#signinButton");

  await page.waitForSelector("#totpPanel:not([hidden])");
  await page.fill("#totpCode", freshCode(server, who.secret, who.email));
  await page.click("#totpForm button[type=submit]");

  await page.waitForURL("**/dashboard.html");
  await page.waitForSelector(".admin-nav-button[data-view]");

  return { ...who, base: server.base, context, page };
}

/* The dashboard's "enter a fresh code" dialog. Returns true if it appeared. */
async function answerStepUpIfAsked(server, who, { wait = 1500 } = {}) {
  try {
    await who.page.waitForSelector("#stepUpDialog[open]", { timeout: wait });
  } catch (error) {
    return false;
  }

  await who.page.fill("#stepUpCode", freshCode(server, who.secret, who.email));
  await who.page.click("#stepUpForm button[type=submit]");
  await who.page.waitForSelector("#stepUpDialog", { state: "hidden" });

  return true;
}

/* Confirm dialog: type the phrase if one is asked for, then press the main button. */
async function confirmDialogOk(page, phrase) {
  await page.waitForSelector("#confirmDialog[open]");

  if (phrase !== undefined && (await page.isVisible("#confirmPhraseBox"))) {
    await page.fill("#confirmPhrase", phrase);
  }

  await page.click("#confirmOk");
}

async function promptDialogOk(page, text) {
  await page.waitForSelector("#promptDialog[open]");
  if (text !== undefined) await page.fill("#promptInput", text);
  await page.click("#promptOk");
}

/* Read what a "show once" secret dialog displays, then close it. */
async function takeSecret(page) {
  await page.waitForSelector("#secretDialog[open]");

  const text = (await page.textContent("#secretBox")).trim();

  await page.click("#secretClose");
  await page.waitForSelector("#secretDialog", { state: "hidden" });

  return text;
}

async function takeInfo(page) {
  await page.waitForSelector("#infoDialog[open]");

  const title = (await page.textContent("#infoTitle")).trim();
  const text = (await page.$eval("#infoBody", (element) => element.innerText)).trim();

  await page.click("#infoClose");
  await page.waitForSelector("#infoDialog", { state: "hidden" });

  return { title, text };
}

module.exports = {
  ROOT,
  PASSWORD,
  loadPlaywright,
  launchChromium,
  startServer,
  readCredentials,
  openDb,
  freshCode,
  expireStepUp,
  clearAdminLimits,
  Reporter,
  watchPage,
  tolerate,
  hiddenViolations,
  horizontalOverflow,
  toastTexts,
  settle,
  waitForToast,
  waitForDialog,
  gotoView,
  adminFirstSignIn,
  adminSignIn,
  answerStepUpIfAsked,
  confirmDialogOk,
  promptDialogOk,
  takeSecret,
  takeInfo
};
