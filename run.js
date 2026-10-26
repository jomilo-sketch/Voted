#!/usr/bin/env node
/*
  BOUESTI Vote — real-browser check (optional).

      npm run test:browser              the whole journey, about two minutes
      npm run test:browser -- --slow    also waits for one real 15-second background refresh
      npm run test:browser -- --headed  show the browser window
      npm run test:browser -- --shots ./shots   save a screenshot at the key moments
      npm run test:browser -- --only settings,admins   run just some steps (while developing)

  The normal tests (npm test) exercise the server over HTTP. This one drives the
  real pages in a real Chromium, the way people use them, because some faults
  only exist in the browser: a button that does nothing, a banner that will not
  hide, a form that resets itself while you type.

  It starts its own throw-away server and database. Nothing here touches real data.

  What it walks through, in order
     1. three officers sign in for the first time through the real sign-in page
     2. every section each role can see opens cleanly, and only those sections
     3. positions and candidates are edited
     4. the student roster: digits-only matric numbers, import, export
     5. a student votes on a phone-sized screen (items 1 and 2 of the brief)
     6. notices, and the problems students report
     7. the election form: typed dates and names survive background refreshes (item 8)
     8. settings, administrator accounts, operations (backups, restore test, incidents)
     9. the audit log, with no voter's choice and no matric number in it
    10. closing the election, the two-person results approval, a downloaded signed
        report checked by the standalone verifier, and the supervised comparison
    11. a new officer's own account: password, recovery codes, signing out everywhere

  It needs Playwright and a Chromium, neither of which is a dependency of the project:

      npm install --no-save playwright
      npx playwright install chromium

  or point at an existing installation:

      PLAYWRIGHT_MODULE=/path/to/node_modules/playwright   CHROMIUM_PATH=/path/to/chrome

  Exit status: 0 = every check passed, 1 = something failed, 2 = could not run.
*/

"use strict";

const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const support = require("./support");

const {
  ROOT, PASSWORD, Reporter, loadPlaywright, launchChromium, startServer, readCredentials,
  expireStepUp, watchPage, hiddenViolations, horizontalOverflow, toastTexts, waitForToast, waitForDialog, gotoView,
  adminFirstSignIn, adminSignIn, answerStepUpIfAsked, confirmDialogOk, promptDialogOk, takeSecret, takeInfo,
  clearAdminLimits, freshCode, tolerate
} = support;

const args = process.argv.slice(2);

const options = {
  slow: args.includes("--slow"),
  headed: args.includes("--headed"),
  shots: args.includes("--shots") ? path.resolve(args[args.indexOf("--shots") + 1] || "shots") : null,
  /* --only settings,admins   run just those steps (the three officers always sign in first) */
  only: args.includes("--only") ? String(args[args.indexOf("--only") + 1] || "").split(",").filter(Boolean) : null
};

/* What each role should see in the menu. This is the least-privilege rule as the person experiences it. */
const EXPECTED_MENU = {
  electoral_officer: [
    "Dashboard", "Election", "Voters / Students", "Candidates", "Voting Statistics", "Results", "Notifications",
    "Activity / Audit Logs", "Settings", "Administrators", "Operations", "My account"
  ],
  results_officer: [
    "Dashboard", "Election", "Candidates", "Voting Statistics", "Results", "Notifications",
    "Activity / Audit Logs", "Operations", "My account"
  ],
  technical_support: [
    "Dashboard", "Election", "Candidates", "Voting Statistics", "Notifications",
    "Activity / Audit Logs", "Operations", "My account"
  ]
};

/* A failed handler shows its message as a red pop-up. These wordings mean the PAGE is broken, not that a rule said no. */
const PROGRAMMING_ERROR = /cannot read|is not a function|is not defined|is null|is undefined|unexpected token|typeerror|referenceerror|syntaxerror/i;

/* ---------------------------------------------------------------------- */
/* Small helpers                                                            */
/* ---------------------------------------------------------------------- */

const count = (page, selector) => page.$$eval(selector, (items) => items.length);
const textOf = (page, selector) => page.$eval(selector, (element) => element.innerText.replace(/\s+/g, " ").trim());
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function shot(ctx, page, name) {
  if (!ctx.options.shots) return;

  fs.mkdirSync(ctx.options.shots, { recursive: true });
  await page.screenshot({ path: path.join(ctx.options.shots, `${name}.png`), fullPage: true });
}

async function newPage(ctx, label, contextOptions = {}) {
  const context = await ctx.browser.newContext({
    viewport: { width: 1280, height: 900 },
    timezoneId: "Africa/Lagos",
    acceptDownloads: true,
    ...contextOptions
  });

  context.setDefaultTimeout(10_000);

  const page = await context.newPage();

  watchPage(page, label, ctx.reporter);

  return { context, page };
}

/* Press something that starts a download and keep the file. */
async function saveDownload(ctx, who, press, { stepUp = false } = {}) {
  if (stepUp) expireStepUp(ctx.server);

  const waiting = who.page.waitForEvent("download", { timeout: 20_000 });

  await press();

  if (stepUp) await answerStepUpIfAsked(ctx.server, who, { wait: 4000 });

  const download = await waiting;
  const target = path.join(ctx.downloads, `${Date.now()}-${download.suggestedFilename()}`);

  await download.saveAs(target);

  return { file: target, name: download.suggestedFilename() };
}

/* Run a command-line verifier exactly as an outside observer would. */
function runScript(script, scriptArgs) {
  const result = spawnSync(process.execPath, ["--disable-warning=ExperimentalWarning", path.join(ROOT, "scripts", script), ...scriptArgs], {
    encoding: "utf8"
  });

  return { status: result.status, output: `${result.stdout || ""}${result.stderr || ""}` };
}

/* Fetch with the signed-in browser's cookies, without the page seeing it. */
async function probe(who, pathname) {
  const response = await who.context.request.get(`${who.base}${pathname}`);
  let body = null;

  try {
    body = await response.json();
  } catch (error) {
    /* not JSON */
  }

  return { status: response.status(), body };
}

/* "2026-11-20T08:00" for an instant, as a wall clock in a named time zone. */
function wallClock(iso, timeZone) {
  const parts = Object.fromEntries(
    new Intl.DateTimeFormat("en-CA", {
      timeZone, year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hourCycle: "h23"
    }).formatToParts(new Date(iso)).map((part) => [part.type, part.value])
  );

  return `${parts.year}-${parts.month}-${parts.day}T${parts.hour}:${parts.minute}`;
}

/* An hour on a day about a month ahead, in the BROWSER's own time zone: both the typed text and the real instant. */
function futureMoment(page, hour) {
  return page.evaluate((chosenHour) => {
    const pad = (number) => String(number).padStart(2, "0");
    const date = new Date();

    date.setDate(date.getDate() + 30);
    date.setHours(chosenHour, 0, 0, 0);

    return {
      typed: `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:00`,
      iso: date.toISOString()
    };
  }, hour);
}

/* ---------------------------------------------------------------------- */
/* 1. Three officers sign in for the first time                            */
/* ---------------------------------------------------------------------- */

async function officersSignIn(ctx) {
  const { reporter, browser, server } = ctx;

  reporter.section("1. The three officers sign in for the first time (temporary password → own password → 2FA → recovery codes)");

  const accounts = readCredentials(server.dataDir);

  reporter.equal("the starter accounts are the three roles", Object.keys(accounts).sort(), ["electoral_officer", "results_officer", "technical_support"]);

  ctx.officers = {};

  for (const role of ["electoral_officer", "results_officer", "technical_support"]) {
    const who = await adminFirstSignIn(browser, server, accounts[role], reporter);

    who.context.setDefaultTimeout(10_000);
    ctx.officers[role] = who;

    reporter.check(`${role}: signed in and was shown 8 recovery codes`, who.recoveryCodes.length === 8, `got ${who.recoveryCodes.length}`);
  }

  ctx.electoral = ctx.officers.electoral_officer;
  ctx.results = ctx.officers.results_officer;
  ctx.tech = ctx.officers.technical_support;

  reporter.check(
    "the temporary-credentials file removes itself once all three have signed in",
    !fs.existsSync(path.join(server.dataDir, "INITIAL-ADMIN-CREDENTIALS.txt"))
  );

  reporter.flush("signing in");
}

/* ---------------------------------------------------------------------- */
/* 2. Every section, for every role                                         */
/* ---------------------------------------------------------------------- */

async function officerSections(ctx) {
  const { reporter } = ctx;

  reporter.section("2. Each role sees its own menu, and every section opens cleanly");

  for (const role of Object.keys(EXPECTED_MENU)) {
    const who = ctx.officers[role];
    const { page } = who;

    const menu = await page.$$eval(".admin-nav-button", (buttons) => buttons.map((button) => button.textContent.trim()));

    reporter.equal(`${role}: the menu holds exactly the sections the role needs`, menu, [...EXPECTED_MENU[role], "Logout"]);

    const ids = await page.$$eval(".admin-nav-button[data-view]", (buttons) => buttons.map((button) => button.dataset.view));
    const trouble = [];

    for (const id of ids) {
      await gotoView(page, id);

      const toasts = await toastTexts(page);
      const bodyText = await textOf(page, `#body-${id}`);
      const hidden = await hiddenViolations(page);

      if (toasts.some((item) => item.error)) trouble.push(`${id}: error pop-up “${toasts.find((item) => item.error).text}”`);
      if (bodyText.length < 20) trouble.push(`${id}: the section is empty`);
      if (hidden.length) trouble.push(`${id}: hidden but showing: ${hidden.join(", ")}`);

      await shot(ctx, page, `${role}-${id}`);
    }

    reporter.check(`${role}: all ${ids.length} sections open without errors or leftovers`, trouble.length === 0, trouble.join("\n"));
  }

  /* Hiding a button is only a courtesy; the server must refuse too. */
  const tech = ctx.tech;

  for (const forbidden of ["/api/admin/results", "/api/admin/students", "/api/admin/admins"]) {
    const answer = await probe(tech, forbidden);

    reporter.equal(`technical support is refused ${forbidden} by the server`, answer.status, 403);
  }

  const resultsOfficer = await probe(ctx.results, "/api/admin/students");

  reporter.equal("the results officer is refused the student list by the server", resultsOfficer.status, 403);

  /* Typing a section's address by hand must not open it either. */
  await tech.page.goto(`${ctx.server.base}/dashboard.html#results`);
  await tech.page.waitForSelector(".admin-nav-button[data-view]");
  await tech.page.waitForLoadState("networkidle");

  const landed = await tech.page.$eval(".admin-view.active-view", (element) => element.id);

  reporter.equal("technical support typing #results lands on its own first section", landed, "view-dashboard");

  /* The page must also work on a small screen. */
  await ctx.electoral.page.setViewportSize({ width: 390, height: 844 });

  const overflowing = [];

  const electoralViews = await ctx.electoral.page.$$eval(".admin-nav-button[data-view]", (buttons) => buttons.map((button) => button.dataset.view));

  for (const id of electoralViews) {
    await gotoView(ctx.electoral.page, id);

    const overflow = await horizontalOverflow(ctx.electoral.page);

    if (overflow > 1) overflowing.push(`${id} (${overflow}px too wide)`);
  }

  reporter.check("on a 390-pixel screen no section needs sideways scrolling of the whole page", overflowing.length === 0, overflowing.join(", "));

  await ctx.electoral.page.setViewportSize({ width: 1280, height: 900 });

  reporter.flush("opening every section");
}

/* ---------------------------------------------------------------------- */
/* 3. Positions and candidates                                              */
/* ---------------------------------------------------------------------- */

async function candidatesFlow(ctx) {
  const { reporter } = ctx;
  const { page } = ctx.electoral;

  reporter.section("3. Positions and candidates");

  await gotoView(page, "candidates");

  reporter.check("the list is not locked before any ballot exists", !(await page.isVisible("#candidateLock")) && (await page.isVisible("#addOfficePanel")));

  const before = await count(page, ".office-panel");

  await page.fill("#newOffice", "Public Relations Officer");
  await page.fill("#newCandidate", "Chika Eze");
  await page.click("#addOfficeForm button[type=submit]");
  await waitForToast(page, /Position added/);
  await page.waitForFunction((expected) => document.querySelectorAll(".office-panel").length === expected, before + 1);

  reporter.equal("a new position appears", await count(page, ".office-panel"), before + 1);

  const panel = page.locator(".office-panel", { has: page.locator("h3", { hasText: "Public Relations Officer" }) });

  await panel.locator("[data-field='name']").fill("Dayo Ade");
  await panel.locator("[data-act='add-candidate']").click();
  await waitForToast(page, /Candidate added/);

  reporter.equal("a second candidate joins that position", await panel.locator("tbody tr").count(), 2);

  await panel.locator("[data-act='toggle-candidate']").first().click();
  await waitForToast(page, /set to pending/);

  reporter.check("making a candidate pending hides them from the ballot", /Pending/.test(await panel.innerText()));

  await panel.locator("[data-act='toggle-candidate']").first().click();
  await waitForToast(page, /approved for the ballot/);

  reporter.check("approving puts them back", !/Pending/.test(await panel.innerText()));

  await panel.locator("[data-act='add-candidate']").click();
  await page.waitForFunction(() => [...document.querySelectorAll("#toasts .toast--error")].some((item) => /full name/.test(item.textContent)));
  reporter.check("adding a candidate without a name is explained, not silently ignored", true);

  await panel.locator("tbody tr", { hasText: "Dayo Ade" }).locator("[data-act='remove-candidate']").click();
  await confirmDialogOk(page);
  await waitForToast(page, /Candidate removed/);

  reporter.equal("removing a candidate asks first, then removes only that one", await panel.locator("tbody tr").count(), 1);

  ctx.officeCount = await count(page, ".office-panel");

  reporter.flush("editing positions and candidates");
}

/* ---------------------------------------------------------------------- */
/* 4. The student roster                                                    */
/* ---------------------------------------------------------------------- */

async function rosterFlow(ctx) {
  const { reporter, server } = ctx;
  const { page } = ctx.electoral;

  reporter.section("4. The student roster (item 1: digits only)");

  await gotoView(page, "students");

  await page.fill("#addMatric", "matric 152637");
  await page.fill("#addName", "Not A Student");
  await page.fill("#addEmail", "not.a.student@bouesti.edu.ng");
  await page.click("#studentAddForm button[type=submit]");

  reporter.check("“matric 152637” is refused with a digits-only message", /digits only/i.test(await textOf(page, "#studentAddMessage")), await textOf(page, "#studentAddMessage"));

  const before = await count(page, "#studentTable tbody tr");

  await page.fill("#addMatric", "152638");
  await page.fill("#addName", "Bola Ige");
  await page.fill("#addEmail", "bola.ige@bouesti.edu.ng");
  await page.click("#studentAddForm button[type=submit]");
  await waitForToast(page, /Student added/);

  reporter.equal("a digits-only matric number is added", await count(page, "#studentTable tbody tr"), before + 1);

  /* Import: one good line, one with a prefix (must be skipped), one good line. */
  await page.fill("#importText", [
    "matric,name,email",
    "152639, Chika Eze, chika.eze@bouesti.edu.ng",
    "matric 152640, Prefix Person, prefix.person@bouesti.edu.ng",
    "152641, Dayo Ade, dayo.ade@bouesti.edu.ng"
  ].join("\n"));

  expireStepUp(server);
  await page.click("#importRun");

  const asked = await answerStepUpIfAsked(server, ctx.electoral, { wait: 4000 });

  reporter.check("importing a list asks for a fresh 2FA code", asked);

  await page.waitForFunction(() => /added/.test(document.getElementById("importResult").textContent));

  const importText = await textOf(page, "#importResult");

  reporter.check("the import adds two lines and skips the one with a prefix", /2 added, 1 skipped/.test(importText) && /Line 3/.test(importText), importText);

  const download = await saveDownload(ctx, ctx.electoral, () => page.click("#body-students [data-act='export']"), { stepUp: true });
  const raw = fs.readFileSync(download.file);

  reporter.check("the roster file opens correctly in a spreadsheet (starts with a byte-order mark)", raw[0] === 0xef && raw[1] === 0xbb && raw[2] === 0xbf);

  const lines = raw.toString("utf8").replace(/^\uFEFF/, "").trim().split(/\r?\n/);

  reporter.equal("its header row", lines[0], "matric,name,email,registered,verified,voted,active");
  reporter.check("every matric number in it is digits only", lines.slice(1).every((line) => /^\d{4,15},/.test(line)), lines.join("\n"));

  await page.click("#studentFilters [data-filter='voted']");
  await page.waitForTimeout(300);
  reporter.check("the “Voted” filter works before anyone has voted", (await count(page, "#studentTable tbody tr")) === 0);
  await page.click("#studentFilters [data-filter='all']");

  await page.fill("#studentSearch", "bola");
  await page.waitForFunction(() => document.querySelectorAll("#studentTable tbody tr").length === 1);
  reporter.check("searching finds a student by name", /Bola Ige/.test(await textOf(page, "#studentTable")));
  await page.fill("#studentSearch", "");

  reporter.flush("managing the roster");
}

/* ---------------------------------------------------------------------- */
/* 5. A student votes (phone-sized screen)                                  */
/* ---------------------------------------------------------------------- */

async function studentJourney(ctx) {
  const { reporter, server } = ctx;

  reporter.section("5. A student votes, on a phone-sized screen (items 1 and 2)");

  const { context, page } = await newPage(ctx, "student", { viewport: { width: 390, height: 844 } });

  await page.goto(server.base);
  await page.waitForSelector("#loginForm");

  reporter.check("the page says voting is open", /open/i.test(await page.textContent("#electionStatusText")));
  reporter.check("the rehearsal banner shows while the system is in rehearsal", await page.isVisible("#rehearsalBanner"));
  reporter.equal("nothing marked [hidden] is showing", await hiddenViolations(page), []);
  reporter.check("no sideways scrolling on a phone", (await horizontalOverflow(page)) <= 1);

  await shot(ctx, page, "student-1-home");

  /* Item 1: a prefix is refused. */
  await page.fill("#matricNumber", "matric 152637");
  await page.fill("#password", "password1");
  await page.click("#loginButton");

  const prefixMessage = (await textOf(page, "#loginMessage"));

  reporter.check("“matric 152637” is refused, with the reason", /digits only/i.test(prefixMessage) && (await page.isVisible("#loginPanel")), prefixMessage);

  /* Item 2: any other password is refused. */
  await page.fill("#matricNumber", "152637");
  await page.fill("#password", "Password1");
  await page.click("#loginButton");
  await page.waitForFunction(() => /incorrect/i.test(document.getElementById("loginMessage").textContent));

  reporter.check("any password except password1 is refused", (await page.isVisible("#loginPanel")) && !(await page.evaluate(() => document.getElementById("rulesDialog").open)));

  await page.fill("#password", "password1");
  await page.click("#loginButton");
  await page.waitForSelector("#rulesDialog[open]");

  reporter.check("the rules cannot be accepted before they are read", await page.isDisabled("#acceptRules"));

  await shot(ctx, page, "student-2-rules");

  await page.evaluate(() => {
    const body = document.getElementById("rulesBody");

    body.scrollTop = body.scrollHeight;
    body.dispatchEvent(new Event("scroll"));
  });

  await page.waitForFunction(() => !document.getElementById("agreeRules").disabled);
  await page.check("#agreeRules");
  await page.click("#acceptRules");

  await page.waitForSelector("#verifyPanel.active-panel");
  await page.fill("#universityEmail", "ada.obi@bouesti.edu.ng");
  await page.click("#sendCodeButton");
  await page.waitForSelector("#otpPanel.active-panel");

  reporter.check("the e-mail address is masked on the code page", /•/.test(await page.textContent("#maskedEmail")), await page.textContent("#maskedEmail"));
  reporter.check("a five-minute countdown is running", /^0[45]:\d\d$/.test((await page.textContent("#timer")).trim()), await page.textContent("#timer"));
  reporter.check("“Resend code” waits out a cooldown", (await page.isDisabled("#resendButton")) && /\(\d+s\)/.test(await page.textContent("#resendButton")));

  await page.fill("#otpInput", "123456");
  await page.click("#verifyButton");
  await page.waitForSelector("#ballotPanel.active-panel");

  const cards = await count(page, "#ballotPositions .candidate");
  const positions = await page.$$eval("#ballotPositions input[type=radio]", (inputs) => [...new Set(inputs.map((input) => input.name))]);

  reporter.equal("the ballot shows every position the officers set up", positions.length, ctx.officeCount);
  reporter.check("and a card for every approved candidate", cards > positions.length, `${cards} cards for ${positions.length} positions`);
  reporter.check("the ballot fits a phone screen", (await horizontalOverflow(page)) <= 1);

  await shot(ctx, page, "student-3-ballot");

  for (const name of positions) {
    await page.check(`#ballotPositions input[name="${name}"] >> nth=0`, { force: true });
  }

  await page.click("#ballotForm button[type=submit]");
  await page.waitForSelector("#reviewPanel.active-panel");
  await page.check("#confirmVote");
  await page.click("#submitVote");
  await page.waitForSelector("#successPanel.active-panel");

  ctx.receipt = (await page.textContent("#receiptId")).trim();

  reporter.check("a receipt number is shown", /^BOUESTI-/.test(ctx.receipt), ctx.receipt);

  await shot(ctx, page, "student-4-receipt");

  await page.click("#returnHomeButton");
  await page.waitForSelector("#loginPanel.active-panel");

  reporter.check("“Return home” shows the login page with a confirmation banner", await page.isVisible("#voteConfirmation"));
  reporter.equal("nothing marked [hidden] is showing afterwards", await hiddenViolations(page), []);

  /* The same student cannot vote twice. */
  await page.fill("#matricNumber", "152637");
  await page.fill("#password", "password1");
  await page.click("#loginButton");
  await page.waitForSelector("#alreadyVotedNotice:not([hidden])");

  reporter.check("a second sign-in is stopped before the rules page", !(await page.evaluate(() => document.getElementById("rulesDialog").open)));

  await shot(ctx, page, "student-5-already-voted");

  /* Help: receipt check and problem report. */
  await page.click("#helpButton");
  await page.waitForSelector("#helpDialog[open]");
  await page.fill("#receiptInput", ctx.receipt);
  await page.click("#receiptForm button[type=submit]");
  await page.waitForFunction(() => document.getElementById("receiptStatus").textContent.trim().length > 0);

  reporter.check("the receipt can be checked, and says nothing about the choice", /accepted/.test(await textOf(page, "#receiptStatus")) && !/president|candidate/i.test(await textOf(page, "#receiptStatus")));

  await page.fill("#problemMessage", "My code arrived late during the browser check.");
  await page.click("#problemForm button[type=submit]");
  await page.waitForFunction(() => /received/i.test(document.getElementById("problemStatus").textContent));

  reporter.check("a problem report is accepted", true);

  await context.close();

  reporter.flush("a student voted");
}

/* ---------------------------------------------------------------------- */
/* 6. Notices and student reports                                           */
/* ---------------------------------------------------------------------- */

async function noticesFlow(ctx) {
  const { reporter, server } = ctx;
  const { page } = ctx.electoral;

  reporter.section("6. Notices to students, and problems they report");

  const student = await newPage(ctx, "student (reading notices)", { viewport: { width: 390, height: 844 } });

  await student.page.goto(server.base);
  await student.page.waitForSelector("#loginForm");
  reporter.check("no notice is showing at first", !(await student.page.isVisible("#announcementBanner")));

  await gotoView(page, "notifications");
  await page.click("#noticeTemplates [data-template='1']");
  reporter.check("a ready-made wording fills the box", /closes soon/i.test(await page.inputValue("#noticeText")));

  await page.click("#noticeForm button[type=submit]");
  await waitForToast(page, /Notice posted/);

  await student.page.evaluate(() => refreshPublicState());
  await student.page.waitForSelector("#announcementBanner:not([hidden])");

  reporter.check("students see the notice on the voting page", /closes soon/i.test(await textOf(student.page, "#announcementText")));

  await student.page.click("#dismissAnnouncement");
  reporter.check("a student can dismiss it", !(await student.page.isVisible("#announcementBanner")));
  reporter.equal("nothing marked [hidden] is showing", await hiddenViolations(student.page), []);

  await page.click("#body-notifications [data-act='clear-notice']");
  await waitForToast(page, /removed from the voting page/);
  await student.context.close();

  reporter.check("the officer can take the notice down", /No notice is showing/.test(await textOf(page, "#noticeCurrent")));

  /* The results officer may read notices but not post them. */
  await gotoView(ctx.results.page, "notifications");
  reporter.check("the results officer has no posting form", (await count(ctx.results.page, "#noticeForm")) === 0);

  /* The technical officer handles what students reported. */
  const tech = ctx.tech.page;

  await gotoView(tech, "notifications");
  await tech.waitForSelector("#inboxPanel:not([hidden])");

  const inbox = await textOf(tech, "#inboxTable");

  reporter.check("the student's report is in the inbox", /code arrived late/.test(inbox), inbox);

  await tech.click("#inboxTable [data-act='report'][data-status='seen']");
  await tech.waitForFunction(() => /Seen/.test(document.getElementById("inboxTable").textContent));
  await tech.click("#inboxTable [data-act='report'][data-status='resolved']");
  await tech.waitForFunction(() => /Resolved/.test(document.getElementById("inboxTable").textContent));

  reporter.check("a report can be marked seen, then resolved", true);

  reporter.flush("posting notices and handling reports");
}

/* ---------------------------------------------------------------------- */
/* 7. The election form (item 8)                                            */
/* ---------------------------------------------------------------------- */

async function electionFlow(ctx) {
  const { reporter, server } = ctx;
  const { page } = ctx.electoral;

  reporter.section("7. The election form: dates, status and name stay put (item 8)");

  await gotoView(page, "election");

  const read = () => page.evaluate(() => ({
    name: document.getElementById("electionName").value,
    opens: document.getElementById("votingOpensAt").value,
    closes: document.getElementById("votingClosesAt").value,
    status: (document.querySelector("input[name='electionStatus']:checked") || {}).value || null
  }));

  const opens = await futureMoment(page, 8);
  const closes = await futureMoment(page, 18);

  await page.fill("#electionName", "BOUESTI SUG Election 2026/27");
  await page.fill("#votingOpensAt", opens.typed);
  await page.fill("#votingClosesAt", closes.typed);
  await page.click("label.status-option:has(input[value='upcoming'])");

  const typed = await read();

  reporter.equal("what was typed is in the form", typed, { name: "BOUESTI SUG Election 2026/27", opens: opens.typed, closes: closes.typed, status: "upcoming" });

  await page.evaluate(() => pollElection());
  await page.evaluate(() => pollElection());

  reporter.equal("two background refreshes leave the typed values alone (the reported bug)", await read(), typed);

  if (options.slow) {
    reporter.info("waiting 17 seconds for a real background refresh…");
    await page.waitForTimeout(17_000);
    reporter.equal("a real background refresh leaves the typed values alone", await read(), typed);
  }

  await shot(ctx, page, "election-1-typed");

  /* Save: the status changes, so a fresh code is asked for. */
  expireStepUp(server);
  await page.click("#electionSave");

  reporter.check("changing the status asks for a fresh 2FA code", await answerStepUpIfAsked(server, ctx.electoral, { wait: 4000 }));

  await waitForToast(page, /Election saved/);

  reporter.equal("the saved values are still in the form", await read(), typed);

  const summary = await textOf(page, "#electionSummary");

  reporter.check("the summary says voting will open by itself at the opening time", /open it by itself/.test(summary), summary);

  const stored = (await probe(ctx.electoral, "/api/admin/election")).body.election;

  reporter.equal("the server stored the instants (UTC)", { name: stored.name, status: stored.status, opens: stored.votingOpensAt, closes: stored.votingClosesAt }, {
    name: "BOUESTI SUG Election 2026/27", status: "upcoming", opens: opens.iso, closes: closes.iso
  });

  await shot(ctx, page, "election-2-saved");

  /* Another browser in another time zone sees the same instants as its own wall clock. */
  const newYork = await adminSignIn(ctx.browser, server, ctx.electoral, reporter, { timezoneId: "America/New_York" });

  newYork.context.setDefaultTimeout(10_000);
  await gotoView(newYork.page, "election");

  const seenInNewYork = await newYork.page.evaluate(() => ({
    opens: document.getElementById("votingOpensAt").value,
    closes: document.getElementById("votingClosesAt").value
  }));

  reporter.equal(
    "the same instants show in New York as New York wall-clock time",
    seenInNewYork,
    { opens: wallClock(opens.iso, "America/New_York"), closes: wallClock(closes.iso, "America/New_York") }
  );

  await newYork.context.close();

  /* A reload keeps everything. */
  await page.reload();
  await page.waitForSelector(".admin-nav-button[data-view]");
  await gotoView(page, "election");

  reporter.equal("after reloading the page the values are the same", await read(), typed);

  /* A name-only change is not a status change: no 2FA dialog, and nothing else moves. */
  await page.fill("#electionName", "BOUESTI SUG Election 2026/27 (final)");
  await page.click("#electionSave");
  await waitForToast(page, /Election saved/);

  reporter.check("a name-only change does not ask for a 2FA code", !(await page.evaluate(() => document.getElementById("stepUpDialog").open)));
  reporter.equal("and nothing else changes", await read(), { ...typed, name: "BOUESTI SUG Election 2026/27 (final)" });

  /* Discard puts the saved values back. */
  await page.fill("#electionName", "typed and then discarded");
  await page.click("#electionDiscard");

  reporter.equal("“Discard” restores the saved values", (await read()).name, "BOUESTI SUG Election 2026/27 (final)");

  /* An impossible calendar is explained and nothing is lost. */
  const earlier = await futureMoment(page, 7);

  await page.fill("#votingOpensAt", closes.typed);
  await page.fill("#votingClosesAt", earlier.typed);
  await page.click("#electionSave");
  await page.waitForFunction(() => document.getElementById("electionMessage").textContent.trim().length > 0);

  reporter.check("closing before opening is explained", /later than the opening/.test(await textOf(page, "#electionMessage")), await textOf(page, "#electionMessage"));
  reporter.equal("and what was typed is kept", { opens: (await read()).opens, closes: (await read()).closes }, { opens: closes.typed, closes: earlier.typed });

  await page.click("#electionDiscard");

  /* Clearing both dates. */
  await page.fill("#votingOpensAt", "");
  await page.fill("#votingClosesAt", "");
  await page.click("#electionSave");
  await waitForToast(page, /Election saved/);

  reporter.equal("both dates can be cleared", { opens: (await read()).opens, closes: (await read()).closes }, { opens: "", closes: "" });

  /* An opening time already in the past must not silently promise an automatic opening. */
  const past = await page.evaluate(() => {
    const pad = (number) => String(number).padStart(2, "0");
    const date = new Date(Date.now() - 3 * 24 * 3600 * 1000);

    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:00`;
  });

  await page.fill("#votingOpensAt", past);
  await page.click("#electionSave");
  await waitForToast(page, /Election saved/);
  await page.waitForFunction(() => document.getElementById("electionMessage").textContent.trim().length > 0).catch(() => {});

  reporter.check(
    "an opening time that has already passed says voting will not open by itself",
    /will not open by itself/.test(await textOf(page, "#electionMessage")),
    await textOf(page, "#electionMessage")
  );

  await page.fill("#votingOpensAt", "");
  await page.click("#electionSave");
  await waitForToast(page, /Election saved/);

  /* Back to Active (needs a fresh code again). */
  await page.click("label.status-option:has(input[value='active'])");
  expireStepUp(server);
  await page.click("#electionSave");
  await answerStepUpIfAsked(server, ctx.electoral, { wait: 4000 });
  await page.waitForFunction(() => /Voting open/.test(document.getElementById("electionPills").textContent));

  reporter.check("choosing Active opens voting again", true);

  reporter.equal("nothing marked [hidden] is showing", await hiddenViolations(page), []);

  reporter.flush("editing the election");
}

/* ---------------------------------------------------------------------- */
/* 8. Settings, administrators                                              */
/* ---------------------------------------------------------------------- */

async function settingsFlow(ctx) {
  const { reporter, server } = ctx;
  const { page } = ctx.electoral;

  reporter.section("8a. Settings");

  await gotoView(page, "settings");

  await page.fill("#schoolName", "Bamidele Olumilua University");
  await page.click("#settingsSave");
  await waitForToast(page, /Settings saved/);

  reporter.equal("the school name is saved", await page.inputValue("#schoolName"), "Bamidele Olumilua University");

  await page.fill("#schoolName", "typed and then discarded");
  await page.click("#settingsDiscard");

  reporter.equal("“Discard changes” puts it back", await page.inputValue("#schoolName"), "Bamidele Olumilua University");

  /* Who may sign in: changing it asks for a fresh code. Start from whatever the system has now. */
  const original = await page.$eval("input[name='rosterMode']:checked", (radio) => radio.value);
  const other = original === "open" ? "closed" : "open";

  await page.check(`input[name='rosterMode'][value='${other}']`, { force: true });
  expireStepUp(server);
  await page.click("#settingsSave");

  reporter.check("changing who may sign in asks for a fresh 2FA code", await answerStepUpIfAsked(server, ctx.electoral, { wait: 4000 }));

  await waitForToast(page, /Settings saved/);

  reporter.check(`the new setting (${other} roster) is kept`, await page.isChecked(`input[name='rosterMode'][value='${other}']`));

  await page.check(`input[name='rosterMode'][value='${original}']`, { force: true });
  await page.click("#settingsSave");
  await waitForToast(page, /Settings saved/);

  reporter.check(`and it can be put back (${original} roster)`, await page.isChecked(`input[name='rosterMode'][value='${original}']`));

  reporter.flush("changing settings");
}

async function adminsFlow(ctx) {
  const { reporter, server } = ctx;
  const { page } = ctx.electoral;

  reporter.section("8b. Administrator accounts");

  await gotoView(page, "admins");

  reporter.equal("the three starter officers are listed", await count(page, "#adminTable tbody tr"), 3);
  reporter.check("the role table explains each role", (await count(page, "#rolesTable tbody tr")) === 3);

  await page.fill("#newAdminEmail", "new.officer@bouesti.ng");
  await page.fill("#newAdminName", "New Officer");
  await page.selectOption("#newAdminRole", "results_officer");

  expireStepUp(server);
  await page.click("#adminAddForm button[type=submit]");

  reporter.check("creating an account asks for a fresh 2FA code", await answerStepUpIfAsked(server, ctx.electoral, { wait: 4000 }));

  const temporary = await takeSecret(page);

  reporter.check("a one-time password is shown once", temporary.length >= 12, temporary);

  await page.waitForFunction(() => document.querySelectorAll("#adminTable tbody tr").length === 4);

  reporter.equal("the new account is listed", await count(page, "#adminTable tbody tr"), 4);
  reporter.check("and is marked as not having chosen a password yet", /Password not chosen yet/.test(await textOf(page, "#adminTable")));

  tolerate(page, 400, /\/api\/admin\/admins$/, { once: true });

  await page.fill("#newAdminEmail", "new.officer@bouesti.ng");
  await page.fill("#newAdminName", "Duplicate");
  await page.click("#adminAddForm button[type=submit]");
  await page.waitForFunction(() => document.getElementById("adminAddMessage").textContent.trim().length > 0);

  reporter.check("the same e-mail cannot be used twice", /already|exists|in use/i.test(await textOf(page, "#adminAddMessage")), await textOf(page, "#adminAddMessage"));

  /* The new officer signs in for the first time through the real page. */
  ctx.newOfficer = await adminFirstSignIn(ctx.browser, server, {
    role: "results_officer", email: "new.officer@bouesti.ng", temporaryPassword: temporary
  }, reporter);

  ctx.newOfficer.context.setDefaultTimeout(10_000);

  ctx.newOfficerIdentity = {
    role: "results_officer",
    email: ctx.newOfficer.email,
    password: ctx.newOfficer.password,
    secret: ctx.newOfficer.secret
  };

  const menu = await ctx.newOfficer.page.$$eval(".admin-nav-button", (buttons) => buttons.map((button) => button.textContent.trim()));

  reporter.equal("the new results officer gets the results officer's menu", menu, [...EXPECTED_MENU.results_officer, "Logout"]);

  /* Stop the new officer's page polling, so the sign-out below does not look like a fault on that page. */
  await ctx.newOfficer.page.goto("about:blank");

  await gotoView(page, "admins");
  await page.waitForFunction(() => !/Password not chosen yet/.test(document.getElementById("adminTable").textContent));

  reporter.check("the account list now shows two-factor as on for the new officer", true);

  /* A reset code. */
  const row = page.locator("#adminTable tbody tr", { hasText: "new.officer@bouesti.ng" });

  expireStepUp(server);
  await row.locator("[data-act='reset-password']").click();
  await confirmDialogOk(page);

  reporter.check("issuing a password-reset code asks for a fresh 2FA code", await answerStepUpIfAsked(server, ctx.electoral, { wait: 4000 }));

  const resetCode = await takeSecret(page);

  reporter.check("a one-time reset code is shown", resetCode.length >= 8, resetCode);

  await page.waitForFunction(() => /active|pending/i.test(document.getElementById("resetsTable").textContent));

  reporter.check("and is listed with its expiry", /active|pending/i.test(await textOf(page, "#resetsTable")), await textOf(page, "#resetsTable"));

  /* Sign-in history. */
  await row.locator("[data-act='history']").click();

  const history = await takeInfo(page);

  reporter.check("sign-in history opens and names the account", /new\.officer@bouesti\.ng/.test(history.title), history.title);

  /* Disable and enable. */
  await row.locator("[data-act='disable']").click();
  await confirmDialogOk(page);
  await answerStepUpIfAsked(server, ctx.electoral, { wait: 1500 });
  await waitForToast(page, /Account disabled/);

  reporter.check("a disabled account is marked as such", /Disabled/.test(await textOf(page, "#adminTable")));

  await row.locator("[data-act='disable']").click();
  await confirmDialogOk(page);
  await answerStepUpIfAsked(server, ctx.electoral, { wait: 1500 });
  await waitForToast(page, /Account enabled/);

  /* Change the role (signs the person out) and back. */
  await row.locator("select[data-role-for]").selectOption("technical_support");
  await confirmDialogOk(page);
  await answerStepUpIfAsked(server, ctx.electoral, { wait: 1500 });
  await waitForToast(page, /Role changed/);

  reporter.check("a role change is applied", /Technical Support/.test(await row.locator("select[data-role-for]").evaluate((element) => element.options[element.selectedIndex].textContent)));

  await row.locator("select[data-role-for]").selectOption("results_officer");
  await confirmDialogOk(page);
  await answerStepUpIfAsked(server, ctx.electoral, { wait: 1500 });
  await waitForToast(page, /Role changed/);

  /* A role change signs the person out; they sign in again with their password and a code. */
  const signedOut = await probe(ctx.newOfficer, "/api/admin/session");

  reporter.equal("changing someone's role signs them out", signedOut.body && signedOut.body.signedIn, false);

  await ctx.newOfficer.context.close();

  reporter.flush("managing administrators");
}

/* ---------------------------------------------------------------------- */
/* 8c. Operations                                                           */
/* ---------------------------------------------------------------------- */

async function operationsFlow(ctx) {
  const { reporter, server } = ctx;
  const { page } = ctx.tech;

  reporter.section("8c. Operations: monitoring, backups, restore test, audit copy, incidents");

  await gotoView(page, "ops");

  reporter.check("the monitoring panel shows a health status", /All good|Needs attention|Critical/.test(await textOf(page, "#opsHealthPill")));
  reporter.check("and a full set of numbers", (await count(page, "#opsMetrics .stat-card")) >= 12);
  reporter.check("the go-live checklist is listed", (await count(page, "#opsReadiness .check-row")) >= 5);
  reporter.check("technical support cannot press “Go live”", (await count(page, "[data-act='golive']")) === 0);

  const electoralOps = ctx.electoral.page;

  await gotoView(electoralOps, "ops");
  reporter.check("the electoral officer's “Go live” stays disabled until the checklist is complete", await electoralOps.isDisabled("[data-act='golive']"));

  /* A person confirms a thing a computer cannot check. */
  const confirmButton = page.locator("#opsReadiness [data-act='confirm']").first();

  await confirmButton.click();
  await page.waitForFunction(() => /Un-confirm/.test(document.getElementById("opsReadiness").textContent));

  reporter.check("a manual checklist item can be confirmed", true);

  await page.click("#opsReadiness [data-act='confirm'][data-confirmed='true']");
  await page.waitForFunction(() => !/Un-confirm/.test(document.getElementById("opsReadiness").textContent));

  /* Backup. */
  await page.click("[data-act='backup']");
  await waitForToast(page, /Backup saved/);
  await page.waitForFunction(() => document.querySelectorAll("#backupsTable tbody tr").length >= 1);

  reporter.equal("a backup appears in the list", await count(page, "#backupsTable tbody tr"), 1);
  reporter.check("and is marked OK", /OK/.test(await textOf(page, "#backupsTable")));

  /* Restore test. */
  await page.click("[data-act='drill']");

  const drill = await takeInfo(page);

  reporter.check("the restore test passes", /passed/i.test(drill.title), `${drill.title}\n${drill.text}`);
  reporter.check("and lists the checks it made", (drill.text.match(/✓/g) || []).length >= 4, drill.text);

  await page.waitForFunction(() => /Passed/.test(document.getElementById("drillsTable").textContent));

  /* Read-only audit copy. */
  await page.click("[data-act='auditcopy']");
  await waitForToast(page, /Audit copy saved/);
  await page.waitForFunction(() => document.querySelectorAll("#auditCopiesTable tbody tr").length >= 1);

  reporter.equal("an audit copy appears in the list", await count(page, "#auditCopiesTable tbody tr"), 1);

  /* Downloads need a fresh code. */
  const backupDownload = await saveDownload(ctx, ctx.tech, () => page.click("#backupsTable [data-act='get-backup']:not([data-manifest])"), { stepUp: true });

  reporter.check("the backup file downloads, and is encrypted (not a plain SQLite file)", fs.statSync(backupDownload.file).size > 1000 && !fs.readFileSync(backupDownload.file).subarray(0, 15).toString("latin1").startsWith("SQLite format 3"));

  const manifestDownload = await saveDownload(ctx, ctx.tech, () => page.click("#backupsTable [data-act='get-backup'][data-manifest]"));
  const manifest = JSON.parse(fs.readFileSync(manifestDownload.file, "utf8"));

  reporter.check("its manifest is readable JSON that names the file", Boolean(manifest) && typeof manifest === "object");

  /* Test e-mail. */
  await page.fill("#testMailTo", "someone@bouesti.edu.ng");
  await page.click("#testMailForm button[type=submit]");
  await page.waitForFunction(() => document.getElementById("testMailMessage").textContent.trim().length > 0);

  reporter.check("the test e-mail button answers (in demo mode it says nothing was sent)", (await textOf(page, "#testMailMessage")).length > 10, await textOf(page, "#testMailMessage"));

  /* Incidents. */
  await page.fill("#incidentTitle", "Verification codes arriving late");
  await page.fill("#incidentDetails", "Several students reported waiting more than three minutes.");
  await page.click("#incidentForm button[type=submit]");
  await waitForToast(page, /Incident #\d+ opened/);

  reporter.equal("an incident is recorded", await count(page, "#incidentList tbody tr"), 1);

  await page.click("#incidentList [data-act='incident'][data-status='investigating']");
  await page.waitForFunction(() => /investigating/i.test(document.getElementById("incidentList").textContent));

  await page.click("#incidentList [data-act='incident'][data-status='resolved']");
  await promptDialogOk(page, "Mail provider recovered; codes arrive in seconds.");
  await page.waitForFunction(() => /Resolution:/.test(document.getElementById("incidentList").textContent));

  reporter.check("an incident moves from open to investigating to resolved, with the reason kept", true);
  reporter.check("the open-incident counter goes back to zero", /0 open/.test(await textOf(page, "#incidentCount")), await textOf(page, "#incidentCount"));

  reporter.flush("running operations");
}

/* ---------------------------------------------------------------------- */
/* 9. The audit log                                                         */
/* ---------------------------------------------------------------------- */

async function auditFlow(ctx) {
  const { reporter, server } = ctx;
  const { page } = ctx.electoral;

  reporter.section("9. The audit log: restricted, tamper-evident, and free of anyone's choice");

  await gotoView(page, "audit");

  reporter.check("entries are listed", (await count(page, "#auditTable tbody tr")) > 5);
  reporter.check("the newest entry number is shown", /Latest entry #\d+/.test(await textOf(page, "#auditHead")));
  reporter.check("kinds of event can be filtered", (await count(page, "#auditCategory option")) > 2);

  await page.fill("#auditSearch", "backup");
  await page.click("#auditForm button[type=submit]");
  await page.waitForFunction(() => {
    const rows = [...document.querySelectorAll("#auditTable tbody tr")];

    return rows.length > 0 && rows.every((row) => /backup/i.test(row.innerText));
  });

  const filtered = await page.$$eval("#auditTable tbody tr", (rows) => rows.map((row) => row.innerText));

  reporter.check("searching narrows the list to matching entries", filtered.length > 0 && filtered.every((text) => /backup/i.test(text)));

  await page.fill("#auditSearch", "");
  await page.click("#auditForm button[type=submit]");
  await page.waitForFunction(() => document.querySelectorAll("#auditTable tbody tr").length > 5);

  /* The whole visible log: no matric number, no choice. */
  const everything = await page.$$eval("#auditTable tbody tr", (rows) => rows.map((row) => row.innerText).join("\n"));

  reporter.check("no student's matric number appears anywhere in the log", !/15263[789]|15264[01]/.test(everything));
  reporter.check("the student appears only under a tag like v-1a2b3c4d5e", /\bv-[0-9a-f]{10}\b/.test(everything));

  /* One student's trail: needs a fresh code, shows only the tag. */
  await page.fill("#auditVoter", "matric 152637");
  await page.click("#auditForm button[type=submit]");
  await page.waitForFunction(() => [...document.querySelectorAll("#toasts .toast--error")].some((item) => /digits only/.test(item.textContent)));

  reporter.check("the trail box refuses anything but digits", true);

  await page.fill("#auditVoter", "152637");
  expireStepUp(server);
  await page.click("#auditForm button[type=submit]");

  reporter.check("following one student's trail asks for a fresh 2FA code", await answerStepUpIfAsked(server, ctx.electoral, { wait: 4000 }));

  await page.waitForFunction(() => /Latest entry/.test(document.getElementById("auditHead").textContent));

  const trail = await page.$$eval("#auditTable tbody tr", (rows) => rows.map((row) => row.innerText).join("\n"));

  reporter.check("the trail shows that student's events under the tag, not the number", trail.length > 0 && !/152637/.test(trail));

  await page.fill("#auditVoter", "");
  await page.click("#auditForm button[type=submit]");

  /* Integrity. */
  await page.click("#body-audit [data-act='verify']");
  await page.waitForFunction(() => /intact|FAILED/.test(document.getElementById("auditVerifyResult").textContent));

  reporter.check("verifying the whole chain says it is intact", /log is intact/.test(await textOf(page, "#auditVerifyResult")), await textOf(page, "#auditVerifyResult"));

  await page.click("#body-audit [data-act='checkpoints']");

  const checkpoints = await takeInfo(page);

  reporter.check("the signed-checkpoints list names the signing key's fingerprint", /fingerprint[^\n]*[0-9A-F]{4} [0-9A-F]{4}/i.test(checkpoints.text), checkpoints.text);

  await page.click("#body-audit [data-act='access']");

  const access = await takeInfo(page);

  reporter.check("reading the log is itself recorded, with the reader's name", /electoral@bouesti\.ng/.test(access.text), access.text.slice(0, 300));

  reporter.flush("reading the audit log");
}

async function statisticsFlow(ctx) {
  const { reporter } = ctx;
  const { page } = ctx.results;

  reporter.section("9b. Voting statistics");

  await gotoView(page, "statistics");

  reporter.check("statistics show counts", (await count(page, "#statCards .stat-card")) >= 3);

  const text = await textOf(page, "#body-statistics");

  reporter.check("they show how many voted, but never who", /Voted/.test(text) && !/15263\d|15264\d/.test(text) && !/BOUESTI-/.test(text));

  reporter.flush("reading statistics");
}

/* ---------------------------------------------------------------------- */
/* 10. Closing, two-person approval, independent verification              */
/* ---------------------------------------------------------------------- */

async function resultsFlow(ctx) {
  const { reporter, server } = ctx;
  const electoral = ctx.electoral;
  const results = ctx.results;

  reporter.section("10. Results: closing, the two-person rule, a signed report checked on its own, a supervised comparison");

  /* Before voting closes, results are sealed from publication. */
  await gotoView(results.page, "results");

  reporter.check("while voting is open the count is marked provisional", /Provisional count/.test(await textOf(results.page, "#resultsStatusPanel")));
  reporter.check("and a signed report cannot be prepared yet", (await count(results.page, "[data-act='prepare']")) === 0);

  /* Close voting. */
  await gotoView(electoral.page, "election");
  await electoral.page.click("label.status-option:has(input[value='closed'])");
  expireStepUp(server);
  await electoral.page.click("#electionSave");

  reporter.check("closing the election asks for a fresh 2FA code", await answerStepUpIfAsked(server, electoral, { wait: 4000 }));

  await electoral.page.waitForFunction(() => /Closed/.test(document.getElementById("electionPills").textContent));

  /* The Results Officer prepares. */
  await gotoView(results.page, "results");

  reporter.check("after closing the count is final", /Final count/.test(await textOf(results.page, "#resultsStatusPanel")));
  reporter.check("ballots, turnout records and receipts agree", /counts agree/.test(await textOf(results.page, "#resultsStatusPanel")), await textOf(results.page, "#resultsStatusPanel"));

  await results.page.click("[data-act='prepare']");
  await promptDialogOk(results.page, "Final count for the browser check.");
  await answerStepUpIfAsked(server, results, { wait: 4000 });
  await waitForToast(results.page, /Report #\d+ prepared and signed/);

  reporter.check("the Results Officer's own row says it is waiting for a different officer", /Waiting for a different officer/.test(await textOf(results.page, "#reportsTable")));
  reporter.equal("and offers no Approve button to the person who prepared it", await count(results.page, "#reportsTable [data-act='approve']"), 0);

  /* Nothing is public yet. */
  const student = await newPage(ctx, "student (reading results)", { viewport: { width: 390, height: 844 } });

  await student.page.goto(server.base);
  await student.page.waitForSelector("#loginForm");
  await student.page.evaluate(() => refreshPublicState());
  await student.page.waitForTimeout(400);

  reporter.check("students see no results before approval", !(await student.page.isVisible("#resultsSection")));

  /* A different officer approves. */
  await gotoView(electoral.page, "results");

  reporter.equal("the Electoral Officer sees the pending report with Approve and Reject", await count(electoral.page, "#reportsTable [data-act='approve'], #reportsTable [data-act='reject']"), 2);

  expireStepUp(server);
  await electoral.page.click("#reportsTable [data-act='approve']");
  await confirmDialogOk(electoral.page);

  reporter.check("approving asks for a fresh 2FA code", await answerStepUpIfAsked(server, electoral, { wait: 4000 }));

  await waitForToast(electoral.page, /approved and published/);

  /* Students now see the results. */
  await student.page.evaluate(() => refreshPublicState());
  await student.page.waitForSelector("#resultsSection:not([hidden])");

  reporter.equal("students see every position's result", await count(student.page, "#resultsBody .result-office"), ctx.officeCount);
  reporter.check("with the number of ballots counted", /1 ballot counted/.test(await textOf(student.page, "#resultsMeta")), await textOf(student.page, "#resultsMeta"));
  reporter.check("and the signing key's fingerprint", /Ed25519/.test(await textOf(student.page, "#resultsSignature")), await textOf(student.page, "#resultsSignature"));
  reporter.equal("nothing marked [hidden] is showing", await hiddenViolations(student.page), []);

  await shot(ctx, student.page, "student-6-results");
  await student.context.close();

  /* The signed report, checked on the page and then by the standalone program. */
  await gotoView(results.page, "results");

  const report = await saveDownload(ctx, results, () => results.page.click("#reportsTable [data-act='download']"));
  const envelope = JSON.parse(fs.readFileSync(report.file, "utf8"));

  reporter.check("the downloaded report is a signed envelope", /^bouesti-vote-signed-tally/.test(envelope.format || ""), Object.keys(envelope).join(", "));

  await results.page.setInputFiles("#verifyFile", report.file);
  await results.page.click("#verifyPanel [data-act='verify']");
  await results.page.waitForFunction(() => /passed|FAILED/.test(document.getElementById("verifyResult").textContent));

  reporter.check("the page's own “Check a downloaded report” says all checks passed", /All checks passed/.test(await textOf(results.page, "#verifyResult")), await textOf(results.page, "#verifyResult"));

  const fingerprint = (await results.page.textContent("#verifyResult .mono")).trim();

  /* Change one number in a copy: it must be caught. */
  const tampered = JSON.parse(fs.readFileSync(report.file, "utf8"));
  let changed = false;

  (function bump(value) {
    if (changed || !value || typeof value !== "object") return;

    for (const key of Object.keys(value)) {
      if (key === "votes" && typeof value[key] === "number") {
        value[key] += 1;
        changed = true;
        return;
      }

      bump(value[key]);
    }
  }(tampered));

  const tamperedFile = path.join(ctx.downloads, "tampered-report.json");

  fs.writeFileSync(tamperedFile, JSON.stringify(tampered));

  await results.page.setInputFiles("#verifyFile", tamperedFile);
  await results.page.click("#verifyPanel [data-act='verify']");
  await results.page.waitForFunction(() => /FAILED/.test(document.getElementById("verifyResult").textContent));

  reporter.check("a copy with one vote changed is caught", changed && /FAILED/.test(await textOf(results.page, "#verifyResult")));

  const cli = runScript("verify-report.js", [report.file, "--trusted-fingerprint", fingerprint]);

  reporter.check("the standalone verifier, on its own, agrees (exit 0)", cli.status === 0, cli.output.slice(-600));

  const cliTampered = runScript("verify-report.js", [tamperedFile, "--trusted-fingerprint", fingerprint]);

  reporter.check("and rejects the changed copy (exit 1)", cliTampered.status === 1, cliTampered.output.slice(-600));

  /* Supervised comparison with the live database. */
  /* The next two attempts are refused on purpose: the same person, then a wrong password. */
  tolerate(results.page, 400, /\/api\/admin\/results\/\d+\/compare$/, { once: true });
  tolerate(results.page, 400, /\/api\/admin\/results\/\d+\/compare$/, { once: true });

  await results.page.click("#reportsTable [data-act='compare']");
  await waitForDialog(results.page, "#witnessDialog");

  await results.page.fill("#witnessEmail", results.email);
  await results.page.fill("#witnessPassword", results.password);
  await results.page.fill("#witnessCode", freshCode(server, results.secret, results.email));
  await results.page.click("#witnessOk");
  await results.page.waitForFunction(() => document.getElementById("witnessMessage").textContent.trim().length > 0);

  reporter.check("the witness cannot be the person running the comparison", /different/i.test(await textOf(results.page, "#witnessMessage")), await textOf(results.page, "#witnessMessage"));

  await results.page.fill("#witnessEmail", electoral.email);
  await results.page.fill("#witnessPassword", "not-the-right-password");
  await results.page.fill("#witnessCode", freshCode(server, electoral.secret, electoral.email));
  await results.page.click("#witnessOk");
  await results.page.waitForFunction(() => /./.test(document.getElementById("witnessMessage").textContent) && document.getElementById("witnessPassword").value === "");

  reporter.check("a wrong witness password is refused", (await results.page.evaluate(() => document.getElementById("witnessDialog").open)));

  clearAdminLimits(server);

  await results.page.fill("#witnessPassword", electoral.password);
  await results.page.fill("#witnessCode", freshCode(server, electoral.secret, electoral.email));
  await results.page.click("#witnessOk");

  const comparison = await takeInfo(results.page);

  reporter.check("with a real second official the comparison finds a MATCH", /MATCH/.test(comparison.text) && !/MISMATCH/.test(comparison.text), comparison.text);

  await results.page.waitForFunction(() => /Match/.test(document.getElementById("comparisonsTable").textContent));
  await results.page.click("#comparisonsTable [data-act='details']");

  const details = await takeInfo(results.page);

  reporter.check("the comparison is kept, with who ran it and who witnessed it", /electoral@bouesti\.ng/.test(details.text) && /results@bouesti\.ng/.test(details.text), details.text);

  const csv = await saveDownload(ctx, results, () => results.page.click("#body-results [data-act='csv']"));

  reporter.check("the tally also downloads as a spreadsheet file", /position,candidate,votes/.test(fs.readFileSync(csv.file, "utf8")), fs.readFileSync(csv.file, "utf8").slice(0, 200));

  /* The audit log and a read-only audit copy, checked outside the system. */
  await gotoView(ctx.tech.page, "ops");
  await ctx.tech.page.click("[data-act='auditcopy']");
  await waitForToast(ctx.tech.page, /Audit copy saved/);

  const copy = await saveDownload(ctx, ctx.tech, () => ctx.tech.page.click("#auditCopiesTable tbody tr:first-child [data-act='get-copy']:not([data-manifest])"), { stepUp: true });

  const recount = runScript("verify-report.js", [report.file, "--trusted-fingerprint", fingerprint, "--audit-copy", copy.file]);

  reporter.check("the report recounted from the read-only audit copy gives the same totals (exit 0)", recount.status === 0, recount.output.slice(-800));

  await gotoView(results.page, "audit");

  const exported = await saveDownload(ctx, results, () => results.page.click("#body-audit [data-act='export']"), { stepUp: true });
  const auditCheck = runScript("verify-audit.js", [exported.file]);

  reporter.check("the exported audit log verifies on its own (exit 0)", auditCheck.status === 0, auditCheck.output.slice(-800));

  const copyCheck = runScript("verify-audit.js", [copy.file]);

  reporter.check("and so does the read-only audit copy (exit 0)", copyCheck.status === 0, copyCheck.output.slice(-800));

  /* Closing, preparing and publishing each left a signed checkpoint behind. */
  await gotoView(results.page, "audit");
  await results.page.click("#body-audit [data-act='checkpoints']");

  const checkpointsNow = await takeInfo(results.page);

  reporter.check("signed checkpoints now exist for the key moments", (checkpointsNow.text.match(/#\d+/g) || []).length >= 2, checkpointsNow.text);

  /* The log's exported text carries no ballot choices and no matric numbers. */
  const exportedText = fs.readFileSync(exported.file, "utf8");

  reporter.check("the exported audit log holds no matric number", !/15263[789]|15264[01]/.test(exportedText));

  reporter.flush("closing the election and publishing results");
}

/* ---------------------------------------------------------------------- */
/* 11. A new officer's own account                                          */
/* ---------------------------------------------------------------------- */

async function accountFlow(ctx) {
  const { reporter, server } = ctx;

  reporter.section("11. An officer's own account: password, recovery codes, sessions, signing out everywhere");

  if (!ctx.newOfficerIdentity) {
    reporter.check("the new officer exists (created in step 8b)", false, "step 8b did not get as far as creating the account");
    return;
  }

  /* The new officer was signed out by the role change; sign in again with a password and code. */
  const officer = await adminSignIn(ctx.browser, server, ctx.newOfficerIdentity, reporter);

  officer.context.setDefaultTimeout(10_000);

  const { page } = officer;

  await gotoView(page, "account");

  const facts = await textOf(page, "#accountFacts");

  reporter.check("the account page shows name, e-mail, role and two-factor status", /New Officer/.test(facts) && /new\.officer@bouesti\.ng/.test(facts) && /Results Officer/.test(facts) && /On/.test(facts), facts);
  reporter.check("the session list shows this device with real times (not dashes)", /This device/.test(await textOf(page, "#sessionsTable")) && !/—\s+—/.test(await textOf(page, "#sessionsTable")), await textOf(page, "#sessionsTable"));

  /* Password change. */
  tolerate(page, 400, /\/api\/admin\/password$/, { once: true });

  await page.fill("#currentPassword", "wrong-current-password");
  await page.fill("#changeNewPassword", "A-Brand-New-Passphrase-2026!");
  await page.fill("#changeNewPasswordAgain", "A-Different-Passphrase-2026!");
  await page.click("#passwordChangeSave");

  reporter.check("two different new passwords are caught before anything is sent", /not the same/.test(await textOf(page, "#passwordChangeMessage")), await textOf(page, "#passwordChangeMessage"));

  await page.fill("#changeNewPasswordAgain", "A-Brand-New-Passphrase-2026!");
  await page.click("#passwordChangeSave");
  await page.waitForFunction(() => document.getElementById("passwordChangeMessage").textContent.trim().length > 0);

  reporter.check("a wrong current password is refused", /current password|incorrect|wrong/i.test(await textOf(page, "#passwordChangeMessage")), await textOf(page, "#passwordChangeMessage"));

  await page.fill("#currentPassword", officer.password);
  await page.fill("#changeNewPassword", "A-Brand-New-Passphrase-2026!");
  await page.fill("#changeNewPasswordAgain", "A-Brand-New-Passphrase-2026!");
  await page.click("#passwordChangeSave");
  await page.waitForFunction(() => /changed/i.test(document.getElementById("passwordChangeMessage").textContent));

  officer.password = "A-Brand-New-Passphrase-2026!";

  reporter.check("the password is changed", true);

  /* Recovery codes. */
  expireStepUp(server);
  await page.click("#body-account [data-act='regenerate']");
  await confirmDialogOk(page);

  reporter.check("making new recovery codes asks for a fresh 2FA code", await answerStepUpIfAsked(server, officer, { wait: 4000 }));

  const codes = (await takeSecret(page)).split(/\s+/).filter(Boolean);

  reporter.equal("eight new recovery codes are shown once", codes.length, 8);
  reporter.check("the page says how many are unused", /8 unused/.test(await textOf(page, "#recoveryInfo")), await textOf(page, "#recoveryInfo"));

  /* Sign out everywhere. */
  await page.click("#body-account [data-act='logout-all']");
  await confirmDialogOk(page);
  await page.waitForURL(/\/admin(\.html)?(\?|$|#)/);

  reporter.check("“Sign out everywhere” returns to the sign-in page", /\/admin/.test(page.url()));

  const after = await probe(officer, "/api/admin/session");

  reporter.equal("and the session is really gone", after.body && after.body.signedIn, false);

  await officer.context.close();

  /* A recovery code works once, in place of the 6-digit code. */
  const viaRecovery = await newPage(ctx, "new officer (recovery code)");

  await viaRecovery.page.goto(`${server.base}/admin.html`);
  clearAdminLimits(server);
  await viaRecovery.page.fill("#adminEmail", officer.email);
  await viaRecovery.page.fill("#adminPassword", officer.password);
  await viaRecovery.page.click("#signinButton");
  await viaRecovery.page.waitForSelector("#totpPanel:not([hidden])");
  await viaRecovery.page.fill("#totpCode", codes[0]);
  await viaRecovery.page.click("#totpForm button[type=submit]");

  /* Using a recovery code shows a notice (how many are left) before the dashboard. */
  await viaRecovery.page.waitForSelector("#noticePanel:not([hidden])");

  reporter.check("using a recovery code says how many are left", /recovery code/i.test(await textOf(viaRecovery.page, "#noticeText")), await textOf(viaRecovery.page, "#noticeText"));

  await viaRecovery.page.click("#noticeContinue");
  await viaRecovery.page.waitForURL("**/dashboard.html");
  await viaRecovery.page.waitForSelector(".admin-nav-button[data-view]");

  reporter.check("a recovery code signs in when the phone is not to hand", true);

  await viaRecovery.page.click(".admin-nav-button.logout");
  await viaRecovery.page.waitForURL(/\/admin(\.html)?(\?|$|#)/);

  clearAdminLimits(server);
  tolerate(viaRecovery.page, 401, /\/api\/admin\/totp$/, { once: true });
  await viaRecovery.page.fill("#adminEmail", officer.email);
  await viaRecovery.page.fill("#adminPassword", officer.password);
  await viaRecovery.page.click("#signinButton");
  await viaRecovery.page.waitForSelector("#totpPanel:not([hidden])");
  await viaRecovery.page.fill("#totpCode", codes[0]);
  await viaRecovery.page.click("#totpForm button[type=submit]");
  await viaRecovery.page.waitForFunction(() => document.getElementById("totpMessage").textContent.trim().length > 0);

  reporter.check("but the same recovery code cannot be used a second time", /\/admin/.test(viaRecovery.page.url()) && !/dashboard/.test(viaRecovery.page.url()), viaRecovery.page.url());

  await viaRecovery.context.close();

  reporter.flush("using the account pages");
}

/* ---------------------------------------------------------------------- */
/* 12. Press the harmless buttons                                           */
/* ---------------------------------------------------------------------- */

/*
  Buttons that open a pop-up are pressed and the pop-up is cancelled; nothing is
  changed. The point is to find a handler that crashes ("x is not a function")
  in a corner nobody walked through.
*/
async function pokeFlow(ctx) {
  const { reporter } = ctx;

  reporter.section("12. Every harmless button is pressed once (pop-ups are cancelled)");

  const plan = [
    ["electoral_officer", "dashboard", ["[data-act='feed']"]],
    ["electoral_officer", "election", ["#modePanel [data-act='reset']"]],
    ["electoral_officer", "students", ["[data-act='remove']"]],
    ["electoral_officer", "results", ["[data-act='refresh']", "[data-act='details']"]],
    ["electoral_officer", "audit", ["[data-act='checkpoints']", "[data-act='access']"]],
    ["electoral_officer", "admins", ["[data-act='history']", "[data-act='disable']", "[data-act='reset-password']", "[data-act='reset-2fa']"]],
    ["electoral_officer", "ops", ["[data-act='drill-details']"]],
    ["results_officer", "results", ["[data-act='refresh']", "[data-act='details']"]],
    ["results_officer", "audit", ["[data-act='checkpoints']", "[data-act='access']"]],
    ["technical_support", "ops", ["[data-act='drill-details']"]],
    ["technical_support", "audit", ["[data-act='checkpoints']", "[data-act='access']"]]
  ];

  let pressed = 0;
  const trouble = [];

  for (const [role, view, selectors] of plan) {
    const { page } = ctx.officers[role];

    await gotoView(page, view);

    for (const selector of selectors) {
      const buttons = page.locator(`#body-${view} ${selector}`);
      const total = await buttons.count();

      for (let index = 0; index < Math.min(total, 2); index += 1) {
        const button = buttons.nth(index);

        if (!(await button.isVisible()) || !(await button.isEnabled())) continue;

        await button.click();
        pressed += 1;
        await page.waitForTimeout(250);

        /* Whatever opened, close it without doing anything. */
        for (const [dialog, cancel] of [["#stepUpDialog", "#stepUpCancel"], ["#confirmDialog", "#confirmCancel"], ["#promptDialog", "#promptCancel"], ["#infoDialog", "#infoClose"], ["#secretDialog", "#secretClose"]]) {
          if (await page.evaluate((id) => document.querySelector(id).open, dialog)) {
            await page.click(cancel);
            await page.waitForSelector(dialog, { state: "hidden" });
          }
        }

        const problems = (await toastTexts(page)).filter((item) => item.error && PROGRAMMING_ERROR.test(item.text));

        if (problems.length) trouble.push(`${role} › ${view} › ${selector}: ${problems[0].text}`);
      }
    }
  }

  reporter.check(`${pressed} buttons pressed; none of them crashed`, pressed > 15 && trouble.length === 0, trouble.join("\n") || `only ${pressed} pressed`);

  reporter.flush("pressing buttons");
}

/* ---------------------------------------------------------------------- */
/* When a step crashes                                                      */
/* ---------------------------------------------------------------------- */

const DIALOGS = [
  ["#stepUpDialog", "#stepUpCancel"], ["#confirmDialog", "#confirmCancel"], ["#promptDialog", "#promptCancel"],
  ["#witnessDialog", "#witnessCancel"], ["#infoDialog", "#infoClose"], ["#secretDialog", "#secretClose"]
];

function officerPages(ctx) {
  return Object.values(ctx.officers || {}).map((who) => who.page).filter((page) => !page.isClosed());
}

/* A pop-up left open blocks every later click, so say which one it was. */
async function describeOpenDialogs(ctx) {
  const open = [];

  for (const page of officerPages(ctx)) {
    for (const [dialog] of DIALOGS) {
      try {
        if (await page.evaluate((id) => Boolean(document.querySelector(id) && document.querySelector(id).open), dialog)) {
          open.push(`${dialog} is still open on ${page.url()}`);
        }
      } catch (error) {
        /* the page is gone */
      }
    }
  }

  return open.length ? `Left open: ${open.join("; ")}` : "No pop-up was left open.";
}

/* Let the later steps start from a clean screen. */
async function closeStrayDialogs(ctx) {
  for (const page of officerPages(ctx)) {
    for (const [dialog, cancel] of DIALOGS) {
      try {
        if (await page.evaluate((id) => Boolean(document.querySelector(id) && document.querySelector(id).open), dialog)) {
          await page.click(cancel, { timeout: 2000 });
        }
      } catch (error) {
        /* best effort */
      }
    }
  }
}

/* ---------------------------------------------------------------------- */
/* Run                                                                      */
/* ---------------------------------------------------------------------- */

async function main() {
  const reporter = new Reporter();
  const playwright = loadPlaywright();

  if (!playwright) {
    console.error([
      "The browser check needs Playwright, which is not part of the project.",
      "",
      "  npm install --no-save playwright",
      "  npx playwright install chromium",
      "",
      "or point at an existing copy:",
      "",
      "  PLAYWRIGHT_MODULE=/path/to/node_modules/playwright npm run test:browser",
      "  CHROMIUM_PATH=/path/to/chrome npm run test:browser"
    ].join("\n"));

    return 2;
  }

  let browser;

  try {
    browser = await launchChromium(playwright, { headed: options.headed });
  } catch (error) {
    console.error(`Could not start Chromium: ${error.message.split("\n")[0]}\n\nInstall one with:  npx playwright install chromium\nor set CHROMIUM_PATH to an existing browser.`);

    return 2;
  }

  console.log("BOUESTI Vote — real-browser check");
  console.log(`Chromium ${browser.version()}${options.slow ? " · slow mode" : ""}`);

  const server = await startServer();
  const downloads = fs.mkdtempSync(path.join(os.tmpdir(), "bouesti-browser-downloads-"));
  const ctx = { browser, server, reporter, options, downloads };

  console.log(`Throw-away server on ${server.base} (data in ${server.dataDir})`);

  const flows = [
    officersSignIn, officerSections, candidatesFlow, rosterFlow, studentJourney, noticesFlow, electionFlow,
    settingsFlow, adminsFlow, operationsFlow, auditFlow, statisticsFlow, resultsFlow, accountFlow, pokeFlow
  ];

  try {
    for (const flow of flows) {
      if (options.only && flow !== officersSignIn && !options.only.some((name) => flow.name.toLowerCase().startsWith(name.toLowerCase()))) continue;

      try {
        await flow(ctx);
      } catch (error) {
        const lines = (error.stack || String(error)).split("\n").slice(0, 28);

        reporter.check(`${flow.name} ran to the end`, false, `${lines.join("\n")}\n${await describeOpenDialogs(ctx)}`);
        reporter.flush(`${flow.name} crashed`);
        await closeStrayDialogs(ctx);
      }
    }
  } finally {
    await browser.close();
    await server.stop();
  }

  const code = reporter.finish();

  if (code !== 0) {
    console.log(`\nServer output (last lines):\n${server.output().split("\n").slice(-15).join("\n")}`);
  }

  return code;
}

main().then((code) => process.exit(code), (error) => {
  console.error(error);
  process.exit(2);
});
