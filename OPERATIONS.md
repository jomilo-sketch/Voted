# BOUESTI Vote — Operating Procedure

This is the procedure that goes with the software. A secure program does not make a
trustworthy election by itself: people have to run it the same way every time, keep
the keys safe, watch it while students vote, answer problems quickly, and let others
check the result. This document says who does what, and when.

It is written for the Electoral Committee and the three officers, not for programmers.
Where a step uses the program, it names the page (for example **Operations → Back up
now**). Where it needs a command typed on the server, the command is shown in a box.

> **Adapt it before you use it.** Names, phone numbers, dates and the rules about
> extending voting belong to the Electoral Committee. Fill in Appendix B (contact list)
> and have the Committee approve the document. Nothing here replaces the university's
> electoral guidelines or its data-protection rules.

---

## Contents

1. [Who does what](#1-who-does-what)
2. [The timeline](#2-the-timeline)
3. [Key custody](#3-key-custody)
4. [Before the election](#4-before-the-election)
5. [Backups that are tested, not just created](#5-backups-that-are-tested-not-just-created)
6. [Restoring after a loss](#6-restoring-after-a-loss)
7. [Monitoring while voting is open](#7-monitoring-while-voting-is-open)
8. [Communicating with students](#8-communicating-with-students)
9. [Incidents](#9-incidents)
10. [Closing, counting and publishing](#10-closing-counting-and-publishing)
11. [Independent verification of the result](#11-independent-verification-of-the-result)
12. [After the election](#12-after-the-election)
13. [What the software enforces, and what only people can](#13-what-the-software-enforces-and-what-only-people-can)
14. [Known limits](#14-known-limits)

Appendices: [A. Go-live checklist](#appendix-a--go-live-checklist) ·
[B. Contact list](#appendix-b--incident-contact-list-print-and-hold) ·
[C. Student messages](#appendix-c--student-messages) ·
[D. Election-day run sheet](#appendix-d--election-day-run-sheet) ·
[E. Archive checklist](#appendix-e--archive-checklist) ·
[F. Plain-words glossary](#appendix-f--plain-words-glossary)

---

## 1. Who does what

Three officers each hold one role in the program, with only the permissions that role needs.
Nobody can do the whole job alone — that is deliberate.

| Role | Does | Cannot |
|---|---|---|
| **Electoral Officer** | Runs the election: candidates, voter roster, opening and closing, announcements, administrator accounts. **Approves** the results report so it becomes public. Decides to pause or extend voting (with the Committee Chair). | Prepare the results report. Download backups. |
| **Results Officer** | **Prepares** and signs the results report after voting closes. Runs the supervised comparison with the database. | Edit candidates or voters. Publish results alone. |
| **Technical Support Officer** | Keeps the system healthy: backups, restoration drills, the audit copy, monitoring, incidents, the test e-mail. | See results. Change the election. See voter details. |

Others with a part to play:

* **Committee Chair** — the person who decides, with the Electoral Officer, to pause, extend or
  restart voting. Named on the contact list (Appendix B).
* **Witness** — a second official (never the person running the step) who supervises the comparison
  of the database with the published results (section 11). The Electoral Officer is the usual witness
  when the Results Officer runs it.
* **Observers** — candidates' agents, a lecturer or an external examiner. They receive the signed
  report, the audit export and the fingerprint, and check them on their own computer (section 11).
* **University ICT** — owns the network, the web address, the HTTPS certificate and the mail service.
  Named on the contact list.

**Two-person rule for results.** The Results Officer prepares; a *different* person publishes. The
program refuses anything else, and during live counting it also freezes changes to the Electoral and
Results Officers' accounts so one person cannot take over a colleague's login.

**Every administrator signs in with a password and a six-digit code from an authenticator app.**
Sensitive actions (opening or closing voting, going live, importing the roster, downloading backups,
publishing results) ask for a fresh code again. Nobody shares a login. If a person leaves, the
Electoral Officer disables the account the same day (**Administrators**).

---

## 2. The timeline

| When | What happens | Section |
|---|---|---|
| **4 weeks before** | Appoint the three officers and the Committee Chair. Prepare the server, the web address and HTTPS. Start the system once; create and store the master key copies. | 3, 4 |
| **3 weeks before** | Import the voter roster from the Registry's list. Candidates are screened and entered. | 4 |
| **2 weeks before** | **Rehearsal** with volunteer students and every officer. Practise the incident steps. | 4, 9 |
| **1 week before** | **Full restore rehearsal** on a different computer. Fix the dates. First announcement to students. Announce the signing-key fingerprint. | 5, 6, 8 |
| **2 days before** | Go-live checklist (Appendix A). **Go live** — this wipes the rehearsal data. Set the opening and closing times. Second announcement. | 4, 8 |
| **Election day** | Voting opens; two people watch the Operations page all day; notices as needed. At the closing time the system takes its own closing backup, audit copy and restoration drill. | 7, 8, 9 |
| **Same day / next day** | Count, publish (two officers), supervised comparison, hand the signed files to observers. | 10, 11 |
| **Within a week** | Post-election review with the read-only audit copy. Archive. Remove what must not be kept. | 12 |

---

## 3. Key custody

The system has **one secret that cannot be re-created: the master key** (32 random bytes). Everything
else is derived from it — the key that encrypts the backups, the key that signs the results report, the
key that scrambles matric numbers in the turnout record, and the key that protects the administrators'
authenticator secrets.

* **Without it**, encrypted backups cannot be opened, and results can no longer be signed with the same identity.
* **With it, plus a backup**, anyone could read that backup. Treat it like the keys to the ballot box.

The key is created automatically the first time the server starts, as the file `data/keys/master.key`
(readable only by the account that runs the server). The first-start screen says so.

**The rules**

1. **Two sealed copies, held by two different officers, in two different places.** For example: one in
   the Electoral Officer's safe at the Registry, one with the Committee Chair. The Technical Support Officer
   makes the copies but **does not keep one**.
2. **Never keep a copy next to the backups.** A backup folder and the key together are an open book.
3. **Write it down once, seal it, and prove the copy is right** before you rely on it:

   ```
   npm run keys -- export            # prints the key once, after a typed confirmation
   BOUESTI_MASTER_KEY=<the copy you wrote down> npm run keys -- check
   ```

   `check` must say the key opens the election database. If you mis-copied a character you find out now,
   not on the worst day.
4. **Record the fingerprint, not the key.** `npm run keys` shows the key's *fingerprint* (a short label that
   identifies the key without revealing it). Write it in the Committee's minutes. It is safe to share.
5. **Announce the signing fingerprint before voting opens.** `npm run keys` also shows the result-signing
   *public* key and its fingerprint. Publish the fingerprint on the notice board and the website. Later,
   observers compare it with the one on the signed results (section 11). A replaced key would not match.
6. **Tick "key custody" in the go-live checklist only when 1–5 are really done.** The program records who ticked it.

**If a copy is lost or a custodian leaves:** make a new sealed copy from the other custodian's copy, destroy
the old one in front of a witness, and write it in the minutes.

**If you think the key has leaked:** open a *critical* incident (section 9) at once. An attacker holding both the key
and a backup could read that backup, and one holding the key could forge a signed report. During a live election
the Committee decides whether to continue; keep the audit log and every backup as evidence. The key cannot be changed
in the middle of an election.

---

## 4. Before the election

### 4.1 The server

* One dedicated, patched computer (a virtual server is fine), in a place with reliable power and network. See the
  README for installing and starting it. It runs as a service that restarts by itself.
* **HTTPS is required.** Either a reverse proxy with the university's certificate, or the server's own `TLS_KEY_FILE`
  and `TLS_CERT_FILE`. The program refuses to start in production without Secure cookies.
* **E-mail codes are required.** The program refuses `OTP_MODE=demo` in production. Use the university's mail service
  (`SMTP_*` settings). Port 587 with STARTTLS or port 465 with TLS; the program verifies the mail server's certificate
  and will not send a password over an unencrypted connection.
* Only the Technical Support Officer and ICT can sign in to the server itself. Keep the operating system updated.
* The data folder (`data/`) holds the database, the keys and the backups. Only the account running the server may read it.

### 4.2 People and accounts

* The first start creates three accounts and writes their **one-time passwords** to `data/INITIAL-ADMIN-CREDENTIALS.txt`
  (and the screen). Hand each password over *in person*. Each person signs in, chooses their own password (12 characters
  or more) and sets up the authenticator app. The file deletes itself when all three are done.
* The starter e-mail addresses (`electoral@bouesti.ng`, `results@bouesti.ng`, `tech@bouesti.ng`) are placeholders. The
  Electoral Officer creates named accounts for the real people (**Administrators**) and disables the placeholders.
* Everyone saves their **eight recovery codes** (shown once) in a safe place — not on the same phone as the authenticator.
* **Lockouts:** five wrong passwords lock an account for 15 minutes. If a person is locked out or loses their phone, the
  Technical Support Officer recovers them at the server console (section 9, "Locked out").

### 4.3 Voters and candidates

* **Roster.** The Registry supplies the list of eligible students: matric number (digits only), name, university e-mail
  (`…@bouesti.edu.ng`). The Electoral Officer imports it (**Voters / Students → Import**). A live election uses a **closed
  roster**: only listed students can sign in, and the code goes to the e-mail on file — nobody can redirect it to another mailbox.
* The Committee **checks the roster against the official list** and signs the minutes. Tick "roster verified" only then.
* **Candidates.** The Electoral Officer enters the positions and candidates (**Candidates**) after screening. Once ballots
  exist the list is locked.
* **Matric numbers are digits only.** "matric 152637" or "BOU/15/2637" is refused at sign-in, in the roster and in the audit lookup.

### 4.4 The rehearsal

Run a full rehearsal two weeks ahead, with the whole team and a few volunteer students:

1. Sign in as a student, accept the rules, receive the e-mailed code, vote, check the receipt.
2. Check what happens when the code is late, mistyped, expired.
3. Close the rehearsal election, prepare and publish a report, run the verifier (section 11).
4. Practise at least three incident drills from section 9 (suggested: e-mail not arriving; a locked-out officer; a restore).
5. **Dashboard → Reset rehearsal data** clears the test ballots. **Going live also wipes them.**

### 4.5 Going live

Use **Appendix A**. The **Go live…** button (Operations) stays disabled until every required item is true, and says exactly what
is missing. It needs the Electoral Officer's fresh authenticator code *and* the typed words `GO LIVE`. It takes a safety
backup first, then wipes the rehearsal data, closes the roster, sets voting to "upcoming" and records a signed checkpoint in the
audit log. **It cannot be undone.** After that, a live election can never be turned back into a rehearsal.

Set the opening and closing times on **Election**. With the time set and the status left on *Upcoming*, the server opens voting by
itself at the opening time. If you press *Active* yourself, that wins. Check the page's note: it says plainly whether voting
will open by itself.

> **Extending voting must be decided before the closing time.** In a live election, once voting has closed (by the clock or by
> hand) it cannot be reopened — that is what protects the result. Decide on any extension at least 15 minutes before the closing
> time, and agree it with the Committee Chair. A *pause* (set the status back to *Upcoming*, then *Active* again) is allowed while
> the election is running.

---

## 5. Backups that are tested, not just created

A backup nobody has restored is only a hope. The system therefore does four things automatically, and people do two more.

### 5.1 What the system does by itself

| What | How often | Notes |
|---|---|---|
| **Encrypted backup** of the whole database | every 30 minutes (`BACKUP_INTERVAL_MIN`) | AES-256 encrypted, with a signed manifest. Safe to take while students vote. Needs the master key to open. |
| **Restoration drill** | every 6 hours (`DRILL_INTERVAL_MIN`), and straight after voting closes | Decrypts the newest backup into a scratch folder, checks its signature and checksum, opens the restored database, runs every integrity check, reports how much a restore would lose, then deletes the scratch copy. Your live database is not touched. |
| **Read-only audit copy** | every hour (`AUDIT_COPY_INTERVAL_MIN`), and straight after voting closes | Contains the audit log, the ballot box and the results — and **no** student list, no passwords, no sessions, no authenticator secrets. For post-election review and for the observers' recount. |
| **Milestone backups** | at "pre-live", "post-live" and "election-closed", and every manual one | Never pruned automatically. Scheduled ones are pruned to the newest 48 (`BACKUP_RETENTION`). |

A **failed backup or failed drill** turns the Operations page critical and writes a security entry to the audit log.

### 5.2 What people do

* **Mirror copy.** Set `BACKUP_MIRROR_DIR` to a second location (USB drive, network share) so every backup is also copied
  away from the server. The Operations page shows whether a mirror is configured. **Keep the key elsewhere** (section 3).
* **Before the risky moments, take a manual backup** (**Operations → Back up now**, or `npm run backup`): just before going
  live, just before the closing time, before any restore.
* **Full restore rehearsal, on a different computer, before the election** (and once more if the server is replaced).
  This is the human test that a drill cannot give you — it proves the *procedure*, the *key copy* and the *person*:
  1. On a spare computer, install Node.js and the program; copy the project folder (not `data/`).
  2. Put the master key in first: `BOUESTI_MASTER_KEY=<the sealed copy>` (or the key file).
  3. Copy one `.bvbak` file and its `.manifest.json` into `data/backups/`.
  4. `npm run restore -- <file>` — read what it says it will do; type the confirmation.
  5. Start it and check: the audit log verifies, the ballot count equals what the restore said, and the administrators can sign in.
  6. Write the date, the people present and how long it took in the minutes.

### 5.3 Reading the Operations page

* **Backups** — last backup time, how many files, free disk, whether a mirror exists.
* **Restoration drills** — latest result; **Test a restore now** (beside **Back up now**) runs a drill on demand. Click a row for the individual checks.
* **Recovery point** — each drill shows how many ballots and audit entries are *newer* than the backup it tested. That is
  what a restore at that moment would lose. At 30-minute backups the worst case is about 30 minutes of voting; lower
  `BACKUP_INTERVAL_MIN` (for example to 10) for the voting day if the Committee wants a smaller window.

Downloading a backup, a manifest or an audit copy needs the right role **and a fresh authenticator code**, and is logged.

---

## 6. Restoring after a loss

Restoring is a serious step that loses recent work. **It needs the Electoral Officer's agreement and the Technical Support
Officer's hands**, and is recorded in the audit log.

**When to restore:** the database is damaged, the integrity check fails, the audit chain fails and the Committee decides to
continue from a good copy, or the machine is lost. **Do not restore** for a slow site or missing e-mails — that is not what a
backup is for.

1. **Open a critical incident** (section 9) and tell the Committee Chair. If voting is open, **pause** it and post the
   "Short pause" notice (Appendix C).
2. **Stop the server.** The restore tool refuses to run while the server is running.
3. **Have the master key to hand** (the sealed copy if this is a new machine). It must be the key the backup was made with.
4. **Choose the backup.** Prefer the newest that passed a drill. On the Operations page note its time and how many ballots it holds.

   ```
   npm run restore -- <backup-file>
   ```

   The tool decrypts the backup into a scratch folder and checks its signature, checksum and contents. **Nothing changes if
   any check fails.** It shows what is inside and asks you to type a confirmation.
5. **Your current database is never deleted** — it is moved to `data/pre-restore-<time>/`, so a wrong choice can be undone.
6. **Start the server.** It writes "restored from backup …" into the audit log.
7. **Check** (Operations): the audit chain verifies, the database integrity check passes, the ballot count is what the backup held.
8. **Count the loss.** Compare the ballots in the restored database with the last count you saw. Those votes are gone
   *together with their turnout records*, so the students concerned can vote again — but they hold receipts that will now say
   "not found". Post a notice (Appendix C, "After a restore") asking anyone who saw a receipt but cannot find it on the site to vote again.
9. **Resume voting** only when the Committee Chair agrees. Consider extending the closing time to make up the lost window — before it passes.
10. Close the incident with a written account (what failed, what was lost, what was learned).

---

## 7. Monitoring while voting is open

**Two people are on watch for the whole voting period** — one technical (usually the Technical Support Officer), one from the
electoral side. Keep the **Operations** page open on a screen that is always visible; the monitoring panel refreshes by itself
every 15 seconds. Agree a check-in by phone every hour and note it in the log sheet (Appendix D).

### 7.1 What to look at

* **Votes per hour** (Voting Statistics) should rise steadily, with the peaks you expect. A sudden stop usually means a network or e-mail problem.
* **Registered → Verified → Voted.** A large gap between *verified* and *voted* means students are stuck on the ballot page.
* **E-mail failures**, **rate-limit blocks**, **wrong passwords**, **administrator failures**, **open incidents**, **student reports waiting**.
* **Backups and drills** keep passing; **disk space**; **audit chain** intact.

### 7.2 What the alerts mean, and the first move

| Alert | Level | What it means | First move |
|---|---|---|---|
| Audit log failed verification | critical | The record may have been tampered with. | **Stop. Do not publish results.** Critical incident. Keep everything. |
| Database consistency problem | critical | SQLite reports damage. | Critical incident; Committee decides on a restore (section 6). |
| Backup failed | critical | The newest backup attempt failed. | Check disk space and the audit log; run **Back up now**. |
| Backup stale | warning → critical | No good backup for a long time. During a *live* election, twice the grace period turns it critical. | **Back up now**; find out why the schedule stopped. |
| Restoration drill failed | critical | The backups may not be restorable. | Take a new backup and run a drill. If it fails again, treat as critical. |
| Drill stale | warning | No passing drill for a long time. | **Test a restore now.** |
| Disk low / critical | warning / critical | Under 1 GB (or 10 %) / under 100 MB free. | Free space or move the data folder **now**. Votes will fail when the disk is full. |
| Verification e-mails failing | warning | Three or more failed e-mails in 15 minutes. | Check the mail service; send a **test e-mail**; post "Code is late". |
| Rate-limit blocks | warning | Ten or more in an hour. | If real students are blocked together, the proxy setting is probably wrong (README: `TRUST_PROXY`, `RATE_IP_SCALE`). |
| Failed administrator sign-ins | warning | Ten or more in an hour. | Possible guessing. Check **Audit** for the source; tell ICT. |
| Wrong student passwords | warning | 100 or more in an hour. | Usually typing mistakes; otherwise probing. Check **Audit**. |
| Student reports waiting | warning | Problem reports not yet read. | Read them (**Notifications**), triage, open an incident if they share a cause. |
| Serious incident still open | warning | A high/critical incident has no resolution recorded. | Make sure someone owns it. |
| Schedulers off | warning | No automatic backups, drills, or scheduled opening/closing. | Restart with schedulers enabled; take a manual backup. |
| Opening missed | warning | The opening time passed and voting did not open. | Check there is an approved candidate; press **Active**. |
| Closing soon | info | Under 30 minutes to the closing time. | Decide **now** whether any extension is needed (section 4.5). |

### 7.3 Rules for the watchers

* **Never restart the server or restore a backup during voting without the Electoral Officer's agreement.** Both are recorded.
* **Post a notice as soon as students are affected** (Notifications), then open an incident (Operations).
* **Do not look at individual students' trails** unless an incident needs it. Looking one up asks for a fresh code and is recorded
  under a pseudonym; the log of who looked is visible to every officer.
* Use the **hourly log sheet** (Appendix D): time, votes cast, any alert, anything done and by whom.

### 7.4 If the server crashes or the power fails

Ballots are written in a single database transaction: a vote is either wholly recorded or not at all. Administrator and student
sessions are stored in the database, so after a restart people are still signed in (until their normal time-out). Restart the
service, then check Operations: the audit log should verify and a "Server started" entry should follow the last "Server stopped"
or the crash. A student who did not see a receipt did **not** vote and can sign in again.

---

## 8. Communicating with students

Students find out the rules from you, not from the screen. Say the same things, in the same words, through every channel.

### 8.1 Channels

The university website and the voting site's notice banner, the SUG social-media and WhatsApp groups, department notice boards and
class representatives, e-mail to the university address, and campus radio if there is one. Name one person as the voice.

### 8.2 What every message must make clear

* The **web address** (the real one, spelled out) and the **dates and times**, with the time zone.
* How to sign in: **matric number (digits only) and the election password**.
* The **six-digit code is sent to your university e-mail** and works for five minutes, once.
* **No official will ever ask for your code or your password.** Never share the code with anyone.
* Where to get help, and that **a receipt means your vote is recorded**; no receipt means it is not.
* The password is the same for every student and is not secret — your protection is the e-mailed code.

### 8.3 Schedule of messages

| When | Message (Appendix C) | Where from |
|---|---|---|
| 1 week before | "Dates and how to vote" | All channels |
| 2 days before | "Check your university e-mail now" — students who cannot read their university mailbox must fix it *before* election day | All channels, class representatives |
| Opening morning | "Voting is open" | Notice banner + all channels |
| Mid-day | "Reminder" | Social media |
| 2 hours before closing | "Closing soon" | Notice banner + all channels |
| When something goes wrong | The matching incident message | **Within 15 minutes** of the first confirmed problem |
| After closing | "Voting has closed — results coming" | Notice banner + all channels |
| After publication | "Results published; how to check them" | All channels |

The Notifications page offers one-click templates for six of these (voting open, closing soon, code is late, short pause, voting
extended, results coming); they are the short versions in Appendix C.

### 8.4 The help desk

Staff the help desk (phone or WhatsApp) for the whole voting period with people who have read this section. Never ask a student
for their code, their password or **who they voted for**. Give them the matric-number check only through the Electoral Officer.

| A student says… | Say / do |
|---|---|
| "It says my matric number isn't eligible." | The roster is closed. The Electoral Officer looks the student up (**Voters / Students**). If they should be on it, the Electoral Officer adds them (recorded); then they sign in again. |
| "Incorrect password." | The password is the one in the announcement, typed exactly. Twelve wrong tries in 15 minutes pause that matric number for 10 minutes. |
| "I didn't get my code." | Check the spam folder; the e-mail comes from the university's sending address. Wait a minute and request again (30-second wait between requests; 10 requests an hour; 5 per sign-in). The e-mail must be the **university e-mail on the roster**, typed exactly. |
| "The code says expired / wrong." | Codes last five minutes and work once; five wrong tries cancel the code. Request a new one. If many wrong tries, the matric number is paused for up to an hour — be patient. |
| "It says I already voted." | The record shows a ballot was accepted for that matric number. Ask whether they saw a receipt and check it on the home page (**Check my receipt**). If the student insists they did not vote, open an incident — **do not** try to look at their ballot (nobody can). |
| "It logged me out." | Sessions end after 15 minutes of inactivity (40 minutes in total). Nothing is lost; sign in again. |
| "I voted but got no receipt." | If there was no receipt, the vote was not recorded. Sign in and vote again. |
| "Can I vote late / on behalf of someone?" | No. The Committee decides any extension for everyone, in advance. Nobody may vote for another student. |

---

## 9. Incidents

An **incident** is anything that threatens the vote, its secrecy, its record, or students' ability to take part. Record it —
in the program's own **Operations → Incidents** — so there is one account of what happened and who decided what.

**Never type a student's matric number, or anything about anyone's choices, into an incident.** The audit log records only that an
incident existed and how it changed; the text stays in the incident record.

### 9.1 Severity and who decides

| Severity | Examples | Who decides | Response time |
|---|---|---|---|
| **Low** | One student cannot sign in; a typo in an announcement. | Help desk | Same day |
| **Medium** | Codes arriving late; a slow site; a failed (but not repeated) backup. | Technical Support Officer, tells the Electoral Officer | 15 minutes |
| **High** | The site is down for some students; many e-mail failures; suspected guessing attack; a failed drill. | **Electoral Officer** (with the Committee Chair for any pause or extension) | Immediately |
| **Critical** | Audit chain or integrity check fails; suspected key leak; suspected tampering; ballots missing; loss of the server. | **Committee Chair and Electoral Officer together**; ICT; consider an independent observer | Immediately — stop and call |

**Pause, extend, close:** the Electoral Officer and the Committee Chair decide, together, and write the reason in the incident.
*Pause* = set the status to *Upcoming* (students see that voting is not open; their progress is safe). *Resume* = *Active*.
*Extend* = move the closing time **before it passes** (section 4.5). *Close* ends it for good in a live election.

### 9.2 The steps for every incident

1. **Confirm** what you see (two people if it is serious). Write the time.
2. **Open the incident** (title, severity, what happened). Tell the right person from Appendix B.
3. **Protect the evidence.** Do not "clean up". The audit log is permanent and signed; leave it alone. Take a manual backup.
4. **Protect the vote.** If in doubt, pause. A short pause is cheaper than a doubtful result.
5. **Tell students** (section 8, within 15 minutes if they are affected).
6. **Fix** the cause (below), then **check** the system (audit chain, integrity, backups) before resuming.
7. **Resolve** the incident with a written account: cause, what was affected, what was decided and by whom.
8. **Review** within a week: what would we change in this procedure?

### 9.3 Playbook

**Verification e-mails are not arriving** (alert "e-mails failing", or students report it)
1. Operations → **Send a test e-mail** to a mailbox you can see. If it fails, the mail service or its settings are the problem.
2. Call the mail service contact (Appendix B). Check the server has not been blocked for volume.
3. Post **"Code is late"**. Do not tell students to request many codes — each request is limited and many requests make it worse.
4. If it is not fixed within the Committee's agreed limit (suggest 30 minutes), **pause** and **extend** the closing time.

**The site is slow or down**
1. Check the server and the proxy are running and the disk is not full (Operations → disk).
2. Restart the service if it is hung (with the Electoral Officer's agreement; it is recorded). Sessions and ballots survive a restart.
3. If the whole campus is behind one address and students are being blocked together, set `TRUST_PROXY` correctly or raise `RATE_IP_SCALE`.
4. Post **"Short pause"** if students are affected for more than a few minutes.

**Suspected guessing or attack** (many wrong passwords/codes; administrator failures)
1. Check **Audit** for the pattern and source. The rate limits are already slowing it down.
2. Tell ICT; ask them to block the source address at the network edge.
3. If an administrator account is targeted, the account locks itself after five wrong passwords; change that person's password.
4. Open a *high* incident. If any sign that a vote was cast by someone else, it is *critical*.

**A student says someone voted for them / "I never voted but it says I did"**
1. Do not look for the ballot — the program cannot link a student to a choice, and nobody should try. Check only that **a turnout record exists** (it does, if the sign-in says "already voted").
2. Open an incident with no matric number. The Committee decides what to do. A shared mailbox or a stolen phone is the usual cause: the e-mailed code is the proof of identity.

**An officer is locked out, forgot the password, or lost the authenticator phone**
1. Technical Support Officer, at the server: `npm run admin -- list`, then `unlock`, `reset-code` or `reset-2fa` for that person (the tool never shows a password; it gives a one-time code the person uses themselves). **Hand it over in person.**
2. During live counting the web page will not change the two officers' accounts (by design); the console still can, and every console action is logged under the operator's name and shown to the other officers as a security entry.

**Disk full**
1. Free space (old logs, unrelated files) or move the data folder. Do **not** delete files inside `data/` by hand.
2. Run **Back up now** and a drill once there is room.

**Audit chain or integrity check fails — critical**
1. **Stop.** Do not publish results. Do not restart "to see if it goes away".
2. Take a manual backup (it is evidence). Tell the Committee Chair and ICT.
3. Compare with the latest read-only audit copy and the signed checkpoints (section 11) to find where the record diverges.
4. The Committee decides: restore from the last good backup (section 6) or investigate first. Involve an independent observer.

**A restoration drill failed**
1. Take a new backup, run a drill again. If it passes, note it in the incident and keep an eye on the cause.
2. If it fails again, treat the backups as unreliable: critical incident, check the key (`npm run keys -- check`), the disk, and the file permissions.

**The server machine is lost**
1. Section 6 on a replacement computer, with the sealed key copy and the mirrored backups.

---

## 10. Closing, counting and publishing

1. **Closing.** Voting closes at the set time (or the Electoral Officer presses *Closed*, with a fresh code). All student
   sessions end. Within a minute the system takes the **closing backup, the read-only audit copy and a restoration
   drill** by itself. Check that all three appear and the drill passed (Operations).
2. **Count.** The Results Officer opens **Results**: the counts are only visible after closing. Look at the *consistency* line —
   ballots must equal receipts must equal turnout records.
3. **Prepare the signed report.** The Results Officer presses **Prepare signed report** (fresh code). The program
   counts from the ballots, seals the totals with a digital signature and anchors the report to the audit log. It refuses if
   the ballots, receipts and turnout do not agree.
4. **Approve and publish.** A *different* officer — the Electoral Officer — reads the report and presses **Approve and publish**
   (fresh code). Only now do the totals appear to students and visitors. If something is wrong, **Reject** with a reason and
   prepare again; nothing was public.
5. **Supervised comparison.** With the observers present, the Results Officer runs **Compare with database**. The witness
   (a different official) signs in again — their own password and authenticator code — on the same screen. The program recounts
   from the database and checks it matches the published report, entry by entry.
6. **Hand over the files** (section 11). Announce the signing fingerprint again and where observers can get the files.
7. **Tell students** that results are published and how to check their receipt.

---

## 11. Independent verification of the result

The point of this section: **nobody has to take the officials' word for the result.** Observers can check, on their own
computers, with a tool that contains no part of the voting system and no secret.

### 11.1 What observers receive

* The **signed tally report** (Results → **Download signed report**): one file containing the report, the officials who
  prepared and approved it, the signing key and its signature.
* The **fingerprint** of the signing key, announced *before* voting opened and again at publication.
* Optionally the **audit-log export** (Audit → **Export**, needs a fresh code) and the **read-only audit copy**
  (Operations → Audit copies → download, needs a fresh code).
* The two small checking tools `scripts/verify-report.js` and `scripts/verify-audit.js` (Node.js 22.13+ and nothing else).

### 11.2 What they run

```
node scripts/verify-report.js signed-report.json --trusted-fingerprint "ABCD 1234 …"
node scripts/verify-report.js signed-report.json --trusted-fingerprint "ABCD 1234 …" --audit-copy audit-copy.db
node scripts/verify-audit.js  audit-log.ndjson   --trusted-fingerprint "ABCD 1234 …"
node scripts/verify-audit.js  audit-copy.db      --trusted-fingerprint "ABCD 1234 …"
```

Each prints every check and **exits with 0 only if all pass** (1 = a check failed, 2 = it could not run).

| The tool checks | Which proves |
|---|---|
| The report is exactly what was signed (not one byte changed) | Nobody edited the figures after signing. |
| The signing key is the one the officials announced | It was not signed with a substituted key. |
| Totals add up: per candidate, per position, ballots = receipts = turnout | The arithmetic is honest. |
| The publication record is signed, names *this* report, and the approver is a different person from the preparer | The two-person rule really happened. |
| With `--audit-copy`: the ballots in the copy, counted again from scratch, give the same totals and digest; the audit log in the copy is intact and contains the entry the report was anchored to | The totals really come from the stored ballots, and the record was not rewritten. |
| (audit tool) every entry's hash chains to the one before; every signed checkpoint verifies; an announced head hash or entry count matches | The log has not been altered, shortened or re-written. |

### 11.3 What the checks do *not* prove

* They do not prove that the **right students** voted — the e-mailed code and the roster do that, and a stolen mailbox defeats it.
* They do not prove **secrecy** — see section 14.
* They are only as good as the **fingerprint the observer trusts**. An observer who takes the fingerprint from the same file they
  are checking proves nothing. They must have it from an independent announcement (notice board, minutes, their own copy).

### 11.4 If a check fails

Do not argue the result. Open a **critical incident**, keep every file, run the supervised comparison again, and ask an observer to
repeat the check on their own computer. A failure may be a corrupted download — compare the file's checksum — but treat it as real until shown otherwise.

---

## 12. After the election

**Within a week** — the post-election review, with the Committee, the three officers and (if possible) an observer:

* Walk through the incident log and the audit log's key moments (go-live, opening, closing, preparation, publication).
* Use the **read-only audit copy** (it has no student data) to answer questions without touching the live system.
* List what went well, what went wrong and what to change in this procedure. Minute it.

**Archive** (Appendix E) — keep, with the Committee, for the period the university's rules require:

* the signed report and its fingerprint, the audit export, the final audit copy with its manifest,
* the closing backup (encrypted) **and, separately, the sealed master key** — together, in different custody,
* the minutes, the incident log, the rehearsal and restore-rehearsal records.

**Remove what must not be kept.** The student roster (matric numbers and e-mail addresses) is personal data. Ask the university's
data-protection officer how long it may be kept and under what conditions; the Nigeria Data Protection Act applies to personal
data like this. The turnout record holds only a keyed hash of each matric number and the audit log only pseudonyms; the roster
is the sensitive part. When the retention period ends, destroy the server's data folder and every backup **and** the key copies, with a witness.

**Plan the next election now.** A new election should start from a clean installation and a new master key, not from this database.

---

## 13. What the software enforces, and what only people can

| The software enforces | Only people can |
|---|---|
| Digits-only matric numbers, one shared student password, an e-mailed code that expires and works once | Decide who is on the roster; keep students' mailboxes in their own hands |
| One vote per student; the ballot box holds no link to the student | Keep the mail service and the server's operating system safe |
| Admin passwords stored as salted hashes; two-factor sign-in; lockout; session expiry; fresh codes for sensitive steps | Keep authenticator phones and recovery codes safe, and never share a login |
| Two-person publication; frozen officer accounts during live counting | Choose two officers who are genuinely independent |
| Encrypted backups, automatic drills, a read-only audit copy | Keep the master key apart from the backups, in two places, with two custodians |
| A signed, hash-chained audit log; restricted, monitored access to it | Actually look at the alerts, and act on them |
| Signed tally report and independent verifier tools | Announce the fingerprint beforehand; invite observers; keep their copies |
| Rate limits on sign-in, codes and the ballot | Tell students the truth, quickly, when something goes wrong |

---

## 14. Known limits

Be honest with the Committee and with students about these.

* **One server.** There is no automatic failover. The protection against loss is the backups and the restore procedure (sections 5 and 6).
* **The student password is the same for everyone and is public.** Identity rests on the e-mailed code. Anyone who can read a student's university
  mailbox can vote as that student.
* **Ballot secrecy** holds against anyone who obtains a snapshot, a backup, an export or the audit copy, and against anyone running queries on the stored tables:
  there is no stored link from a student to a choice. It does **not** hold against an attacker who controls the running server or can read the
  live database files while votes are being written, because such a person could watch the votes arrive in order. Keep that machine locked down.
* **Passwords** for administrators are hashed with scrypt (a memory-hard, salted hash that needs no native add-ons). It is a modern alternative
  to Argon2id or bcrypt; if the university's policy requires one of those by name, that is a small change to one module.
* **HTTPS** and the mail service are outside this program. If either is weak, so is the system. The program refuses to run in production
  without Secure cookies and with the demo code.
* **The mail client** has been tested against a local test mail server (plain, STARTTLS, TLS, refusals, dropped connections), not against every
  provider. **Send a test e-mail from Operations before the election** — go-live requires it for exactly this reason.
* **A closed live election cannot be reopened.** That is protection, not a bug; plan extensions in advance.
* **Time zone.** Times are stored exactly and shown in each person's own time zone; the closing time is a moment, not a clock reading. State the zone in announcements.

---

## Appendix A — Go-live checklist

The program checks the items marked ✔ itself and refuses to go live while any is missing. The others are people's confirmations,
recorded with the name of the person who ticked them.

| ✔ / ☐ | Item |
|---|---|
| ✔ | Server runs in production mode; session cookies are Secure (HTTPS) |
| ✔ | Verification codes are e-mailed (no demo code) |
| ✔ | **A real test e-mail was delivered in the last 72 hours** with the current mail settings |
| ✔ | Background schedulers are running |
| ✔ | The voter roster is loaded; at least one position has an approved candidate |
| ✔ | Every administrator has chosen a password and enrolled two-factor sign-in; an Electoral Officer and a Results Officer exist |
| ✔ | A recent encrypted backup exists; **the latest restoration drill passed** |
| ✔ | The audit log verifies; the database passes its integrity check |
| ☐ | **Key custody:** the master key is saved in two sealed copies, held by different officers (section 3) |
| ☐ | **Roster verified** against the official student list, signed in the minutes |
| ☐ | **Students notified** of dates, address, how the code works, where to report problems (section 8) |
| ☐ | **Incident contacts:** every officer holds the printed contact list and knows who decides to pause or extend (Appendix B) |
| ☐ | The full restore rehearsal on a different computer was done and minuted (section 5.2) |
| ☐ | The signing fingerprint has been announced |
| ☐ | The opening and closing times are set and agreed; the time zone is stated in the announcement |

Nice to have (the page shows them but does not block): every active student has an e-mail on file, positions are contested,
backups are mirrored to a second place, at least 1 GB of free disk, `TRUST_PROXY` set correctly behind a proxy, a Technical
Support Officer exists, the shared student password is not the published default.

---

## Appendix B — Incident contact list (print and hold)

Every officer keeps a printed copy. Check the numbers a week before and again the day before.

| Role | Name | Phone | WhatsApp | Deputy (name, phone) |
|---|---|---|---|---|
| Committee Chair (decides pause / extend, with the Electoral Officer) | | | | |
| Electoral Officer | | | | |
| Results Officer | | | | |
| Technical Support Officer | | | | |
| University ICT — network and web address | | | | |
| University ICT — mail service | | | | |
| Registry (roster questions) | | | | |
| Student Affairs / Dean of Students | | | | |
| Data-protection / legal contact | | | | |
| Observers' coordinator | | | | |
| Campus security | | | | |

Escalation: help desk → Technical Support Officer → Electoral Officer → Committee Chair. A *critical* incident goes straight to the Chair and the Electoral Officer.

---

## Appendix C — Student messages

Adapt the dates, times and address. Short versions fit an SMS or a WhatsApp status; longer versions suit e-mail and notice boards.

**Dates and how to vote** *(1 week before)*
> The BOUESTI SUG election will hold on **[date]**, voting from **[time]** to **[time]** ([time zone]). Vote at **[web address]**.
> Sign in with your matric number (digits only) and the election password **[password]**, accept the rules, then enter the 6-digit code we e-mail to your **university e-mail**. Make sure you can open that mailbox *before* election day. We will never ask for your code or password. Problems: **[help desk contact]**.

**Check your university e-mail** *(2 days before)*
> Voting is in 2 days. Your code is sent only to your university e-mail (…@bouesti.edu.ng). Log in to it today. If you cannot, contact **[contact]** now — we cannot send codes anywhere else.

**Voting is open** *(also the in-app template "Voting is open")*
> Voting is now open. Log in with your matric number and password, accept the election rules, then enter the 6-digit code sent to your university e-mail.

**Closing soon**
> Voting closes soon. If you have not voted yet, please do so now. Check your university e-mail for your 6-digit code.

**Code is late**
> Some e-mail codes are arriving late. Please wait a few minutes before asking for a new code, and check your spam folder.

**Short pause**
> Voting is briefly paused while we fix a technical problem. Your progress is safe and nothing has been lost. Please check back shortly. *(If you did not see a receipt, your vote has not been recorded — you can sign in again once voting resumes.)*

**Voting extended**
> Voting has been extended. The new closing time is shown on this page. Thank you for your patience.

**After a restore**
> We restored the system from a backup after a technical fault. A small number of votes cast between **[time]** and **[time]** may not have been kept. If you voted in that period, please check your receipt on the home page ("Check my receipt"). If it says "not found", sign in and vote again. Votes cast outside that period are not affected.

**Results coming**
> Voting has closed. Results will be published here once they have been counted and verified by two electoral officers.

**Results published**
> The results are published at **[web address]**. The report is digitally signed; its fingerprint is **[fingerprint]**. Observers and candidates can check it independently — ask the Electoral Committee for the verification pack.

**Security reminder** *(any time)*
> No election official will ever ask for your 6-digit code or your password, by phone, WhatsApp or e-mail. If someone does, do not give it, and tell **[contact]**.

---

## Appendix D — Election-day run sheet

Before opening:

* [ ] Server up, Operations page green; time on the server is right
* [ ] Last backup < 30 minutes old; last drill passed; audit chain intact
* [ ] Test e-mail received on a real mailbox *today*
* [ ] Help desk staffed; contact lists in hand; watchers named for each shift
* [ ] "Voting is open" notice ready

Hourly log (copy one line per hour):

| Time | Votes so far | Alerts? | Backup/drill OK? | Notes / actions / who |
|---|---|---|---|---|
| | | | | |

Two hours before closing:

* [ ] Decide on any extension (before the closing time; with the Chair) — otherwise "Closing soon" notice
* [ ] Manual backup

At closing:

* [ ] Closing backup, audit copy and drill appeared; the drill **passed**
* [ ] Students told voting has closed
* [ ] Counting begins in the presence of observers

---

## Appendix E — Archive checklist

* [ ] Signed report (published) and its fingerprint, in two places
* [ ] Audit-log export and the final audit copy (with its manifest)
* [ ] Closing backup (encrypted) and its manifest
* [ ] Sealed master-key copies (kept **apart** from the backup)
* [ ] Minutes: go-live, comparison, post-election review, restore rehearsal
* [ ] Incident log and any written accounts
* [ ] Written decision on how long each item is kept, and who may open the archive
* [ ] Roster and working copies removed or scheduled for removal as agreed

---

## Appendix F — Plain-words glossary

| Term | Meaning |
|---|---|
| **Rehearsal / live** | A rehearsal is a practice with test data that can be reset. *Live* is the real election; going live is one-way. |
| **Roster (open / closed)** | The list of students allowed to vote. A closed roster admits only listed students. |
| **Registered, verified, voted** | The three stages of a student's visit: accepted the rules; proved the e-mailed code; ballot accepted. |
| **Receipt** | A code shown after voting that proves a ballot was accepted, without saying who it was or what it held. |
| **Audit log** | The permanent record of important events. Each entry is chained to the one before it, so changing or deleting anything breaks the chain. It records no ballots and no matric numbers. |
| **Checkpoint** | A signed note of the log's state at an important moment (going live, closing, publishing). |
| **Master key** | The one secret from which the backup, signing and scrambling keys are made. Section 3. |
| **Fingerprint** | A short label that identifies a key without revealing it. |
| **Signed report** | The results, sealed with a digital signature so any change is detectable. |
| **Two-person rule** | One officer prepares, a different officer publishes. |
| **Witness** | A second official who supervises a step by signing in again as themselves. |
| **Restoration drill** | A test that restores a backup into a scratch area and checks it, without touching the live system. |
| **Recovery point** | How much a restore would lose: the votes and entries newer than the backup. |
| **Step-up** | Asking an administrator for a fresh authenticator code before a sensitive action. |
