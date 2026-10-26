# BOUESTI Vote

The e-voting system for the BOUESTI Student Union Government (SUG) election: a voter portal and a
role-based administrator dashboard, served by one small Node.js program with a database that
keeps ballots separate from voters, backups that are encrypted **and tested**, a tamper-evident
audit log, and a signed results report that anyone can check on their own computer.

* **One dependency.** Express. The database is Node's built-in SQLite (`node:sqlite`); passwords,
  two-factor codes, signatures, e-mail and backups all use Node's own libraries. Nothing to compile.
* **Node.js 22.13 or newer** (check with `node -v`). Older versions stop at once with a plain message.
* **Two documents.** This README is for the person who installs and runs the server.
  [`docs/OPERATIONS.md`](docs/OPERATIONS.md) is the operating procedure for the Electoral Committee:
  who does what, key custody, backups and restoration drills, monitoring, messages to students,
  incidents, counting, and independent verification.

> **Read this first.** A rehearsal on a laptop needs five minutes (section 1). A real election needs
> HTTPS, an e-mail service, a safely stored master key and a rehearsal first (section 5 and
> `docs/OPERATIONS.md`). The program refuses to run an unsafe configuration in production instead of
> quietly accepting it.

---

## Contents

1. [Quick start (rehearsal)](#1-quick-start-rehearsal)
2. [What students do](#2-what-students-do)
3. [Administrators and roles](#3-administrators-and-roles)
4. [Settings](#4-settings)
5. [Going live](#5-going-live)
6. [Command-line tools](#6-command-line-tools)
7. [Tests](#7-tests)
8. [How the eight requirements are met](#8-how-the-eight-requirements-are-met)
9. [How the vote is protected](#9-how-the-vote-is-protected)
10. [Project map](#10-project-map)
11. [Limits](#11-limits)
12. [Troubleshooting](#12-troubleshooting)

---

## 1. Quick start (rehearsal)

```bash
node -v        # must print v22.13.0 or higher
npm install    # installs Express, the only dependency
npm start
```

Then open

* **Students:** <http://127.0.0.1:3000/>
* **Administrators:** <http://127.0.0.1:3000/admin>

The first start creates three things and tells you about each on the screen:

1. **A master key**, the file `data/keys/master.key`. It protects the encrypted backups, the
   administrators' two-factor secrets and the key that signs results. Copy it to safe places now
   (section 5.5). It is only a rehearsal today, but the habit starts here.
2. **Three starter administrator accounts** with one-time passwords. The same list is written to
   `data/INITIAL-ADMIN-CREDENTIALS.txt`, which deletes itself once all three accounts are set up.

   | Role | Starter e-mail |
   |---|---|
   | Electoral Officer | `electoral@bouesti.ng` |
   | Results Officer | `results@bouesti.ng` |
   | Technical Support Officer | `tech@bouesti.ng` |

   These addresses are placeholders. Before a real election the Electoral Officer creates accounts for
   the real people (**Administrators**) and disables these.
3. **A sample election** in *rehearsal* mode: nine positions with two sample candidates each, status
   *Active*, and an open roster, so you can try voting immediately.

**Rehearsal mode is deliberately relaxed and is not secure:** the e-mail code is always `123456`, and
any matric number of 4–15 digits may sign in. The server prints a warning saying so. Rehearsal is
for learning the system, not for holding an election.

**To try it as a student:** open the student page, enter a matric number such as `152637`, the password
`password1`, accept the rules, enter a university e-mail (`anything@bouesti.edu.ng`), then the code
`123456`, choose candidates and submit. Keep the receipt code and check it on the home page.

**To try it as an administrator:** sign in at `/admin` with a starter e-mail and its one-time password,
choose a new password of at least 12 characters, add the *setup key* shown to an authenticator app
(Google Authenticator, Microsoft Authenticator, Authy, 1Password … choose "enter a setup key"; the
type is time-based, 6 digits, 30 seconds), type the code the app shows, and save the eight recovery
codes. From then on every sign-in needs the password and a code.

To start again from nothing, stop the server and delete the `data/` folder. (Never do this to a real
election: the folder holds the ballots and the keys.)

---

## 2. What students do

```
sign in  →  accept the rules  →  e-mailed code  →  ballot  →  receipt
```

**The sign-in rules (items 1 and 2 of the brief)**

| | Accepted | Refused |
|---|---|---|
| **Matric number** | **Digits only**, 4 to 15 of them: `152637`, `1257`, `173637` | `matric 152637`, `matric`, `BOU/15/2637`, `15 26 37`, `1526a7`, `123` |
| **Password** | **`password1`**, exactly | every other password, including `Password1`, `password`, `password1 ` and an empty one |

Both rules are enforced on the server. The page's own check only gives a faster answer. The matric
number is also constrained inside the database, so a roster row such as `matric 152637` cannot be
stored by any route, including a bad import. If real matric numbers are shorter or longer than 4–15
digits, change `MATRIC_PATTERN` in `config.js` and the matching `CHECK` in `schema.js` together.

The student password is the same for everyone **by design**, so it is not secret and cannot prove
who a student is. The proof of identity is the **one-time code e-mailed to the student's university
mailbox**: in a live election it goes to the address on the roster and nowhere else.

**Around the sign-in**

* The code is valid for 5 minutes and allows 5 attempts. "Resend code" waits 30 seconds, and a
  sign-in may request at most 5 codes.
* A student who has already voted who signs in again is told so, and is never shown the ballot.
* Signing in on a second device ends the first session.
* A session ends after 15 idle minutes or 40 minutes in total, and **Sign out** ends it at once on the
  server (not just in the browser).
* The receipt code lets a student confirm that a ballot was counted. It reveals nothing about the
  choices and is not linked to the student.

---

## 3. Administrators and roles

Three roles, each with only the permissions its duties need. An administrator has exactly one role.

| | **Electoral Officer** | **Results Officer** | **Technical Support Officer** |
|---|---|---|---|
| Election dates and status, positions, candidates, notices | ✔ | view | view |
| Voter roster (view, import, export), settings, go-live | ✔ | — | — |
| Voting statistics | ✔ | ✔ | ✔ |
| See the results | ✔ | ✔ | — |
| **Prepare** the signed results report | — | ✔ | — |
| **Approve** (publish) the results | ✔ | — | — |
| Supervised comparison with the database | ✔ | ✔ | — |
| Audit log: read, export, download the audit copy | ✔ | ✔ | ✔ |
| Back up, test a restore, make an audit copy, send the test e-mail, download a backup | view | view | ✔ |
| Read and answer students' problem reports | ✔ | — | ✔ |
| Incidents | ✔ | ✔ | ✔ |
| Administrator accounts | ✔ | — | — |

**Two-person rule.** The Results Officer prepares the report; a *different* administrator publishes
it. The program refuses anything else.

**Security of administrator accounts (item 7)**

* Accounts live in the database with salted **scrypt** password hashes (see the note on Argon2id in
  section 11). Passwords must be at least 12 characters.
* **Two-factor authentication** (an authenticator app) is compulsory; 8 one-time recovery codes are shown once.
* **Lockout:** 5 wrong passwords lock the account for 15 minutes. Wrong two-factor codes count too.
* **Sessions** end after 15 idle minutes or 4 hours in total, are stored in the database (they survive a
  restart), can be revoked from **My account → Sign out everywhere**, and are replaced at every sign-in.
* **Fresh-code step-up:** sensitive actions each ask for a new code from the app (good for 5 minutes):
  changing the voting status, going live, importing, exporting or removing voters, preparing or publishing
  results, creating or changing administrator accounts, downloading a backup, an audit copy or the audit
  export, and looking up a voter's trail in the audit log.
* **Password reset** is a one-time code issued by an officer (or at the server console), valid for
  30 minutes. Nobody, including the server operator, can read or set another person's password.
* **While live counting is under way** (live election, voting closed) the web dashboard freezes
  changes to the Electoral and Results Officers' accounts, so one person cannot take over a
  colleague's login. The console tool still works and leaves a security entry that the others see.

If someone is locked out, or loses their phone, the person at the server console recovers them:

```bash
npm run admin -- list
npm run admin -- unlock <email>
npm run admin -- reset-code <email>      # prints a one-time code to hand over in person
npm run admin -- reset-2fa <email>
npm run admin -- create <email> <role> "<Full name>"
```

---

## 4. Settings

Everything is set through environment variables. Nothing is required for a rehearsal. Section 5 says
which ones a real election needs. The same settings are read by the server **and** by the
command-line tools, so run the tools with the same environment as the server.

| Variable | Default | Meaning |
|---|---|---|
| **Network** | | |
| `HOST` | `127.0.0.1` | Address to listen on. Keep it behind a proxy; use `0.0.0.0` only with `TLS_KEY_FILE`/`TLS_CERT_FILE`. |
| `PORT` | `3000` | Port to listen on. |
| `TRUST_PROXY` | *(empty)* | Behind nginx on the same machine use `loopback` (or a hop count such as `1`), so rate limits see each student's real address. |
| `PUBLIC_ORIGIN` | *(empty)* | The address students type, e.g. `https://vote.bouesti.edu.ng`, with no path. Browser requests must come from exactly this origin. |
| `TLS_KEY_FILE`, `TLS_CERT_FILE` | *(empty)* | Serve HTTPS directly. Set both or neither. |
| **Mode** | | |
| `NODE_ENV` | `development` | `production` turns on the safety checks below. |
| `COOKIE_SECURE` | on in production or with TLS | Marks cookies `Secure` and uses the `__Host-` prefix. The server will not start in production without it. |
| `OTP_MODE` | `demo`, or `smtp` in production | `demo` fixed code 123456 (rehearsal only; **refused in production**); `console` real codes printed on the server screen (lab tests); `smtp` real codes by e-mail. |
| `VOTER_PASSWORD` | `password1` | The one shared student password. Leave it unset: `password1` is the only password accepted. |
| **Storage** | | |
| `DATA_DIR` | `./data` | Database, keys, backups, audit copies. Only the account that runs the server should read it. |
| `BACKUP_DIR` | `<DATA_DIR>/backups` | Encrypted backups. |
| `AUDIT_COPY_DIR` | `<DATA_DIR>/audit-copy` | Read-only audit copies. |
| `BACKUP_MIRROR_DIR` | *(empty)* | A second place (USB drive, network share) every backup is also copied to. |
| `BOUESTI_MASTER_KEY` | *(file in `data/keys/`)* | The 32-byte master key as 64 hex characters or base64, if you would rather keep it out of the data folder. |
| **Sessions and accounts** | | |
| `VOTER_IDLE_MIN` / `VOTER_ABSOLUTE_MIN` | `15` / `40` | Student session limits, in minutes. |
| `ADMIN_IDLE_MIN` / `ADMIN_ABSOLUTE_MIN` | `15` / `240` | Administrator session limits, in minutes. |
| `ADMIN_MAX_FAILED` / `ADMIN_LOCK_MIN` | `5` / `15` | Failed attempts before an administrator account locks, and for how long. |
| `SCRYPT_N` | `131072` | Password-hashing cost. Do not lower it except in tests. |
| `RATE_IP_SCALE` | `1` | Multiplies the per-address flood guards. Raise it (e.g. `3`) if many students share one campus address and are being blocked together. Per-student limits are not scaled. |
| **Background work** | | |
| `ENABLE_SCHEDULERS` | `true` | Scheduled backups, restoration drills, audit copies, integrity checks, and opening/closing at the set times. Required for going live. |
| `BACKUP_INTERVAL_MIN` / `BACKUP_RETENTION` | `30` / `48` | Minutes between scheduled backups, and how many scheduled ones to keep. Manual, pre-live, post-live and closing backups are never pruned. |
| `DRILL_INTERVAL_MIN` | `360` | Minutes between automatic restoration drills. |
| `AUDIT_COPY_INTERVAL_MIN` / `AUDIT_COPY_RETENTION` | `60` / `6` | Minutes between audit copies, and how many scheduled ones to keep. |
| **E-mail (`OTP_MODE=smtp`)** | | |
| `SMTP_HOST` | *(empty)* | The mail server. Required for `smtp`. |
| `SMTP_PORT` | `587` | Port 587 (STARTTLS) or 465 (with `SMTP_SECURE=true`). |
| `SMTP_SECURE` | `false` | `true` = encrypted from the first byte (port 465). |
| `SMTP_STARTTLS` | `true` | The connection **must** be upgraded to TLS before any password is sent. A server that does not offer it is refused. `false` only for a trusted internal relay. |
| `SMTP_USER`, `SMTP_PASS` | *(empty)* | Mail account. Never printed in logs or error messages. |
| `SMTP_FROM` | `BOUESTI Vote <no-reply@bouesti.edu.ng>` | The sender shown to students. |
| `SMTP_CA_FILE` | *(empty)* | A PEM file with an extra certificate authority to trust, for a relay whose certificate was issued by the institution's own authority. The certificate is still checked. |
| `SMTP_TIMEOUT_MS` | `15000` | How long to wait for the mail server. |
| **Diagnostics** | | |
| `LOG_REQUESTS` | *(off)* | `1` prints one line per request (route pattern and status only; never paths, queries or cookies). |

Rate limits are listed in `config.js` (`RATE`). In short: sign-in 12 attempts per matric per 15
minutes; code requests 10 per hour; code checks 15 per hour; ballot calls 30 per 10 minutes; every
administrator action has its own limit. Counters live in the database, so a restart does not reset them.

---

## 5. Going live

A real election needs everything in this section. The **Operations → Go-live checklist** page checks
most of it for you and keeps the **Go live…** button disabled, naming what is missing, until it is true.

### 5.1 What production mode does

`NODE_ENV=production` makes the program **refuse to start** (printing the reason) when:

* `OTP_MODE` is `demo`, or is `smtp` without `SMTP_HOST`;
* cookies would not be `Secure`;
* `PUBLIC_ORIGIN` is not a plain address such as `https://vote.bouesti.edu.ng`;
* only one of `TLS_KEY_FILE` / `TLS_CERT_FILE` is set.

It also turns on HSTS, `Secure` cookies with the `__Host-` prefix, and hides the demo code from the
student page.

### 5.2 HTTPS

Passwords, session cookies and ballots must never cross the network in the clear. Choose one:

**A. nginx in front (recommended).** The program listens only on the machine itself. Renewing the
certificate is `nginx -s reload` and never touches the voting server.

```nginx
server {
    listen 80;
    server_name vote.bouesti.edu.ng;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name vote.bouesti.edu.ng;

    ssl_certificate     /etc/ssl/bouesti/fullchain.pem;
    ssl_certificate_key /etc/ssl/bouesti/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;

    client_max_body_size 4m;                      # roster imports (the program allows 3 MB)

    location / {
        proxy_pass         http://127.0.0.1:3000;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Forwarded-For   $remote_addr;   # replaces anything the client sent
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_read_timeout 60s;
    }
}
```

with `HOST=127.0.0.1`, `TRUST_PROXY=loopback` and `PUBLIC_ORIGIN=https://vote.bouesti.edu.ng`. Open only
ports 80 and 443 in the firewall.

**B. The program serves HTTPS itself.** Set `TLS_KEY_FILE` and `TLS_CERT_FILE` (PEM files), `HOST=0.0.0.0`
and `PORT=443`. The program reads the certificate when it starts, so a renewed certificate needs a
restart. Binding port 443 as an ordinary user needs `AmbientCapabilities=CAP_NET_BIND_SERVICE` in the
service file below.

### 5.3 Run it as a service

Create an account that owns the data, and keep the settings in a file that only root and that account
can read (the file holds the mail password):

```bash
sudo useradd --system --home /opt/bouesti-vote --shell /usr/sbin/nologin bouesti
sudo mkdir -p /opt/bouesti-vote /var/lib/bouesti-vote /var/backups/bouesti-vote
# copy the project into /opt/bouesti-vote, then:
cd /opt/bouesti-vote && sudo npm install --omit=dev
sudo chown -R bouesti:bouesti /var/lib/bouesti-vote /var/backups/bouesti-vote
sudo install -m 640 -o root -g bouesti /dev/null /etc/bouesti-vote.env
sudoedit /etc/bouesti-vote.env
```

`/etc/bouesti-vote.env` (quote any value that contains spaces):

```
NODE_ENV=production
HOST=127.0.0.1
PORT=3000
TRUST_PROXY=loopback
PUBLIC_ORIGIN=https://vote.bouesti.edu.ng
DATA_DIR=/var/lib/bouesti-vote
BACKUP_DIR=/var/backups/bouesti-vote
BACKUP_MIRROR_DIR=/mnt/usb-backup/bouesti-vote
SMTP_HOST=mail.bouesti.edu.ng
SMTP_PORT=587
SMTP_USER=no-reply@bouesti.edu.ng
SMTP_PASS=the-mail-account-password
SMTP_FROM="BOUESTI Vote <no-reply@bouesti.edu.ng>"
```

`/etc/systemd/system/bouesti-vote.service`:

```ini
[Unit]
Description=BOUESTI Vote
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=bouesti
Group=bouesti
WorkingDirectory=/opt/bouesti-vote
EnvironmentFile=/etc/bouesti-vote.env
ExecStart=/usr/bin/node --disable-warning=ExperimentalWarning server.js
Restart=on-failure
RestartSec=5
KillSignal=SIGTERM
TimeoutStopSec=20
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/bouesti-vote /var/backups/bouesti-vote /mnt/usb-backup/bouesti-vote

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now bouesti-vote
sudo journalctl -u bouesti-vote -f        # the first-start screen with the keys and one-time passwords
```

Check `which node` and change `ExecStart` to match. Every folder named in `ReadWritePaths` must exist
(drop the mirror path if you do not use `BACKUP_MIRROR_DIR`). This example is standard but could not be
run on your server from here, so test it before the rehearsal. A restart logs nobody out and loses
nothing: sessions, rate-limit counters and the audit log are in the database, and the server records
"Server stopped" and "Server started" in the audit log. (Voting is unavailable for the few seconds it takes.)

Run the command-line tools as the same account with the same settings, for example:

```bash
sudo -u bouesti bash -c 'set -a; . /etc/bouesti-vote.env; set +a; cd /opt/bouesti-vote && npm run backup'
```

Keep the clock correct (NTP). Scheduled opening and closing use the server's clock.

### 5.4 E-mail

Students receive their code from the university's own mail service. Set the `SMTP_*` settings, then
open **Operations → Send a test e-mail**, send one to a real mailbox and check that it arrives. The
go-live checklist requires a delivered test e-mail made with the current mail settings in the last 72
hours.

The mail client verifies the server's certificate and **will not send a password over an unencrypted
connection**. If your relay uses a certificate from the institution's own authority, put that
authority's certificate in a PEM file and set `SMTP_CA_FILE`. The error message names the setting to
change when a certificate is refused. The client was tested against a local test mail server (plain,
STARTTLS, implicit TLS, refusals, timeouts); it has not been run against your provider, which is exactly
why the test e-mail is part of the checklist.

### 5.5 The master key

The key is created on the first start. It cannot be re-created, and nothing replaces it.

1. Keep **two sealed copies, held by two different officers, in two different places.** Never next to
   the backups.
2. Write it down once and prove the copy is right:

   ```bash
   npm run keys -- export                                      # prints the key, after a typed confirmation
   BOUESTI_MASTER_KEY=<the copy you wrote down> npm run keys -- check
   ```
3. Record the **fingerprint** (not the key) in the Committee's minutes and announce the **signing-key
   fingerprint** (`npm run keys`) before voting opens. Observers compare it with the one on the signed
   results.

`docs/OPERATIONS.md` (section 3) has the full rules and what to do if a copy is lost or leaks.

### 5.6 The go-live checklist and going live

**Operations → Go-live checklist** shows each item as passed or failed. Required items:

* production mode; Secure cookies; codes by e-mail; background schedulers on;
* a real test e-mail delivered in the last 72 hours;
* the voter roster loaded; at least one position with an approved candidate;
* an Electoral Officer and a Results Officer who are active; **every active administrator has set a
  password and enrolled two-factor authentication** (disable the placeholder accounts);
* a recent encrypted backup, and **a restoration drill that passed in the last 24 hours**;
* the audit log verifies, and the database passes its integrity check;
* four confirmations that only people can give, recorded with the person's name: **master key kept
  safely**, **roster checked against the official list**, **students told** (dates, address, how the
  code works, where to report problems), **incident contact list held by every officer**.

Advisory items (shown as "recommended", not blocking): a Technical Support Officer exists, free disk
space (1 GB), a second backup location, `TRUST_PROXY` set when behind a proxy, every active student has an
e-mail address, every position has two candidates, and a custom shared password. (The last is only a note:
the brief makes `password1` the student password, and the e-mailed code is the real protection.)

**Go live…** then needs the Electoral Officer's fresh authenticator code *and* the typed words
`GO LIVE`. It takes a safety backup, wipes the rehearsal ballots, closes the roster so only listed
students can sign in (the code goes to the e-mail on file), sets the status to *Upcoming*, writes a signed
audit checkpoint, and takes a second backup. **It cannot be undone**: a live election can never become a
rehearsal again.

### 5.7 Opening, closing and extending

* **Election** sets the name and the opening and closing times (shown in your own time zone, stored in
  UTC). With the status left on *Upcoming* and an opening time still ahead, the server opens voting by
  itself at that time; the page says plainly whether it will. Pressing *Active* opens voting at once.
  At the closing time the server closes voting by itself.
* **A live election cannot be reopened once it is closed,** whether by the clock or by hand, because that
  is what keeps the result trustworthy. Decide any extension at least 15 minutes **before** the closing
  time and agree it with the Committee Chair. A *pause* (status back to *Upcoming*, then *Active*) is
  allowed while the election is running.
* When voting closes the server makes a closing backup, an audit copy and a restoration drill by itself.
* Then the Results Officer prepares the signed report, a different officer publishes it, and observers
  verify it (section 6, and `docs/OPERATIONS.md` sections 10 and 11).

**Do not change the software during voting.** Take the update, test it in a rehearsal, and install it
outside the voting period.

---

## 6. Command-line tools

All run from the project folder. They need access to the data folder and the master key, so they are run
by the person at the server. Anything that changes the election is recorded in the audit log under the
operator's console name.

| Command | What it does |
|---|---|
| `npm start` | Start the server (rehearsal defaults). |
| `npm run start:production` | Start with `NODE_ENV=production`. Normally the service does this. |
| `npm run backup` | Take an encrypted backup now. Safe while students are voting. |
| `npm run drill [-- <backup>]` | **Prove a backup can be restored**: decrypts it into a scratch folder, checks signature, checksum, ballots versus receipts, audit chain and SQLite integrity, reports what a restore would lose, deletes the scratch copy. Exit status 0 only if every check passed. |
| `npm run restore -- <backup> [--yes]` | Replace the database from a backup. Refuses while the server is running; moves the current database aside (never deletes it). |
| `npm run keys [-- check \| public \| export]` | Show fingerprints; confirm the key opens the database; print the signing public key; print the master key to seal. |
| `npm run admin -- <command>` | Recover administrators (list, unlock, reset-code, reset-2fa, disable, enable, create, history, roles). |
| `npm run verify-report -- <report.json> [options]` | **For observers.** Independently verify a signed tally report. |
| `npm run verify-audit -- <export.ndjson \| audit-copy.db> [options]` | **For observers.** Independently verify the audit log. |
| `npm test` | The automated tests (section 7). |
| `npm run test:browser` | Optional real-browser check (section 7). |

**Independent verification (item 6).** The two verification tools are single standalone files. They use
nothing from the election system: no database, no server, no secret, only Node and the file you give them.
An observer copies `scripts/verify-report.js` (and `verify-audit.js`) next to the downloaded files:

```bash
node scripts/verify-report.js signed-report.json \
     --trusted-fingerprint "ABCD 1234 ..." \
     --audit-copy audit-copy-XXXX.db

node scripts/verify-audit.js audit-export.ndjson \
     --trusted-fingerprint "ABCD 1234 ..." --expect-head <hash written down> --expect-entries 1234
```

`verify-report` proves the report is exactly what was signed; that the signing key is the one the
officials announced; that the totals add up; that the publication record names this report and was
approved by a *different* person from the one who prepared it; and, with `--audit-copy`, that counting
the ballots in the read-only copy again from scratch gives the same totals. `verify-audit` recomputes the
whole hash chain and checks every signed checkpoint. Exit status is 0 only when everything checked out.

---

## 7. Tests

```bash
npm test
```

runs **194 automated tests** with Node's built-in test runner (about half a minute on an ordinary
computer). Each file starts from an empty throw-away database, so nothing touches real data. They cover,
in order:

| File | Covers |
|---|---|
| `00-runtime` | An old Node.js stops the server and every tool with a plain message and creates nothing. |
| `01-database` | Schema rules, constraints, the digits-only matric check inside the database. |
| `02-admins` | Hashing, first sign-in, 2FA, replay protection, lockout, reset codes, roles. |
| `03-sessions-ratelimit` | Sessions stored in the database, expiry, rotation, revocation, cookie flags, counters. |
| `04-voters` | Sign-in rules, one vote per student, the e-mail code, the ballot, privacy of the stored ballot. |
| `05-reports` | Signed tally report, tamper detection, two-person publication, the standalone verifier. |
| `06-backup` | Encrypted backups, drills, restores, pruning, the read-only audit copy. |
| `07-http-voter` | The student journey over real HTTP: CSRF, cookies, flood and rate limits. |
| `08-http-admin-auth` | Administrator sign-in, 2FA, step-up, lockout, roles over real HTTP. |
| `09-scripts` | The command-line tools, including the observers' verifiers. |
| `10-http-election` | The election form (item 8): dates, status, name, scheduled opening, validation. |
| `11-mailer` | The e-mail client against a local test server: TLS, STARTTLS, refusals, timeouts. |
| `12-http-lifecycle` | A whole election with the real server **as a separate process**: refused unsafe settings, three officers' first sign-in, go-live, five students voting with their e-mailed codes, closing, counting, publication, an observer verifying with the CLI tools, backups, a restart, and a search of every output for leaked codes, passwords and choices. |

**Real-browser check (optional).** Some faults exist only in a browser: a button that does nothing, a
form that resets while you type. `npm run test:browser` drives the real pages in a real Chromium through
the whole journey (about 190 checks, phone-sized screen included). It needs Playwright, which is not a
dependency of the project:

```bash
npm install --no-save playwright
npx playwright install chromium
npm run test:browser
```

or `PLAYWRIGHT_MODULE=/path/to/node_modules/playwright CHROMIUM_PATH=/path/to/chrome npm run test:browser`.

---

## 8. How the eight requirements are met

| # | Requirement | Where | Proved by |
|---|---|---|---|
| 1 | **Digits-only matric.** `matric 152637` and `matric` are refused; `152637`, `1257`, `173637` pass. | `voters.js` (`validateMatric`), `config.js` (`MATRIC_PATTERN`), a `CHECK` on `students.matric` in `schema.js`, hint in `public/app.js` | `01`, `04`, `07`, `10`, `12`, browser |
| 2 | **`password1` is the only password.** | `voters.js` `login`, compared in constant time with `config.VOTER_PASSWORD` (default `password1`) | `04`, `07`, `12`, browser |
| 3 | **Durable, expiring sessions; cookies; rate limits.** Sessions are in the database (only a hash of the token is stored), with idle and absolute expiry, rotation, logout and revocation. Cookies are `HttpOnly`, `SameSite=Strict`, `Secure` with the `__Host-` prefix in production. CSRF defence. Rate limits on student sign-in, code requests, code checks and ballot calls, and on administrator sign-in, 2FA, password reset, fresh-code confirmation and the heavy operations; the counters are stored in the database, so a restart does not reset them. | `sessions.js`, `ratelimit.js`, `middleware.js`, `config.js` (`RATE`) | `03`, `07`, `08`, `12` (a restart keeps sessions; cookie flags) |
| 4 | **Ballot privacy and audit.** Eligibility and choices live in separate tables with no link. After a ballot is accepted, the only trace of the voter is a keyed hash saying "this person has voted"; the ballot, its selections and its receipt carry no voter reference and no time. The audit log records security events, never choices, and names voters only by a pseudonym. Reading the audit log is itself logged and restricted by role; looking up a voter's trail needs a fresh 2FA code. | `schema.js`, `voters.js` (`castVote`), `audit.js`, `chain.js` | `04`, `07`, `12` (ballot tables, exports, backups and logs searched for leaks), browser |
| 5 | **Backup, recovery and election procedures.** Scheduled encrypted backups, restoration drills, a second backup location, a read-only audit copy, monitoring and alerts on the Operations page, incident log, console tools. The operating procedure includes the student communication plan and incident reporting. | `backup.js`, `backup-core.js`, `scheduler.js`, `ops.js`, `scripts/`, **`docs/OPERATIONS.md`** | `06`, `09`, `12` (closing jobs, downloads, restore checks), browser |
| 6 | **Independent result verification.** Downloadable signed tally report; an append-only, **tamper-evident** event log (hash chain plus signed checkpoints, so any change is detectable, though not physically impossible); supervised comparison of the database totals with the published report by a second official; standalone verifier tools. | `reports.js`, `routes-admin-results.js`, `scripts/verify-report.js`, `scripts/verify-audit.js` | `05`, `09`, `12` (an observer verifies with the CLI tools), browser |
| 7 | **Administrator account security.** Salted password hashes in the database; three roles with least privilege; password-reset records; lockout after repeated failures; two-factor authentication; session expiry. | `admins.js`, `passwords.js`, `totp.js`, `permissions.js`, `routes-admin-auth.js` | `02`, `08`, `09`, `12`, browser |
| 8 | **The election form.** Dates no longer reset, and neither do the status buttons or the election name. The form is drawn once; the background refresh only updates the read-only summary above it, so an open date picker or a half-typed name is never reset. *Discard changes* reverts; saving shows exactly what the server stored; a scheduled opening is explained on the page. | `public/dashboard.js` (election section), `election.js` | `10`, browser (typed values survive refreshes; time-zone round-trip) |

**Note: "Bring out the code for downloading."** The whole project is delivered as one zip, with the same
files listed in section 10. Nothing is minified or generated: every file is the readable source.

---

## 9. How the vote is protected

**What is stored, and what is not.**

| Table | Holds | Does **not** hold |
|---|---|---|
| `students` | matric, name, e-mail, registered / verified / active | whether or how they voted |
| `turnout` | a **keyed hash** of the matric (HMAC), nothing else | the matric, the choices, any time |
| `turnout_hourly` | how many people voted in each hour (for the statistics page) | who they were |
| `ballots`, `ballot_selections` | a random ballot number and its choices | any voter reference, any time |
| `receipts` | a hash of each receipt code | which ballot or voter it belongs to |
| `sessions` | a hash of each session token | the token itself |
| `audit_log` | security events, hash-chained, with voters shown only as a pseudonym (`v-<10 hex>`) | choices, matric numbers, passwords, codes |

The "voted" flag shown beside a student is worked out when the roster is displayed, by hashing each
matric and looking it up in `turnout`. The roster itself never records a vote. Writing the turnout hash and
the ballot happens in **one transaction**, and afterwards nothing connects them.

**The audit log** is a chain: each entry stores the hash of the one before, so changing, removing or
re-ordering any entry breaks everything after it. Because a person who could edit the database could
recompute every hash, the server also **signs checkpoints** (entry number, hash, time) with a key derived
from the master key at important moments (go-live, closing, publication). Officials keep copies, and a
rewritten log can no longer match them.

**Backups** are encrypted (AES-256-GCM) and signed, contain no more than the live database does, and are
never trusted until a drill has restored one.

**Who can do what to the results.** Counting is read-only from the database. Publication needs two
different people. The signed report names the key that signed it, and the standalone verifier checks it
without trusting the server.

---

## 10. Project map

```
server.js            starts everything in the right order and stops it cleanly
runtime.js           the Node.js version check (22.13+)
config.js            every setting, and the checks that refuse an unsafe start
web.js               the Express app (headers, CSRF, flood guard, routes, errors)
middleware.js        security headers, CSRF origin check, request limits, admin session
routes-public.js     student API: state, sign-in, rules, code, ballot, receipt, problems
routes-admin-*.js    administrator API: auth, election and voters, results and operations
voters.js            the student journey and the roster
election.js          offices, candidates, status, scheduled opening, going live
admins.js            administrator accounts, lockout, reset codes, recovery codes
permissions.js       the three roles and their permissions
passwords.js         scrypt hashing, temporary-password generation
totp.js              two-factor codes with replay protection
sessions.js          database-backed sessions and the cookies
ratelimit.js         database-backed rate limits
keys.js              the master key and the keys derived from it
audit.js, chain.js   the pseudonymous, hash-chained, checkpoint-signed audit log
                     (chain.js is plain SHA-256, so the standalone verifiers can recompute it)
reports.js           the signed tally report and its verification
backup.js            backups, drills, audit copies, status
backup-core.js       the backup file format and the restore engine
ops.js               readiness checks, alerts, incidents, test e-mail, step-up
scheduler.js         what runs on a timer, and what runs when voting closes
mailer.js            the e-mail client (TLS verified, STARTTLS required)
db.js, schema.js     the database and its tables
startup.js           what happens once at every start
http.js              turns a refusal from the domain modules into an HTTP answer
public/              the student page, the sign-in page and the dashboard
scripts/             command-line tools: backup, drill, restore, keys, admin,
                     verify-report, verify-audit (+ shared _cli.js)
docs/OPERATIONS.md   the operating procedure
tests/               automated tests; tests/browser is the optional real-browser check
```

---

## 11. Limits

These are the honest edges of what has been built and tested. Read them before relying on the system.

* **Password hashing is scrypt, not Argon2id or bcrypt.** Argon2id and bcrypt need a compiled add-on or a
  third-party package, which would break the "one dependency, nothing to compile" rule. scrypt is a
  memory-hard, salted, standard key-derivation function with OWASP-recommended parameters (N=2^17, r=8,
  p=1); the stored hash records its parameters so it can be upgraded later.
* **The e-mail client has not been tried against your provider.** It is tested against a local test mail
  server only. That is why a delivered test e-mail is a go-live requirement. Please also have a few real
  students receive real codes in the rehearsal.
* **The student password is public.** A shared `password1` identifies nobody. The e-mailed code is the real
  check, so the roster's e-mail addresses must be correct and the university mailboxes must work.
* **One server, one SQLite file.** There is no automatic failover. The recovery plan is the tested backup,
  the restoration drill and the operating procedure, not clustering.
* **HTTPS and key custody are on the institution.** The program refuses to run production without Secure
  cookies, but it cannot make the certificate, the network or the sealed key copies appear.
* **Ballot secrecy has an honest boundary.** It holds against the database snapshot, backups, exports,
  logs and SQL on the final tables: nothing there links a voter to a choice. It cannot hold against a person
  who controls the *running* server (who could watch votes arrive in real time) or who copies the live
  database files in the middle of voting and correlates them with timing outside the system. This is why the
  procedure restricts who can sign in to the server and records every administrative action.
* **A closed live election cannot be reopened or edited.** Extensions must be decided before the closing time.
* **The browser check ran in headless Chromium only,** on one operating system. Phones and other browsers
  were not driven by script.
* **The systemd and nginx examples** in section 5 are standard but were not run on your server.
* **This is software plus a procedure, not an accreditation.** It has not had an independent security audit
  or penetration test. For a real election, commission one and have the Electoral Committee approve the
  operating procedure.

---

## 12. Troubleshooting

**"This program needs Node.js 22.13 or newer."** Install the current LTS release from <https://nodejs.org>.

**The server will not start in production and prints a list.** Each line says what to set. The usual ones:
`OTP_MODE=smtp` needs `SMTP_HOST`; production needs HTTPS or a proxy (leave `COOKIE_SECURE` unset);
`PUBLIC_ORIGIN` must look like `https://vote.bouesti.edu.ng`.

**"The master key does not match this database"** or **"An election database exists but no master key was
found."** The key in `data/keys/master.key` (or `BOUESTI_MASTER_KEY`) is not the one this database was made
with, or is missing. Put the original key back (from the sealed copy). The program deliberately does not
invent a new one. Never delete `election.db` to "fix" it.

**Every request fails with 403, or the page does nothing after sign-in.** `PUBLIC_ORIGIN` does not match
the address in the browser (check `http` versus `https`, `www`, and the port), or the proxy is not passing
the `Host` header.

**Students are told "too many attempts" in groups.** Many students are sharing one campus address and the
server sees them as one. Behind nginx set `TRUST_PROXY=loopback`; if the address really is shared, raise
`RATE_IP_SCALE`. The per-student limits are separate and are never scaled.

**Codes do not arrive.** Open **Operations → Send a test e-mail**; the error names the cause. Wrong
password and certificate problems are explained in plain words (`SMTP_CA_FILE` for a certificate from the
institution's own authority). Check the student's address on the roster, and the spam folder.

**An administrator is locked out or lost the phone.** At the server: `npm run admin -- unlock <email>`,
`npm run admin -- reset-code <email>` or `npm run admin -- reset-2fa <email>`. Hand the one-time code over in
person. During live counting this also leaves a security entry that the other officers see.

**The go-live button is disabled.** The checklist on **Operations** names exactly what is missing. The
usual last items are the restoration drill (**Test a restore now**; it must have passed in the last 24
hours), the test e-mail, the placeholder administrator accounts that were never set up (finish or disable
them), and the four confirmations.

**I need to put the database back.** Stop the server, then `npm run restore -- <backup-file>`. Read
`docs/OPERATIONS.md` section 6 first; it explains what a restore loses and who decides.

**The system said "record is frozen".** The live election has closed and can no longer be changed. That is
intentional (section 5.7).

---

*For the people running the election, continue with [`docs/OPERATIONS.md`](docs/OPERATIONS.md).*
