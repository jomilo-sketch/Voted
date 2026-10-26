/*
  BOUESTI Vote — is this Node.js new enough?

  The database is node:sqlite, which is built into Node.js (no add-on to
  compile). Before Node 22.13 it sat behind a command-line flag; from 22.13 it
  is available as it is, together with the options this program uses. On an
  older Node the failure would be "No such built-in module: node:sqlite", which
  tells an operator nothing — so say what is needed instead.

  Used by server.js and by every tool in scripts/. Depends on nothing.
*/

"use strict";

const MINIMUM = { major: 22, minor: 13 };
const MINIMUM_TEXT = `${MINIMUM.major}.${MINIMUM.minor}`;

/* null when the version is fine, otherwise a sentence an operator can act on. */
function versionProblem(version = process.versions.node) {
  const [major, minor] = String(version).split(".").map(Number);
  const fine = major > MINIMUM.major || (major === MINIMUM.major && minor >= MINIMUM.minor);

  if (fine) return null;

  return (
    `This program needs Node.js ${MINIMUM_TEXT} or newer, and this computer has ${version}. ` +
    "Install the current LTS release from https://nodejs.org and try again."
  );
}

module.exports = { MINIMUM, MINIMUM_TEXT, versionProblem };
