/*
  BOUESTI Vote — tamper-evident hash chain.

  Every audit-log row stores the hash of the previous row. Changing,
  deleting or re-ordering any row breaks every hash after it, which
  verifyRows() detects. The hash function is plain SHA-256 over a fixed
  JSON encoding, so anyone — including the standalone scripts in
  scripts/ — can recompute it without access to any secret.
*/

"use strict";

const crypto = require("crypto");

const GENESIS_HASH = "0".repeat(64);

function sha256Hex(input) {
  return crypto.createHash("sha256").update(input).digest("hex");
}

function computeHash(prevHash, occurredAt, actor, category, message) {
  return sha256Hex(JSON.stringify([prevHash, occurredAt, actor, category, message]));
}

/*
  rows must be ordered by id ascending. Returns
    { ok: true, count, headId, headHash }
  or
    { ok: false, count, brokenAtId, reason }
  Pass `startHash` when verifying a slice that does not begin at the
  first row.
*/
function verifyRows(rows, startHash = GENESIS_HASH) {
  let previous = startHash;
  let count = 0;
  let headId = 0;

  for (const row of rows) {
    if (row.prevHash !== previous) {
      return {
        ok: false,
        count,
        brokenAtId: row.id,
        reason: "previous-hash link does not match the preceding entry"
      };
    }

    const expected = computeHash(row.prevHash, row.occurredAt, row.actor, row.category, row.message);
    if (row.hash !== expected) {
      return {
        ok: false,
        count,
        brokenAtId: row.id,
        reason: "entry content does not match its stored hash"
      };
    }

    previous = row.hash;
    headId = row.id;
    count += 1;
  }

  return { ok: true, count, headId, headHash: previous };
}

module.exports = { GENESIS_HASH, sha256Hex, computeHash, verifyRows };
