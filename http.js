/*
  BOUESTI Vote — small helpers shared by the route files.
*/

"use strict";

/*
  The domain modules answer with plain objects:
    { ok: true, ... }                                  success
    { ok: false, status?, code?, error, ...extras }    refusal
  This turns a refusal into an HTTP response (and honours Retry-After).
*/
function sendFailure(res, result, fallbackStatus = 400) {
  if (result.retryAfterSec) res.set("Retry-After", String(result.retryAfterSec));

  const { ok, status, ...body } = result;

  if (!body.error && Array.isArray(body.problems) && body.problems.length) {
    body.error = body.problems[0];
  }

  return res.status(status || fallbackStatus).json(body);
}

/* Reply with `result` as JSON if it succeeded, otherwise as an error. */
function reply(res, result, shape = (value) => value) {
  if (!result || result.ok === false) return sendFailure(res, result || { error: "That did not work." });
  return res.json(shape(result));
}

function clientError(res, message, code = "bad-request", status = 400) {
  return res.status(status).json({ error: message, code });
}

/* A strictly positive whole number from a route parameter, or null. */
function idParam(value) {
  const text = String(value ?? "");
  if (!/^\d{1,12}$/.test(text)) return null;

  const number = Number(text);
  return number > 0 ? number : null;
}

function text(value, max = 500) {
  return typeof value === "string" ? value.slice(0, max) : "";
}

function bool(value) {
  return value === true || value === "true" || value === 1 || value === "1";
}

/* Spreadsheet programs run text that starts with = + - @ as a formula, so
   a candidate named "=HYPERLINK(...)" would execute when the CSV is opened. */
function csvCell(value) {
  let cell = String(value ?? "");

  if (/^[=+\-@\t\r]/.test(cell)) cell = `'${cell}`;

  return /[",\n\r]/.test(cell) ? `"${cell.replace(/"/g, '""')}"` : cell;
}

function csvLine(values) {
  return values.map(csvCell).join(",");
}

/* A file name that is safe inside a Content-Disposition header. */
function safeFileName(name) {
  return String(name).replace(/[^A-Za-z0-9._-]+/g, "_").slice(0, 120) || "download";
}

function sendDownload(res, { fileName, contentType, body }) {
  res.setHeader("Content-Type", contentType);
  res.setHeader("Content-Disposition", `attachment; filename="${safeFileName(fileName)}"`);
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.send(body);
}

module.exports = { sendFailure, reply, clientError, idParam, text, bool, csvCell, csvLine, safeFileName, sendDownload };
