/*
  BOUESTI Vote — sends the one-time codes.

  OTP_MODE=smtp     a minimal SMTP client (implicit TLS on 465, or
                    STARTTLS on 587, then AUTH PLAIN/LOGIN). Works with
                    any ordinary mail provider or the university's relay.
  OTP_MODE=console  prints the message to the server console (lab tests).
  OTP_MODE=demo     nothing is sent (the fixed demo code is accepted).

  Written with node:net / node:tls only, to keep the project free of
  third-party code. It has been exercised against a local fake SMTP server
  (tests/11-mailer.test.js) — plain, implicit TLS, STARTTLS, both AUTH
  methods, refusals and dropped connections — but NOT against a real provider.
  Connect it to your real provider and send yourself a test code (Operations →
  "Send a test e-mail") before the election.

  Safety rules this client keeps
    - The server's certificate is always verified. A relay with a private
      authority's certificate is trusted by naming that authority in
      SMTP_CA_FILE; verification is never switched off.
    - With SMTP_STARTTLS=true (the default) a server that does not offer
      STARTTLS is refused, so nobody on the network can strip the encryption
      and read the SMTP password or the codes.
    - Error messages never repeat anything that was sent as a credential.
*/

"use strict";

const fs = require("fs");
const net = require("net");
const tls = require("tls");
const crypto = require("crypto");
const config = require("./config");

/* Read when used, so a test (or an operator changing the environment and restarting) takes effect. */
function timeoutMs() {
  return config.SMTP_TIMEOUT_MS;
}

/* The extra authority named in SMTP_CA_FILE, added to the ordinary list. Verification stays on. */
function trustedAuthorities() {
  if (!config.SMTP_CA_FILE) return undefined;

  return [...tls.rootCertificates, fs.readFileSync(config.SMTP_CA_FILE, "utf8")];
}

/* An address is not a valid TLS server name; only a host name is sent. */
function serverNameFor(host) {
  return net.isIP(host) ? undefined : host;
}

/*
  A certificate problem on its own ("self-signed certificate") does not tell an
  operator what to do. Say what to check. Nothing secret is in these messages.
*/
const CERTIFICATE_PROBLEMS = new Set([
  "DEPTH_ZERO_SELF_SIGNED_CERT",
  "SELF_SIGNED_CERT_IN_CHAIN",
  "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
  "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
  "UNABLE_TO_GET_ISSUER_CERT",
  "CERT_HAS_EXPIRED",
  "CERT_NOT_YET_VALID",
  "CERT_UNTRUSTED",
  "ERR_TLS_CERT_ALTNAME_INVALID"
]);

function explainTlsError(error) {
  if (!error || !CERTIFICATE_PROBLEMS.has(error.code)) return error;

  const explained = new Error(
    `The mail server's security certificate was not accepted (${error.message}). ` +
      "Check that SMTP_HOST is the name the certificate was issued for and that it has not expired. " +
      "If your own authority signed it, set SMTP_CA_FILE to that authority's certificate. " +
      "The check is never switched off."
  );

  explained.code = error.code;

  return explained;
}

/* Which step failed, without ever repeating what was sent (it may be a password). */
const KNOWN_STEPS = new Set(["EHLO", "STARTTLS", "AUTH", "MAIL", "RCPT", "DATA", "QUIT"]);

function describeStep(line) {
  const verb = String(line).split(/[ :]/)[0].toUpperCase();

  return KNOWN_STEPS.has(verb) ? verb : "a sign-in step";
}

class SmtpConnection {
  constructor(socket) {
    this.socket = socket;
    this.buffer = "";
    this.failure = null;
    this.waiting = null;

    /* Kept by name so detach() can remove exactly these and nothing else. */
    this.listeners = {
      data: (chunk) => {
        this.buffer += chunk;
        this.deliver();
      },
      error: (error) => this.fail(error),
      close: () => this.fail(new Error("SMTP connection closed unexpectedly.")),
      timeout: () => this.fail(new Error("SMTP connection timed out."))
    };

    socket.setEncoding("utf8");
    socket.setTimeout(timeoutMs());

    Object.entries(this.listeners).forEach(([event, listener]) => socket.on(event, listener));
  }

  /* Stop listening (before the socket is wrapped in TLS, or when finished). */
  detach() {
    Object.entries(this.listeners).forEach(([event, listener]) => this.socket.off(event, listener));
    this.socket.setTimeout(0);
  }

  fail(error) {
    if (!this.failure) this.failure = error;
    this.deliver();
  }

  /* Pull one complete (possibly multi-line) reply out of the buffer. */
  parseReply() {
    const lines = this.buffer.split("\r\n");
    const collected = [];

    for (let index = 0; index < lines.length - 1; index += 1) {
      const match = /^(\d{3})([ -])/.exec(lines[index]);
      collected.push(lines[index]);

      if (match && match[2] === " ") {
        this.buffer = lines.slice(index + 1).join("\r\n");
        return { code: Number(match[1]), lines: collected };
      }
    }

    return null;
  }

  deliver() {
    if (!this.waiting) return;

    const reply = this.parseReply();

    if (reply) {
      const { resolve } = this.waiting;
      this.waiting = null;
      resolve(reply);
    } else if (this.failure) {
      const { reject } = this.waiting;
      this.waiting = null;
      reject(this.failure);
    }
  }

  readReply() {
    return new Promise((resolve, reject) => {
      this.waiting = { resolve, reject };
      this.deliver();
    });
  }

  async command(line, expected) {
    if (this.failure) throw this.failure;

    this.socket.write(`${line}\r\n`);
    const reply = await this.readReply();

    if (!expected.includes(reply.code)) {
      throw new Error(`SMTP server replied ${reply.code} to ${describeStep(line)}.`);
    }

    return reply;
  }

  close() {
    this.detach();
    this.socket.on("error", () => {}); // a late error on a socket we are discarding is not news
    this.socket.destroy();
  }
}

function connect() {
  return new Promise((resolve, reject) => {
    const options = { host: config.SMTP_HOST, port: config.SMTP_PORT };

    if (config.SMTP_SECURE) {
      options.servername = serverNameFor(config.SMTP_HOST);
      options.ca = trustedAuthorities();
    }

    const socket = config.SMTP_SECURE ? tls.connect(options) : net.connect(options);
    const readyEvent = config.SMTP_SECURE ? "secureConnect" : "connect";

    /* Stays attached until the connection succeeds, so a second error cannot go unhandled. */
    const onError = (error) => reject(config.SMTP_SECURE ? explainTlsError(error) : error);

    const onTimeout = () => {
      socket.destroy();
      reject(new Error("Could not reach the SMTP server in time."));
    };

    socket.once(readyEvent, () => {
      /* Connected: the session object takes over the listeners and the timer. */
      socket.off("error", onError);
      socket.off("timeout", onTimeout);
      socket.setTimeout(0);
      resolve(socket);
    });

    socket.on("error", onError);
    socket.setTimeout(timeoutMs(), onTimeout);
  });
}

function addressOnly(from) {
  const match = /<([^>]+)>/.exec(from);
  return (match ? match[1] : from).trim();
}

function encodeHeader(text) {
  return /^[\x20-\x7e]*$/.test(text) ? text : `=?UTF-8?B?${Buffer.from(text, "utf8").toString("base64")}?=`;
}

async function smtpSend({ to, subject, text }) {
  if (!/^[^\s@<>"]+@[^\s@<>"]+$/.test(to)) throw new Error("Invalid recipient address.");

  const envelopeFrom = addressOnly(config.SMTP_FROM);
  let connection = new SmtpConnection(await connect());

  try {
    await connection.readReply().then((reply) => {
      if (reply.code !== 220) throw new Error("SMTP server did not greet us.");
    });

    let hello = await connection.command("EHLO bouesti-vote.local", [250]);
    const offers = hello.lines.join(" ").toUpperCase();

    if (!config.SMTP_SECURE && config.SMTP_STARTTLS) {
      /* Required, not optional: a server that "forgets" to offer it must not talk us into sending in the clear. */
      if (!offers.includes("STARTTLS")) {
        throw new Error(
          "The mail server does not offer STARTTLS, so the connection would not be encrypted. " +
            "Use SMTP_SECURE=true (port 465), or set SMTP_STARTTLS=false only for a trusted internal relay."
        );
      }

      await connection.command("STARTTLS", [220]);

      const upgraded = tls.connect({
        socket: connection.socket,
        servername: serverNameFor(config.SMTP_HOST),
        ca: trustedAuthorities()
      });

      /* A refused handshake can be followed by a second error on the same socket; never let it crash the server. */
      upgraded.on("error", () => {});

      await new Promise((resolve, reject) => {
        upgraded.once("secureConnect", resolve);
        upgraded.once("error", (error) => reject(explainTlsError(error)));
      });

      /* Hand the conversation over to the secure socket. */
      connection.detach();
      connection.socket.on("error", () => {}); // the plain socket is finished; a late error on it is not news
      connection = new SmtpConnection(upgraded);
      hello = await connection.command("EHLO bouesti-vote.local", [250]);
    }

    if (config.SMTP_USER) {
      const credentials = Buffer.from(`\0${config.SMTP_USER}\0${config.SMTP_PASS}`).toString("base64");

      try {
        await connection.command(`AUTH PLAIN ${credentials}`, [235]);
      } catch (plainError) {
        await connection.command("AUTH LOGIN", [334]);
        await connection.command(Buffer.from(config.SMTP_USER).toString("base64"), [334]);
        await connection.command(Buffer.from(config.SMTP_PASS).toString("base64"), [235]);
      }
    }

    await connection.command(`MAIL FROM:<${envelopeFrom}>`, [250]);
    await connection.command(`RCPT TO:<${to}>`, [250, 251]);
    await connection.command("DATA", [354]);

    const message = [
      `From: ${config.SMTP_FROM}`,
      `To: <${to}>`,
      `Subject: ${encodeHeader(subject)}`,
      `Date: ${new Date().toUTCString()}`,
      `Message-ID: <${crypto.randomBytes(12).toString("hex")}@bouesti-vote>`,
      "MIME-Version: 1.0",
      "Content-Type: text/plain; charset=utf-8",
      "Content-Transfer-Encoding: base64",
      "",
      Buffer.from(text, "utf8").toString("base64").replace(/(.{76})/g, "$1\r\n"),
      "."
    ].join("\r\n");

    // The body is base64, so no line can start with a dot that needs stuffing.
    connection.socket.write(`${message}\r\n`);
    const accepted = await connection.readReply();
    if (accepted.code !== 250) throw new Error(`SMTP server rejected the message (${accepted.code}).`);

    await connection.command("QUIT", [221]).catch(() => {});
  } finally {
    connection.close();
  }

  return { ok: true, via: "smtp" };
}

async function send(message) {
  if (config.OTP_MODE === "smtp") return smtpSend(message);

  if (config.OTP_MODE === "console") {
    console.log(`\n[mail → ${message.to}] ${message.subject}\n${message.text}\n`);
    return { ok: true, via: "console" };
  }

  return { ok: true, via: "none" };
}

module.exports = { send };
