/*
  Is this Node.js new enough? — and what does an operator on an old one see?

  node:sqlite works without a special flag from Node 22.13. On anything older the
  program would fail with "No such built-in module: node:sqlite". Instead the
  server and every tool in scripts/ stop at once and say what is needed.
  (The "old Node.js" below is simulated by a tiny preload file that changes the
  version number the program reads; nothing else about the process changes.)
*/

"use strict";

const { test } = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const runtime = require("../runtime");

const ROOT = path.resolve(__dirname, "..");

test("versions before 22.13 get a plain-words message; 22.13 and newer pass", () => {
  ["18.20.4", "20.19.0", "21.7.3", "22.5.0", "22.12.0"].forEach((version) => {
    const problem = runtime.versionProblem(version);

    assert.ok(problem, `${version} is refused`);
    assert.match(problem, /needs Node\.js 22\.13 or newer/);
    assert.ok(problem.includes(version), "it names the version this computer has");
    assert.match(problem, /nodejs\.org/, "and says where to get a newer one");
  });

  ["22.13.0", "22.13.1", "22.22.0", "23.0.0", "24.1.0", "26.7.0"].forEach((version) => {
    assert.strictEqual(runtime.versionProblem(version), null, `${version} is accepted`);
  });

  assert.strictEqual(runtime.versionProblem(), null, "and the Node.js running these tests is new enough");
});

test("package.json promises exactly the version the check enforces", () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));

  assert.strictEqual(manifest.engines.node, `>=${runtime.MINIMUM_TEXT}.0`);
});

test("on an older Node.js the server and every tool stop at once, say why, and create nothing", () => {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "bouesti-oldnode-"));
  const pretend = path.join(work, "pretend-old-node.js");

  fs.writeFileSync(pretend, "Object.defineProperty(process.versions, 'node', { value: '20.1.0' });\n");

  const programs = [
    ["server.js", []],
    ["scripts/backup.js", []],
    ["scripts/restore.js", ["anything.bvbak"]],
    ["scripts/restore-drill.js", []],
    ["scripts/keys.js", []],
    ["scripts/admin-cli.js", ["list"]]
  ];

  try {
    programs.forEach(([script, args]) => {
      const dataDir = path.join(work, `data-${path.basename(script, ".js")}`);

      fs.mkdirSync(dataDir);

      const result = spawnSync(
        process.execPath,
        ["--disable-warning=ExperimentalWarning", "--require", pretend, path.join(ROOT, script), ...args],
        { cwd: ROOT, encoding: "utf8", env: { ...process.env, DATA_DIR: dataDir, BOUESTI_MASTER_KEY: "" }, timeout: 20000 }
      );

      const output = `${result.stdout}${result.stderr}`;

      assert.strictEqual(result.status, 1, `${script} stops with status 1:\n${output}`);
      assert.match(output, /needs Node\.js 22\.13 or newer, and this computer has 20\.1\.0/, `${script} explains why`);
      assert.ok(!/built-in module|ERR_UNKNOWN_BUILTIN/.test(output), `${script} does not show the cryptic error`);
      assert.deepStrictEqual(fs.readdirSync(dataDir), [], `${script} created nothing`);
    });
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }
});
