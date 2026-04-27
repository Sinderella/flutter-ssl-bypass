#!/usr/bin/env bun
/**
 * Bundle smoke validator.
 *
 * Runs HOST-SIDE under Bun (NOT inside Frida). Lives in scripts/, NOT src/, so
 * it's allowed to use Node/Bun APIs that are banned from agent code. biome.json
 * `files.includes` negation excludes scripts; tsconfig.json `include` is scoped
 * to src only — this file is intentionally excluded from typecheck/lint.
 *
 * Asserts:
 *   1. dist/flutter-ssl-bypass.js exists, > 0 bytes
 *   2. File size in the band [10240, 51200] bytes (10-50 KB). The actual bundle
 *      lands at ~20 KB (frida-compile + ES2022 lib + Biome dead-code elim are
 *      aggressive). Floor 10 KB catches a future tree-shaking bug that nukes
 *      a real module; ceiling 50 KB catches accidental source-map inlining or
 *      Node polyfill leak. Out-of-band is a PR-fail, NOT a warning.
 *   3. Bundle contains all required canary strings:
 *        - "decoder bit-math OK"                           (selfTest)
 *        - "[!] flutter-ssl-bypass requires Frida 17.x"    (Frida 17 API probe)
 *        - "[!] Parameters API rejected:"                  (parameters validator)
 *        - "[*] Hook GetSockAddr function"                 (socket redirect)
 *        - "verify_cert_chain"                             (resolver / hook)
 *   4. Bundle contains NO Node-only requires
 *      (`require("fs"|"path"|"os"|"crypto"|"child_process")`).
 *
 * If any assertion fails, exits non-zero so CI fails loud.
 */

import { readFileSync, statSync } from "node:fs";

const ARTIFACT = "dist/flutter-ssl-bypass.js";

const REQUIRED_CANARIES = [
  "decoder bit-math OK",
  "[!] flutter-ssl-bypass requires Frida 17.x",
  "[!] Parameters API rejected:",
  "[*] Hook GetSockAddr function",
  "verify_cert_chain",
];

const FORBIDDEN_REQUIRES = [
  /require\("fs"/,
  /require\("path"/,
  /require\("os"/,
  /require\("crypto"/,
  /require\("child_process"/,
  /require\("node:fs"/,
  /require\("node:path"/,
];

const SIZE_MIN = 10_240;
const SIZE_MAX = 51_200;

function fail(msg: string): never {
  console.error(`[verify:smoke] FAIL: ${msg}`);
  process.exit(1);
}

let stat;
try {
  stat = statSync(ARTIFACT);
} catch {
  fail(`${ARTIFACT} does not exist — run 'bun run build' first`);
}

if (!stat.isFile()) fail(`${ARTIFACT} exists but is not a file`);
if (stat.size === 0) fail(`${ARTIFACT} is empty (0 bytes)`);
if (stat.size < SIZE_MIN) {
  fail(
    `${ARTIFACT} is ${stat.size} bytes, below SIZE_MIN=${SIZE_MIN} (band [10240, 51200]). Bundler likely tree-shook the agent body — verify src/main.ts pulls in all modules. See .github/workflows/ci.yml comment for context.`,
  );
}
if (stat.size > SIZE_MAX) {
  fail(
    `${ARTIFACT} is ${stat.size} bytes, above SIZE_MAX=${SIZE_MAX} (band [10240, 51200]). Likely sourcemap-inlining regression or Node polyfill leak — check the build flags and bundler output. See .github/workflows/ci.yml comment for context.`,
  );
}

const contents = readFileSync(ARTIFACT, "utf8");

const missing: string[] = [];
for (const canary of REQUIRED_CANARIES) {
  if (!contents.includes(canary)) missing.push(canary);
}
if (missing.length > 0) {
  fail(`${ARTIFACT} missing required canaries: ${missing.map((c) => `'${c}'`).join(", ")}`);
}

const leaked: string[] = [];
for (const re of FORBIDDEN_REQUIRES) {
  if (re.test(contents)) leaked.push(re.source);
}
if (leaked.length > 0) {
  fail(`${ARTIFACT} contains Node-only requires: ${leaked.join(", ")}`);
}

console.log(
  `[verify:smoke] OK — ${ARTIFACT} (${stat.size} bytes), ${REQUIRED_CANARIES.length} canaries present, no Node-leak`,
);
