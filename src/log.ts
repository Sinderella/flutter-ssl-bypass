/**
 * Single output funnel for the agent + repair-time diagnostic dump.
 *
 * Surface:
 *   - mustResolve<T>(label, fn): T   — strict throwing wrapper for "must succeed or abort" resolves
 *   - logAnchor / logTrace / logSelfTest — prefix-conventional helpers
 *   - _A_diagState                    — shared mutable diagnostic singleton
 *   - _A_writeAutoDiag                — repair-time dump, preserved verbatim from JS
 *
 * `_A_writeAutoDiag` is preserved verbatim from flutter-ssl-bypass.js — it is
 * repair-time tribal knowledge. Removing or simplifying it would lose IP.
 *
 * This file is the agent's only side-effectful module: it IS allowed to call
 * `Memory.scan*`, `Module.*`, etc. via the auto-diag path. The pure modules
 * (types/, platform/, anchor-chain.ts) delegate critical resolves through
 * `mustResolve` instead of `!` assertions.
 */

import "./types/globals";

// NOTE on the circular dependency between log.ts and anchor-chain.ts:
//
// `_A_writeAutoDiag` (this file) calls into anchor-chain's scan helpers when a
// `Module` is supplied. `anchor-chain.ts` calls `_A_writeAutoDiag` from
// `selfTest`. Both modules import each other.
//
// In ESM, top-level imports are hoisted before either module body runs, so the
// circular reference resolves cleanly at runtime — function bindings are looked
// up lazily by name when called. The only thing we MUST avoid is using imported
// values at module-init / top-level scope (we don't).
//
// The original JS used hoisted function declarations in a single file; this
// pattern is the ESM equivalent and produces the same runtime semantics.
import {
  _A_findAdrpAddXrefs,
  _A_findAllStringsInModule,
  _A_getModuleSubranges,
  _A_isStubAtAdrp,
} from "./anchor-chain";

export function log(msg: string): void {
  console.log(msg);
}

export function logAnchor(msg: string): void {
  console.log(`[anchor] ${msg}`);
}

export function logTrace(msg: string): void {
  console.log(`[trace] ${msg}`);
}

export function logSelfTest(msg: string): void {
  console.log(`[self-test] ${msg}`);
}

/**
 * Strict throwing wrapper around any "must succeed or abort" Frida resolve.
 * Returns `T` (TypeScript narrows the type — caller never needs the `!`
 * non-null assertion that biome's `noNonNullAssertion` rule forbids in src/).
 *
 * On null/undefined return: logs `[!] mustResolve("<label>") returned ...`,
 * triggers an auto-diag dump, and throws a hard `Error`.
 */
export function mustResolve<T>(label: string, fn: () => T | null | undefined): T {
  const result = fn();
  if (result === null || result === undefined) {
    console.error(`[!] mustResolve("${label}") returned null/undefined`);
    _A_writeAutoDiag(`mustResolve(${label}) failed`, null);
    throw new Error(`mustResolve(${label}) failed`);
  }
  return result;
}

/**
 * Shared mutable diagnostic singleton — ported VERBATIM from
 * flutter-ssl-bypass.js lines 585-594. Hooks update these fields; watchdog
 * timers in main.ts read them; auto-diag includes them in the dump.
 */
export const _A_diagState: {
  written: boolean;
  hookEnterCount: number;
  hookRetvalZeroCount: number;
  hookRetvalOneCount: number;
  socketOverwriteCount: number;
  resolvedVccAddr: string | null;
  resolvedVccVia: string | null;
  candidatesDump: string;
} = {
  written: false,
  hookEnterCount: 0,
  hookRetvalZeroCount: 0,
  hookRetvalOneCount: 0,
  socketOverwriteCount: 0,
  resolvedVccAddr: null,
  resolvedVccVia: null,
  candidatesDump: "",
};

/**
 * Repair-time diagnostic dump — preserved verbatim from JS for parity.
 * Operator pulls the auto-diag file via `adb pull` and uses it as the starting
 * point for re-anchoring the SSL hook against a new libflutter codegen.
 *
 * Ported from flutter-ssl-bypass.js lines 596-709. Behavior preserved:
 *   - dumps once per session (gated by `_A_diagState.written`)
 *   - tries `/data/local/tmp`, `/sdcard`, the app's files dir in order
 *   - on write failure, falls back to inline `console.error` dump
 *   - on success, prints the `adb pull <path>` instruction
 *
 * The `mod` param is `Module | null`; when null the function attempts
 * `Process.findModuleByName("libflutter.so")` as a fallback (matches the JS
 * behavior at line 624).
 */
export function _A_writeAutoDiag(reason: string, modOrNull: Module | null): void {
  if (_A_diagState.written) return;
  _A_diagState.written = true;

  const lines: string[] = [];
  const push = (s: string): void => {
    lines.push(s);
  };

  push("=== Auto-diagnostic dump ===");
  push("Reason: " + reason);
  push("Time: " + new Date().toISOString());
  push("Process.arch: " + Process.arch);
  push("Process.platform: " + Process.platform);
  push("");

  push("--- Hook state ---");
  push("verify_cert_chain resolved addr: " + _A_diagState.resolvedVccAddr);
  push("verify_cert_chain resolved via:  " + _A_diagState.resolvedVccVia);
  push("verify_cert_chain ENTER count:   " + _A_diagState.hookEnterCount);
  push("verify_cert_chain retval=0 seen: " + _A_diagState.hookRetvalZeroCount);
  push("verify_cert_chain retval=1 seen: " + _A_diagState.hookRetvalOneCount);
  push("socket overwrite count:          " + _A_diagState.socketOverwriteCount);
  push("");

  push("--- Candidates seen during resolution ---");
  push(_A_diagState.candidatesDump || "(none)");
  push("");

  let mod = modOrNull;
  if (!mod) {
    try {
      mod = Process.findModuleByName("libflutter.so");
    } catch (_e) {
      // findModuleByName threw — leave `mod` as null
    }
  }

  if (mod) {
    push("--- Module ---");
    push("name: " + mod.name);
    push("path: " + mod.path);
    push("base: " + mod.base);
    push("size: 0x" + mod.size.toString(16));
    push("");

    push("--- Process.enumerateRanges (intersected with module window) ---");
    ["r--", "r-x", "rw-", "--x"].forEach((filter) => {
      let rs: { base: NativePointer; size: number; protection: string }[];
      try {
        rs = _A_getModuleSubranges(mod as Module, filter);
      } catch (_e) {
        rs = [];
      }
      push("  '" + filter + "' : " + rs.length);
      for (let i = 0; i < rs.length; i++) {
        const r = rs[i];
        if (r === undefined) continue;
        push("    " + r.base + "  size=0x" + r.size.toString(16) + "  prot=" + r.protection);
      }
    });
    push("");

    [
      "../../../flutter/third_party/boringssl/src/ssl/ssl_x509.cc",
      "../../../flutter/third_party/boringssl/src/ssl/handshake.cc",
      "ssl_client",
      "ssl_server",
    ].forEach((s) => {
      push("--- String scan: " + s + " ---");
      let hits: NativePointer[];
      try {
        hits = _A_findAllStringsInModule(mod as Module, s);
      } catch (_e) {
        hits = [];
      }
      push("  hits: " + hits.length);
      for (let h = 0; h < hits.length && h < 10; h++) {
        const hit = hits[h];
        if (hit === undefined) continue;
        push("    " + hit);
        try {
          const xrefs = _A_findAdrpAddXrefs(mod as Module, hit);
          push("      adrp+add xrefs: " + xrefs.length);
          for (let x = 0; x < xrefs.length && x < 8; x++) {
            const ax = xrefs[x];
            if (ax === undefined) continue;
            const isStub = _A_isStubAtAdrp(ax);
            let line = "        " + ax + "  isStub=" + isStub;
            try {
              const parsed = Instruction.parse(ax);
              const mnemo = parsed.mnemonic + " " + (parsed.opStr || "");
              line += "  (" + mnemo + ")";
            } catch (_e) {
              // Instruction.parse threw — leave the line without the disassembly suffix
            }
            push(line);
          }
        } catch (e) {
          push("      (xref scan threw: " + (e as Error).message + ")");
        }
      }
      push("");
    });
  }

  push("=== end diag ===");

  const body = lines.join("\n");
  const ts = Date.now();
  let pkg = "unknown";
  try {
    pkg = Java.use("android.app.ActivityThread")
      .currentApplication()
      .getApplicationContext()
      .getPackageName()
      .toString();
  } catch (_e) {
    // Java bridge unavailable (iOS) or app not yet attached — keep "unknown"
  }

  const paths = [
    "/data/local/tmp/flutter-bypass-diag-" + ts + ".txt",
    "/sdcard/flutter-bypass-diag-" + ts + ".txt",
    "/data/data/" + pkg + "/files/flutter-bypass-diag-" + ts + ".txt",
  ];
  let written: string | null = null;
  for (let pi = 0; pi < paths.length; pi++) {
    try {
      const path = paths[pi];
      if (path === undefined) continue;
      const f = new File(path, "w");
      f.write(body);
      f.flush();
      f.close();
      written = path;
      break;
    } catch (_e) {
      // try next path
    }
  }

  if (written) {
    console.error("[auto-diag] " + reason + " — wrote " + body.length + " bytes to " + written);
    console.error("[auto-diag] pull with: adb pull " + written);
  } else {
    console.error("[auto-diag] " + reason + " — failed to write file, dumping inline:");
    console.error(body);
  }
}
