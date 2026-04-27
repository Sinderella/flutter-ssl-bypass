/**
 * Anchor-resolution helpers.
 *
 * Strict-verbatim port from flutter-ssl-bypass.js lines 203-768. Edits are
 * limited to (a) what TypeScript refuses to compile and (b) the shape changes
 * required by the modular split.
 *
 * Side-effect note: this file uses `Memory.scanSync` inside
 * `_A_findAllStringsInModule` and `_A_findAdrpAddXrefs`. A future testability
 * seam may inject the scan dependency; for now the calls remain inline.
 *
 * `_A_selfTest()` body is preserved verbatim; the exported wrapper is named
 * `selfTest` and is called explicitly from src/main.ts at script-load
 * (relocated from the JS IIFE at line 1333).
 */

import { _A_writeAutoDiag, log, logAnchor, logSelfTest } from "./log";
import type { GroundTruthRange, GroundTruthTable } from "./types/anchor";

/**
 * Workaround for `Module.enumerateRanges(filter)` returning empty on some
 * Android+Frida combos (verbatim from JS lines 200-216). Falls back to
 * `Process.enumerateRanges(filter)` intersected with the module window.
 */
export function _A_getModuleSubranges(
  mod: Module,
  filter: string,
): { base: NativePointer; size: number; protection: string }[] {
  const modStart = mod.base;
  const modEnd = mod.base.add(mod.size);
  const out: { base: NativePointer; size: number; protection: string }[] = [];
  let rs: { base: NativePointer; size: number; protection: string }[];
  try {
    rs = Process.enumerateRanges(filter as PageProtection) as {
      base: NativePointer;
      size: number;
      protection: string;
    }[];
  } catch (_e) {
    rs = [];
  }
  for (let i = 0; i < rs.length; i++) {
    const r = rs[i];
    if (r === undefined) continue;
    if (r.base.add(r.size).compare(modStart) <= 0) continue;
    if (r.base.compare(modEnd) >= 0) continue;
    out.push(r);
  }
  return out;
}

export function _A_getTextRange(mod: Module): { base: NativePointer; size: number } {
  // Prefer the largest executable-containing range inside the module window.
  let candidates = _A_getModuleSubranges(mod, "r-x");
  if (candidates.length === 0) candidates = _A_getModuleSubranges(mod, "--x");
  let biggest: { base: NativePointer; size: number } | null = null;
  for (let i = 0; i < candidates.length; i++) {
    const r = candidates[i];
    if (r === undefined) continue;
    if (!biggest || r.size > biggest.size) biggest = r;
  }
  // Fallback: the whole module window.
  if (!biggest) biggest = { base: mod.base, size: mod.size };
  return biggest;
}

/**
 * Return ALL executable subranges inside the module window. Some libflutter
 * builds split BoringSSL/icu/libcxx/etc into multiple r-x sections separated
 * by tiny rwx pages (observed: 7-8 distinct r-x ranges on the target build).
 * The largest range is typically only the Flutter engine .text; BoringSSL
 * functions can live in the secondary 3 MB r-x or 148 KB r-x sections.
 * Scanning only the biggest range silently MISSES xrefs and BL callers in
 * those secondary sections — exactly how the stub-caller chain was failing
 * on this target.
 */
export function _A_getAllTextRanges(mod: Module): { base: NativePointer; size: number }[] {
  let ranges: { base: NativePointer; size: number }[] = _A_getModuleSubranges(mod, "r-x");
  if (ranges.length === 0) ranges = _A_getModuleSubranges(mod, "--x");
  if (ranges.length === 0) ranges = [{ base: mod.base, size: mod.size }];
  return ranges;
}

export function _A_asciiToHexPattern(str: string): string {
  let out = "";
  for (let i = 0; i < str.length; i++) {
    if (i > 0) out += " ";
    out += str.charCodeAt(i).toString(16).padStart(2, "0");
  }
  return out;
}

export function _A_findAllStringsInModule(mod: Module, str: string): NativePointer[] {
  const pattern = _A_asciiToHexPattern(str);
  const results: NativePointer[] = [];
  const seen: Record<string, boolean> = {};

  // Scan the whole module window first — works regardless of section split.
  try {
    const matches = Memory.scanSync(mod.base, mod.size, pattern);
    for (let j = 0; j < matches.length; j++) {
      const match = matches[j];
      if (match === undefined) continue;
      const addr = match.address;
      try {
        if (addr.add(str.length).readU8() === 0) {
          const key = addr.toString();
          if (!seen[key]) {
            seen[key] = true;
            results.push(addr);
          }
        }
      } catch (_e) {
        // unreadable trailing byte — skip
      }
    }
  } catch (_e) {
    /* fall through to sub-range scanning */
  }

  // Also scan individual mapped sub-ranges (r--, r-x) as a belt-and-braces pass.
  const subs = _A_getModuleSubranges(mod, "r--").concat(_A_getModuleSubranges(mod, "r-x"));
  for (let s = 0; s < subs.length; s++) {
    const sub = subs[s];
    if (sub === undefined) continue;
    try {
      const m2 = Memory.scanSync(sub.base, sub.size, pattern);
      for (let k = 0; k < m2.length; k++) {
        const match = m2[k];
        if (match === undefined) continue;
        const a = match.address;
        try {
          if (a.add(str.length).readU8() === 0) {
            const kk = a.toString();
            if (!seen[kk]) {
              seen[kk] = true;
              results.push(a);
            }
          }
        } catch (_e) {
          // skip
        }
      }
    } catch (_e) {
      // skip
    }
  }

  return results;
}

/**
 * Scan .text for every ADRP+ADD pair (any register, with register continuity)
 * that computes `targetAddr`. Returns array of NativePointer at each ADRP.
 */
export function _A_findAdrpAddXrefs(mod: Module, targetAddr: NativePointer): NativePointer[] {
  // Scan EVERY executable subrange — see _A_getAllTextRanges comment for why.
  const ranges = _A_getAllTextRanges(mod);
  const results: NativePointer[] = [];
  const pageMask = ptr("0xfffffffffffff000");

  for (let ri = 0; ri < ranges.length; ri++) {
    const rng = ranges[ri];
    if (rng === undefined) continue;
    let p = rng.base;
    const end = rng.base.add(rng.size);

    while (p.compare(end) < 0) {
      let insn: number;
      // On unreadable page, skip to next page boundary and KEEP SCANNING.
      // A `break` here would silently truncate scans of large .text regions
      // if any single page fails — observed on this target.
      try {
        insn = p.readU32();
      } catch (_e) {
        const aligned = p.and(pageMask).add(0x1000);
        p = aligned;
        continue;
      }

      // ADRP: bits 31=1, 28-24=10000 (mask 0x9F000000, value 0x90000000)
      // Note: `0x90000000 | 0` forces signed-Int32 comparison since JS bitwise ops
      // return signed Int32 and the high bit of the mask produces a negative result.
      if ((insn & 0x9f000000) === (0x90000000 | 0)) {
        const adrpRd = insn & 0x1f;
        const immhi = (insn >>> 5) & 0x7ffff;
        const immlo = (insn >>> 29) & 0x3;
        let imm = (immhi << 2) | immlo;
        if (imm & 0x100000) imm |= ~0x1fffff; // sign-extend 21-bit
        const pcPage = p.and(pageMask);
        const adrpTarget = pcPage.add(imm * 0x1000);

        try {
          const next = p.add(4).readU32();
          // ADD (immediate) 64-bit: top 9 bits = 100100010 (0x91 with sh=0 at pos 22)
          if ((next & 0x7fc00000) === 0x11000000) {
            const shift = (next >>> 22) & 0x3;
            let addImm = (next >>> 10) & 0xfff;
            if (shift === 1) addImm <<= 12;
            const addRn = (next >>> 5) & 0x1f;
            const addRd = next & 0x1f;
            if (addRn === adrpRd && addRd === adrpRd) {
              const computed = adrpTarget.add(addImm);
              if (computed.equals(targetAddr)) {
                results.push(p);
              }
            }
          }
        } catch (_e) {
          /* past readable */
        }
      }
      p = p.add(4);
    }
  }
  return results;
}

export function _A_walkToPrologue(addr: NativePointer, maxBack?: number): NativePointer | null {
  const limit = maxBack || 0x2000;
  for (let off = 0; off < limit; off += 4) {
    const p = addr.sub(off);
    let parsed: Instruction | null;
    try {
      parsed = Instruction.parse(p);
    } catch (_e) {
      continue;
    }
    if (!parsed) continue;

    const m = parsed.mnemonic;
    const ops = parsed.opStr || "";
    if (m === "stp" && ops.indexOf("x29") !== -1 && ops.indexOf("x30") !== -1) return p;
    if (m === "sub" && ops.indexOf("sp, sp,") === 0) return p;
    if (m === "paciasp" || m === "pacibsp") return p;
  }
  return null;
}

/**
 * Detect a compiler-factored "get-file-and-line" stub at an ADRP site.
 * Shape: ADRP, ADD, MOV w?, #imm, RET (typically within 4 instructions).
 * Returns true if the ADRP at `addr` appears to be the first insn of such a stub.
 */
export function _A_isStubAtAdrp(addr: NativePointer): boolean {
  for (let i = 0; i < 6; i++) {
    let insn: number;
    try {
      insn = addr.add(i * 4).readU32();
    } catch (_e) {
      return false;
    }
    // RET X30 encoding 0xd65f03c0 (exact) or any RET (mask bits 9-5 = Rn).
    // Use `| 0` on the mask/value pair to normalize JS Int32 signedness.
    if (insn === 0xd65f03c0) return true;
    if ((insn & (0xfffffc1f | 0)) === (0xd65f0000 | 0)) return true;
  }
  return false;
}

/**
 * Score a candidate function as `ssl_crypto_x509_session_verify_cert_chain`:
 * returns a positive integer if the function body contains a store to [x2]
 * (typical `strb w?, [x2]` = `*out_alert = <alert>` near the top of the fn).
 * Higher score if the store value is SSL_AD_INTERNAL_ERROR (0x50).
 */
export function _A_scoreAsVerifyCertChain(addr: NativePointer, size: number): number {
  let score = 0;
  const scanLen = Math.min(size, 0x100);
  let lastMovValue = -1;
  for (let off = 0; off < scanLen; off += 4) {
    let insn: number;
    try {
      insn = addr.add(off).readU32();
    } catch (_e) {
      break;
    }

    // Track most-recent `mov w?, #imm` values — the alert code is usually
    // loaded into a register just before being stored.
    // MOVZ W register: bits 31-23 = 010100101, imm16 at bits 20-5
    if ((insn & 0xff800000) === 0x52800000) {
      const imm16 = (insn >>> 5) & 0xffff;
      lastMovValue = imm16;
    }

    // STRB (immediate, unsigned offset) base=x2, variant 32-bit:
    // 0011 1001 00 imm12 Rn Rt  where Rn = 2 (x2) → mask ffc003e0 value 39000040
    if ((insn & 0xffc003e0) === 0x39000040) {
      score += 10;
      if (lastMovValue === 0x50) score += 20; // SSL_AD_INTERNAL_ERROR = 0x50
    }

    // STRB (register-zero, no offset, post-idx, etc.) — catch-all via STR x?, [x2]
    // STR 32-bit base=x2: mask ffc003e0 value b9000040
    if ((insn & 0xffc003e0) === 0xb9000040) score += 5;
  }
  return score;
}

/**
 * Measure forward from prologue until the first RET at or past `min` bytes in,
 * bounded by `max`. Returns function size, or 0 if out of bounds.
 */
export function _A_functionSize(
  addr: NativePointer,
  opts?: { min?: number; max?: number },
): number {
  const o = opts || {};
  const min = o.min || 0x10;
  const max = o.max || 0x2000;
  for (let off = 0; off < max; off += 4) {
    let parsed: Instruction | null;
    try {
      parsed = Instruction.parse(addr.add(off));
    } catch (_e) {
      return 0;
    }
    if (!parsed) return 0;
    if (parsed.mnemonic === "ret" && off >= min) return off + 4;
  }
  return 0;
}

/**
 * Scan .text for every `bl <targetFn>` instruction. Returns array of
 * NativePointer at each BL instruction.
 */
export function _A_findBlCallers(mod: Module, targetFn: NativePointer): NativePointer[] {
  // Scan EVERY executable subrange — see _A_getAllTextRanges comment for why.
  const ranges = _A_getAllTextRanges(mod);
  const results: NativePointer[] = [];
  const pageMask = ptr("0xfffffffffffff000");

  for (let ri = 0; ri < ranges.length; ri++) {
    const rng = ranges[ri];
    if (rng === undefined) continue;
    let p = rng.base;
    const end = rng.base.add(rng.size);

    while (p.compare(end) < 0) {
      let insn: number;
      // Skip unreadable pages instead of bailing out of the whole scan.
      try {
        insn = p.readU32();
      } catch (_e) {
        p = p.and(pageMask).add(0x1000);
        continue;
      }
      // BL opcode: bits 31-26 = 100101 (mask 0xFC000000, value 0x94000000)
      // See ADRP note above re: `| 0` for signed Int32 comparison.
      if ((insn & 0xfc000000) === (0x94000000 | 0)) {
        let imm26 = insn & 0x03ffffff;
        if (imm26 & 0x02000000) imm26 |= ~0x03ffffff; // sign-extend
        const dest = p.add(imm26 * 4);
        if (dest.equals(targetFn)) results.push(p);
      }
      p = p.add(4);
    }
  }
  return results;
}

/* -----------------------------------------------------------------------------
 * Decoder self-test. Runs once at script start; throws loud if broken.
 * Exercises every bit-math path (ADRP, ADD, BL, RET) against known-good
 * instruction words. This is the first line of defense against Rule A / Rule B
 * regressions and makes the kind of Int32-signedness bug we hit on this repair
 * impossible to ship unnoticed.
 *
 * Body verbatim from flutter-ssl-bypass.js lines 490-530. The exported wrapper
 * takes the clean name `selfTest`; internal variable names preserved as-is.
 * -----------------------------------------------------------------------------
 */
export function selfTest(): void {
  const errors: string[] = [];

  // ADRP mask/value — top bit set, must use `| 0`
  const adrp_word = 0xd0ffd441; // adrp x1, <page> (observed in this sample)
  if ((adrp_word & 0x9f000000) !== (0x90000000 | 0)) {
    errors.push("ADRP opcode mask check failed (Rule A regression?)");
  }
  // ADRP field extraction
  const rd = adrp_word & 0x1f;
  if (rd !== 1) errors.push("ADRP Rd extraction wrong: got " + rd + " expected 1");

  // ADD (imm, 64-bit) — top bit NOT set, simpler check
  const add_word = 0x913e2821; // add x1, x1, #0xf8a
  if ((add_word & 0x7fc00000) !== 0x11000000) {
    errors.push("ADD immediate mask check failed");
  }
  const add_imm = (add_word >>> 10) & 0xfff;
  if (add_imm !== 0xf8a) errors.push("ADD imm12 extraction wrong: got 0x" + add_imm.toString(16));

  // BL mask/value — top bit set, must use `| 0`
  const bl_word = 0x940c31d4; // bl <target>
  if ((bl_word & 0xfc000000) !== (0x94000000 | 0)) {
    errors.push("BL opcode mask check failed (Rule A regression?)");
  }

  // RET — exact word comparison
  const ret_word = 0xd65f03c0;
  if (ret_word !== 0xd65f03c0) errors.push("RET literal comparison broken");
  if ((ret_word & (0xfffffc1f | 0)) !== (0xd65f0000 | 0)) {
    errors.push("RET generic mask check failed (Rule A regression?)");
  }

  if (errors.length > 0) {
    console.error(
      "[self-test] FAILED — decoder bit-math is broken. Aborting to avoid silent wrong answers:",
    );
    for (let i = 0; i < errors.length; i++) console.error("  - " + errors[i]);
    _A_writeAutoDiag("self-test failed: " + errors.join("; "), null);
    throw new Error("decoder self-test failed");
  }
  console.log("[self-test] decoder bit-math OK (ADRP, ADD, BL, RET)");
}

/* -----------------------------------------------------------------------------
 * Ground-truth expectations for the Android anchor resolution. These numbers
 * come from static analysis (r2 axt + Python scan on libflutter-dart-3.10.9.so) of
 * the target this script was built against. They're loose lower bounds — if
 * runtime returns FEWER than expected, something is wrong (broken scan,
 * missing page, masked bug) and we fail loud instead of quietly falling
 * through to a weaker strategy.
 *
 * When porting to a new libflutter.so: re-run static analysis, update these.
 *
 * Verbatim from JS lines 558-562. Type added: `GroundTruthTable` from
 * src/types/anchor.ts.
 * -----------------------------------------------------------------------------
 */
export const GROUND_TRUTH: GroundTruthTable = {
  ssl_x509_cc_string_hits: { min: 1 },
  ssl_x509_cc_xrefs: { min: 1 },
  ssl_x509_cc_stub_callers: { min: 1 },
};

export function _A_assertRange(label: string, actual: number, range: GroundTruthRange): boolean {
  if (actual < range.min) {
    console.warn(
      "[ground-truth] " +
        label +
        " = " +
        actual +
        " (expected >= " +
        range.min +
        "). " +
        "Unusual — likely a decoder regression or a genuine compiler change. " +
        "Continuing; candidate validator will decide if resolution succeeded.",
    );
    return false;
  }
  return true;
}

/**
 * Validate that a candidate function "looks like" verify_cert_chain before
 * hooking it. Requires at least 2 positive signals out of:
 *   (1) strb w?, [x2] signature (writes to out_alert)
 *   (2) function size in the plausible range [0x100, 0x800]
 *   (3) body contains a BL to a neighboring ssl_x509.cc stub
 *   (4) prologue saves at least 2 callee-reg pairs (STP x19..x22)
 * Returns { ok, signals, reasons } so the caller can log WHY rejection happened.
 */
export function _A_validateVerifyCertChainCandidate(
  addr: NativePointer,
  size: number,
  sslX509StubAddr: NativePointer | null,
): { ok: boolean; signals: number; reasons: string[] } {
  let signals = 0;
  const reasons: string[] = [];

  // (1) strb [x2] — cheapest, most discriminating
  const score = _A_scoreAsVerifyCertChain(addr, size);
  if (score > 0) {
    signals++;
    reasons.push("+strb[x2](score=" + score + ")");
  } else {
    reasons.push("-no strb[x2]");
  }

  // (2) size plausibility
  if (size >= 0x100 && size <= 0x800) {
    signals++;
    reasons.push("+size ok (0x" + size.toString(16) + ")");
  } else {
    reasons.push("-size 0x" + size.toString(16) + " out of range");
  }

  // (3) BL to ssl_x509.cc stub inside body
  if (sslX509StubAddr) {
    const scanLen = Math.min(size, 0x600);
    let foundStubCall = false;
    for (let off = 0; off < scanLen; off += 4) {
      let insn: number;
      try {
        insn = addr.add(off).readU32();
      } catch (_e) {
        break;
      }
      if ((insn & 0xfc000000) !== (0x94000000 | 0)) continue;
      let imm26 = insn & 0x03ffffff;
      if (imm26 & 0x02000000) imm26 |= ~0x03ffffff;
      if (
        addr
          .add(off)
          .add(imm26 * 4)
          .equals(sslX509StubAddr)
      ) {
        foundStubCall = true;
        break;
      }
    }
    if (foundStubCall) {
      signals++;
      reasons.push("+bl(ssl_x509.cc_stub)");
    } else {
      reasons.push("-no stub BL");
    }
  }

  // (4) multi-register prologue
  let stpCount = 0;
  for (let po = 0; po < 0x20; po += 4) {
    let pi: number;
    try {
      pi = addr.add(po).readU32();
    } catch (_e) {
      break;
    }
    // STP (signed offset, 64-bit) encoding: 1010100Xsss imm7 Rt2 Rn Rt
    //   top byte pattern for stp [sp, ...]: 0xa9 or 0xa8 (pre-index)
    if (((pi >>> 22) & 0x3ff) === 0x2a4 || ((pi >>> 22) & 0x3ff) === 0x2a6) stpCount++;
  }
  if (stpCount >= 2) {
    signals++;
    reasons.push("+prologue-stp(" + stpCount + ")");
  } else {
    reasons.push("-prologue-stp(" + stpCount + ")");
  }

  return { ok: signals >= 2, signals: signals, reasons: reasons };
}

// Re-export logging helpers to keep import surface compact for downstream
// modules (src/dart-resolver.ts uses `logAnchor` heavily).
export { log, logAnchor, logSelfTest };
