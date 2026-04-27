/*
 * frida-anchors.js — reusable anchor-resolution helpers for stripped arm64 libraries.
 *
 * Designed for libflutter.so but applicable to any stripped arm64 .so loaded into
 * the target process.
 *
 * USAGE (with frida-compile):
 *   const A = require("./frida-anchors.js");
 *   const mod = A.getModule("libflutter.so");
 *   const addr = A.resolveChain("ssl_verify_peer_cert", [
 *     { name: "x509.cc-xref",       fn: () => A.findByStringXref(mod, "x509.cc", { walkToPrologue: true }), validate: A.looksLikeFunctionStart },
 *     { name: "ssl_client.cc-xref", fn: () => A.findByStringXref(mod, "ssl_client.cc", { walkToPrologue: true }), validate: A.looksLikeFunctionStart },
 *   ]);
 *
 * USAGE (single-file): paste this file's contents at the top of your script and
 * replace the `module.exports` assignment with plain top-level function declarations.
 */

"use strict";

// ---------- Module helpers ----------

function getModule(name) {
  return Process.getModuleByName(name);
}

function getTextRange(mod) {
  // The largest r-x range is almost always .text in a stripped arm64 .so.
  const ranges = mod.enumerateRanges("r-x");
  let biggest = null;
  for (let i = 0; i < ranges.length; i++) {
    const r = ranges[i];
    if (!biggest || r.size > biggest.size) biggest = r;
  }
  return biggest;
}

// ---------- String scanning ----------

function _asciiToHexPattern(str) {
  let out = "";
  for (let i = 0; i < str.length; i++) {
    if (i > 0) out += " ";
    out += str.charCodeAt(i).toString(16).padStart(2, "0");
  }
  return out;
}

function findAllStringsInModule(mod, str) {
  const pattern = _asciiToHexPattern(str);
  const results = [];
  const ranges = mod.enumerateRanges("r--");
  for (let i = 0; i < ranges.length; i++) {
    const r = ranges[i];
    let matches;
    try {
      matches = Memory.scanSync(r.base, r.size, pattern);
    } catch (e) {
      continue;
    }
    for (let j = 0; j < matches.length; j++) {
      const addr = matches[j].address;
      try {
        // Require null terminator to avoid substring matches
        if (addr.add(str.length).readU8() === 0) {
          results.push(addr);
        }
      } catch (e) {
        // Past readable range; skip.
      }
    }
  }
  return results;
}

function findStringInModule(mod, str) {
  const all = findAllStringsInModule(mod, str);
  return all.length ? all[0] : null;
}

// ---------- ADRP + ADD xref scanning ----------

/**
 * Find all instructions in the module's .text that compute `targetAddr` via
 * an adjacent ADRP + ADD pair (with register continuity).
 *
 * Returns an array of NativePointer, each pointing at the ADRP instruction.
 */
function findAdrpAddXrefs(mod, targetAddr) {
  const text = getTextRange(mod);
  if (!text) return [];
  const results = [];
  const end = text.base.add(text.size);
  // Iterate 4 bytes at a time; arm64 instructions are fixed-width.
  let p = text.base;
  const pageMask = ptr("0xfffffffffffff000");

  while (p.compare(end) < 0) {
    let insn;
    try {
      insn = p.readU32();
    } catch (e) {
      break;
    }

    // ADRP: bits 31, 28-24 = 1_10000 → mask 0x9F000000, value 0x90000000
    if ((insn & 0x9f000000) === 0x90000000) {
      const adrpRd = insn & 0x1f;
      const immhi = (insn >>> 5) & 0x7ffff;
      const immlo = (insn >>> 29) & 0x3;
      let imm = (immhi << 2) | immlo;
      if (imm & 0x100000) imm |= ~0x1fffff; // sign extend 21-bit
      const pcPage = p.and(pageMask);
      // ADRP computes pcPage + (imm << 12). Using NativePointer arithmetic:
      const adrpTarget = pcPage.add(imm * 0x1000);

      // Check the next instruction for ADD (immediate), same register chain.
      try {
        const next = p.add(4).readU32();
        // ADD (immediate): bits 30-22 = 0_0100010 with shift in 23-22
        // Mask: 0x7FC00000, value: 0x11000000 (sf=0) or 0x91000000 (sf=1)
        if ((next & 0x7fc00000) === 0x11000000) {
          const shift = (next >>> 22) & 0x3;
          let addImm = (next >>> 10) & 0xfff;
          if (shift === 1) addImm <<= 12;
          // Register continuity: ADD's Rn and Rd should match ADRP's Rd
          const addRn = (next >>> 5) & 0x1f;
          const addRd = next & 0x1f;
          if (addRn === adrpRd && addRd === adrpRd) {
            const computed = adrpTarget.add(addImm);
            if (computed.equals(targetAddr)) {
              results.push(p);
            }
          }
        }
      } catch (e) {
        // Past readable; stop
      }
    }

    p = p.add(4);
  }
  return results;
}

// ---------- Walk back to function prologue ----------

function walkToPrologue(addr, maxBack) {
  const limit = maxBack || 0x2000;
  for (let off = 0; off < limit; off += 4) {
    const p = addr.sub(off);
    let parsed;
    try {
      parsed = Instruction.parse(p);
    } catch (e) {
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

// ---------- High-level strategy functions ----------

/**
 * Find a function by: locate string → follow ADRP+ADD xref → walk back to prologue.
 *
 * opts:
 *   walkToPrologue: bool (default true)
 *   stringNth:      which string occurrence if multiple (default 0)
 *   xrefNth:        which xref to follow if multiple (default 0)
 *   maxBack:        prologue walk-back limit (default 0x2000)
 */
function findByStringXref(mod, str, opts) {
  opts = opts || {};
  const strAddrs = findAllStringsInModule(mod, str);
  if (strAddrs.length === 0) return null;

  const stringIdx = opts.stringNth || 0;
  if (stringIdx >= strAddrs.length) return null;
  const chosenStr = strAddrs[stringIdx];

  const xrefs = findAdrpAddXrefs(mod, chosenStr);
  if (xrefs.length === 0) return null;

  const xrefIdx = opts.xrefNth || 0;
  if (xrefIdx >= xrefs.length) return null;
  const chosen = xrefs[xrefIdx];

  const walk = opts.walkToPrologue !== false;
  if (!walk) return chosen;
  return walkToPrologue(chosen, opts.maxBack);
}

/**
 * Find a function by byte pattern. Returns the first hit, or null.
 * Frida pattern syntax: bytes in hex, "??" for byte wildcard.
 */
function findByPattern(mod, pattern) {
  const text = getTextRange(mod);
  if (!text) return null;
  let hits;
  try {
    hits = Memory.scanSync(text.base, text.size, pattern);
  } catch (e) {
    return null;
  }
  return hits.length ? hits[0].address : null;
}

function findAllByPattern(mod, pattern) {
  const text = getTextRange(mod);
  if (!text) return [];
  let hits;
  try {
    hits = Memory.scanSync(text.base, text.size, pattern);
  } catch (e) {
    return [];
  }
  return hits.map(function (h) { return h.address; });
}

// ---------- Validators ----------

function looksLikeFunctionStart(addr) {
  if (!addr) return false;
  let parsed;
  try {
    parsed = Instruction.parse(addr);
  } catch (e) {
    return false;
  }
  if (!parsed) return false;
  const m = parsed.mnemonic;
  const ops = parsed.opStr || "";
  if (m === "stp" && ops.indexOf("x29") !== -1) return true;
  if (m === "sub" && ops.indexOf("sp, sp,") === 0) return true;
  if (m === "paciasp" || m === "pacibsp") return true;
  return false;
}

function functionSizeReasonable(addr, opts) {
  opts = opts || {};
  const min = opts.min || 0x20;
  const max = opts.max || 0x2000;
  for (let off = 0; off < max; off += 4) {
    let parsed;
    try {
      parsed = Instruction.parse(addr.add(off));
    } catch (e) {
      return false;
    }
    if (!parsed) return false;
    if (parsed.mnemonic === "ret") return off >= min;
  }
  return false;
}

// ---------- Resolution chain ----------

/**
 * Try strategies in order. Each strategy: { name, fn, validate? }.
 * Logs each attempt. Returns the first validated address, or throws if all fail.
 */
function resolveChain(name, strategies) {
  for (let i = 0; i < strategies.length; i++) {
    const strat = strategies[i];
    const label = strat.name || ("#" + i);
    let addr = null;
    try {
      addr = strat.fn();
    } catch (e) {
      console.log("[anchor:" + name + "] " + label + ": threw " + e.message);
      continue;
    }
    if (!addr) {
      console.log("[anchor:" + name + "] " + label + ": no match");
      continue;
    }
    if (strat.validate && !strat.validate(addr)) {
      console.log("[anchor:" + name + "] " + label + ": got " + addr + ", FAILED validation");
      continue;
    }
    console.log("[anchor:" + name + "] " + label + ": resolved to " + addr);
    return addr;
  }
  throw new Error("[anchor:" + name + "] all " + strategies.length + " strategies failed");
}

// ---------- Exports ----------

module.exports = {
  getModule: getModule,
  getTextRange: getTextRange,
  findStringInModule: findStringInModule,
  findAllStringsInModule: findAllStringsInModule,
  findAdrpAddXrefs: findAdrpAddXrefs,
  walkToPrologue: walkToPrologue,
  findByStringXref: findByStringXref,
  findByPattern: findByPattern,
  findAllByPattern: findAllByPattern,
  looksLikeFunctionStart: looksLikeFunctionStart,
  functionSizeReasonable: functionSizeReasonable,
  resolveChain: resolveChain,
};
