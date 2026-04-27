/*
 * ============================================================================
 * flutter-ssl-bypass.js — Flutter TLS pinning bypass for modern libflutter.so
 * ============================================================================
 *
 * Targets arm64 Android Flutter builds where the traditional register-specific
 * byte-pattern approach to finding `ssl_crypto_x509_session_verify_cert_chain`
 * has stopped working due to compiler codegen changes.
 *
 * Origin: repaired from hackcatml/frida-flutterproxy
 * (https://github.com/hackcatml/frida-flutterproxy), which used
 * a hardcoded ADRP X9 / ADD X9 byte pattern to locate verify_cert_chain
 * via the "ssl_client" string xref. That pattern broke when the compiler
 * picked a different register and started factoring assertion file/line
 * loads into a shared stub. This rebuild keeps the upstream's ELF parser
 * and Socket_CreateConnect / GetSockAddr trick intact and replaces the
 * pattern with a register-agnostic, structure-validated anchor chain.
 *
 * USAGE
 * -----
 *   Android:
 *     frida -U -f <package> -l flutter-ssl-bypass.js --no-pause
 *   iOS: attach or spawn likewise; the iOS path still uses the original
 *     handshake.cc pattern-scan (untested on new iOS builds — if it breaks,
 *     apply the same stub-caller logic shown below).
 *
 *   Set BURP_PROXY_IP / BURP_PROXY_PORT in main() before running.
 *
 * WHAT THE SCRIPT DOES
 * --------------------
 *   1. Waits for libflutter.so to load.
 *   2. Parses the ELF (Android) or Mach-O (iOS) in-memory to locate .rodata
 *      and PT_GNU_RELRO (resp. __DATA __const).
 *   3. Resolves `ssl_crypto_x509_session_verify_cert_chain` via a multi-stage
 *      anchor chain (see below) and hooks it with retval 0 -> 1.
 *   4. Resolves Dart's `dart::bin::Socket::CreateConnect` through the
 *      "Socket_CreateConnect" string -> RELRO pointer trick, then follows the
 *      2nd BL inside it to reach `dart::bin::SocketAddress::GetSockAddr`.
 *   5. Hooks GetSockAddr to capture the outbound sockaddr, then hooks libc
 *      `socket()` to rewrite IP/port to the Burp proxy. This yields MITM even
 *      when the app bypasses system DNS / proxy settings.
 *
 * ============================================================================
 * KEY INSIGHTS DISCOVERED DURING REPAIR (READ THIS IF YOU'RE PICKING IT UP)
 * ============================================================================
 *
 * 1. The `"ssl_client"` / `"ssl_server"` ADRP+ADD CSEL pattern inside
 *    verify_cert_chain is NOT an error-reporting construct — it feeds
 *    `X509_STORE_CTX_set_default(ctx, purpose)`. Details confirmed against
 *    BoringSSL source (ssl/ssl_x509.cc:234 as of 2026). The strings are
 *    X.509 verify-purpose identifiers, picked based on `ssl->server`.
 *
 * 2. In the newer build the compiler consolidated those two string loads.
 *    On this sample only ONE ADRP+ADD to `"ssl_client"` survives, inside a
 *    144-byte string DISPATCHER function (sequential strcmp vs "ssl_client",
 *    "ssl_server", "pkcs7", ... — looks like an OBJ/name lookup, NOT the
 *    cert-verify function). The old anchor approach walks back from that
 *    xref and hooks the dispatcher -> no bypass.
 *
 * 3. Newer BoringSSL/Flutter builds FACTOR the per-assertion
 *    `(__FILE__, __LINE__)` load into a 16-byte shared stub:
 *      ADRP xN, <page>        ; load page of ssl_x509.cc path
 *      ADD  xN, xN, #<off>    ; fully-formed path pointer
 *      MOV  w0, #0x10         ; line number (constant)
 *      RET
 *    Every ssl_x509.cc function that wants to report "I errored out here"
 *    does BL to this stub. Static tools (r2's `axt` on the string) find the
 *    xref inside the STUB, not inside the real caller function. Walking back
 *    from the xref falls into WHATEVER function happens to be placed before
 *    the stub in memory — garbage.
 *
 * 4. The fix is stub-caller enumeration: detect the stub shape at the xref,
 *    scan .text for BL instructions targeting the stub's entry, then walk
 *    each BL site back to its enclosing function. Those are the candidates.
 *
 * 5. Among multiple stub callers in ssl_x509.cc (typically 3-4), the one
 *    that is actually `ssl_crypto_x509_session_verify_cert_chain` can be
 *    picked by function signature: it's the only one with
 *        strb w?, [x2]   ; *out_alert = <SSL_AD_*>
 *    near the top, because its C signature is
 *        bool verify_cert_chain(SSL_SESSION*, SSL_HANDSHAKE*, uint8_t* out_alert)
 *    and its error paths set out_alert = SSL_AD_INTERNAL_ERROR (0x50).
 *    Other siblings (cache_objects, flush_cached_ca_names, etc.) take 1-2
 *    args and never touch x2. `_A_scoreAsVerifyCertChain()` uses this.
 *
 * 6. JAVASCRIPT GOTCHA (!!). JS bitwise ops return signed Int32. A literal
 *    like `0x90000000` in source is a POSITIVE Number (2,415,919,104), but
 *    `(insn & 0x9f000000)` returns -1,879,048,192 when the top bit is set.
 *    Strict equality `=== 0x90000000` FAILS silently — my first cut of the
 *    ADRP/BL decoders found zero matches because of this. Fix:
 *        if ((insn & MASK) === (VALUE | 0))   // force both sides to Int32
 *    Any opcode comparison with bit 31 set needs this dance.
 *
 * 7. FRIDA GOTCHA. `mod.enumerateRanges(filter)` returns an empty array on
 *    some Android + Frida combinations (confirmed on this target — A142
 *    device, frida-server 17.x). `Process.enumerateRanges(filter)` works and
 *    can be intersected with the module window to achieve the same result.
 *    This file uses that fallback throughout (`_A_getModuleSubranges`).
 *
 * ============================================================================
 * ANCHOR CHAIN (Android path)
 * ============================================================================
 *
 * Strategies are tried in order; first success wins.
 *
 *   1. ssl_x509.cc stub-caller (PRIMARY, used on current target)
 *        Find: `"../../../flutter/third_party/boringssl/src/ssl/ssl_x509.cc"`
 *        For each ADRP+ADD xref:
 *          - If the xref is a stub (ADRP,ADD,MOV,RET within 6 insns):
 *              enumerate BL callers of the stub, walk each back to prologue
 *          - Else (direct xref): walk back to prologue, accept if size >=0x100
 *        Score each candidate via `strb w?, [x2]` signature (see insight #5).
 *        Highest score wins; ties broken by size.
 *
 *   2. ssl_client register-agnostic xref (FALLBACK)
 *        For builds where the old X9 pattern happens to still be present.
 *        Scans for ANY ADRP+ADD resolving to "ssl_client", walks back, keeps
 *        the first candidate with size >= 0x100 (rejects the dispatcher).
 *
 *   3. handshake.cc -> ssl_verify_peer_cert (LAST-RESORT)
 *        Different function, different semantics. Uses `Interceptor.replace`
 *        and returns 0 (ssl_verify_ok). Only fires if the cert-chain target
 *        couldn't be resolved. Same stub-caller logic as strategy 1.
 *
 * ============================================================================
 * DEBUGGING / EXTENDING
 * ============================================================================
 *
 *   - The hook logs `[trace] verify_cert_chain ENTER/LEAVE` on every call
 *     and `[*] verify cert bypass (return 0 -> 1)` when it flips a failure.
 *     If ENTER never fires during the handshake, the wrong function was
 *     picked — re-check the `[anchor] ssl_x509.cc candidates:` dump and
 *     adjust the scorer or add another signature.
 *
 *   - If the bypass fires but Burp still sees a handshake termination, the
 *     app likely uses Dart-side pinning (SecurityContext.badCertificateCallback
 *     or similar). Hook at Dart-FFI level instead of BoringSSL.
 *
 *   - Future compiler bumps: if the 4-instruction stub shape changes, update
 *     `_A_isStubAtAdrp`. If the scoring misidentifies (e.g. verify_cert_chain
 *     gets inlined and loses the strb-[x2] signature), add a second
 *     fingerprint in `_A_scoreAsVerifyCertChain` — calling X509_verify_cert
 *     is another stable tell.
 *
 *   - For a fresh repair against a new libflutter.so, run the companion
 *     `diag.js` to dump the exact runtime string hits, range map, and ADRP+ADD
 *     xref list before editing the main script.
 *
 * ============================================================================
 * RELATED COMMUNITY WORK / SOURCES
 * ============================================================================
 *
 *   - DIRECT UPSTREAM: hackcatml/frida-flutterproxy
 *     (https://github.com/hackcatml/frida-flutterproxy)
 *     This script is a repair of that one against a newer libflutter
 *     build. The ELF/Mach-O in-memory parser and the
 *     Socket_CreateConnect / GetSockAddr / libc-socket redirect trick
 *     are essentially unchanged from there. All credit for that
 *     foundation goes to the original author. The anchor-resolution
 *     layer (the _A_* helpers, multi-signal validator, stub-caller
 *     chain, auto-diag) is new in this fork.
 *   - NVISOsecurity/disable-flutter-tls-verification (issue #51, Jan 2026)
 *     documents exactly this "ssl_verify_peer_cert unlocatable -> pivot to
 *     ssl_crypto_x509_session_verify_cert_chain with retval.replace(0x1)"
 *     situation on recent builds.
 *   - BoringSSL source (main branch): ssl/ssl_x509.cc, ssl/handshake.cc
 *     (ssl_verify_peer_cert at line 268; session_verify_cert_chain at 201).
 *
 * ============================================================================
 */

/* ===================================================================
 * Anchor resolution helpers (inlined from frida-anchors.js).
 * =================================================================== */

/* -----------------------------------------------------------------------------
 * GENERIC RULES (violating any of these produces silent wrong answers):
 *
 *   RULE A.  Opcode comparisons with a 32-bit value whose bit 31 is set MUST
 *            normalize to Int32 on both sides, e.g.
 *              if ((insn & 0x9f000000) === (0x90000000 | 0))
 *            Without `| 0`, JS treats the literal as a positive Number and
 *            the AND result as signed Int32 — `===` is always false.
 *
 *   RULE B.  Every `readU32()` (or similar) inside a scan loop MUST skip the
 *            next page on exception, NEVER `break`. A single bad page silently
 *            truncates the whole scan — observed masking a stub xref on this
 *            target until we fixed it.
 *
 *   RULE C.  Every `Module.enumerateRanges(filter)` goes through a helper that
 *            falls back to `Process.enumerateRanges(filter)` intersected with
 *            the module window. Some Android+Frida combos return empty from
 *            the former.
 *
 * Self-test at the bottom of this block asserts A + B + C work before any
 * real resolution runs.
 * -----------------------------------------------------------------------------
 */

// NOTE: mod.enumerateRanges(filter) returns an empty array on some Android/Frida
// combos (observed on this target). Use Process.enumerateRanges(filter) and
// intersect with the module window instead.
function _A_getModuleSubranges(mod, filter) {
    var modStart = mod.base;
    var modEnd = mod.base.add(mod.size);
    var out = [];
    var rs;
    try { rs = Process.enumerateRanges(filter); } catch (e) { rs = []; }
    for (var i = 0; i < rs.length; i++) {
        var r = rs[i];
        if (r.base.add(r.size).compare(modStart) <= 0) continue;
        if (r.base.compare(modEnd) >= 0) continue;
        out.push(r);
    }
    return out;
}

function _A_getTextRange(mod) {
    // Prefer the largest executable-containing range inside the module window.
    var candidates = _A_getModuleSubranges(mod, "r-x");
    if (candidates.length === 0) candidates = _A_getModuleSubranges(mod, "--x");
    var biggest = null;
    for (var i = 0; i < candidates.length; i++) {
        var r = candidates[i];
        if (!biggest || r.size > biggest.size) biggest = r;
    }
    // Fallback: the whole module window.
    if (!biggest) biggest = { base: mod.base, size: mod.size };
    return biggest;
}

// Return ALL executable subranges inside the module window. Some libflutter
// builds split BoringSSL/icu/libcxx/etc into multiple r-x sections separated
// by tiny rwx pages (observed: 7-8 distinct r-x ranges on the target
// build). The largest range is typically only the Flutter engine .text;
// BoringSSL functions can live in the secondary 3 MB r-x or 148 KB r-x
// sections. Scanning only the biggest range silently MISSES xrefs and BL
// callers in those secondary sections — exactly how the stub-caller chain
// was failing on this target.
function _A_getAllTextRanges(mod) {
    var ranges = _A_getModuleSubranges(mod, "r-x");
    if (ranges.length === 0) ranges = _A_getModuleSubranges(mod, "--x");
    if (ranges.length === 0) ranges = [{ base: mod.base, size: mod.size }];
    return ranges;
}

function _A_asciiToHexPattern(str) {
    var out = "";
    for (var i = 0; i < str.length; i++) {
        if (i > 0) out += " ";
        out += str.charCodeAt(i).toString(16).padStart(2, "0");
    }
    return out;
}

function _A_findAllStringsInModule(mod, str) {
    var pattern = _A_asciiToHexPattern(str);
    var results = [];
    var seen = {};

    // Scan the whole module window first — works regardless of section split.
    try {
        var matches = Memory.scanSync(mod.base, mod.size, pattern);
        for (var j = 0; j < matches.length; j++) {
            var addr = matches[j].address;
            try {
                if (addr.add(str.length).readU8() === 0) {
                    var key = addr.toString();
                    if (!seen[key]) { seen[key] = true; results.push(addr); }
                }
            } catch (e) {}
        }
    } catch (e) { /* fall through to sub-range scanning */ }

    // Also scan individual mapped sub-ranges (r--, r-x) as a belt-and-braces pass.
    var subs = _A_getModuleSubranges(mod, "r--").concat(_A_getModuleSubranges(mod, "r-x"));
    for (var s = 0; s < subs.length; s++) {
        try {
            var m2 = Memory.scanSync(subs[s].base, subs[s].size, pattern);
            for (var k = 0; k < m2.length; k++) {
                var a = m2[k].address;
                try {
                    if (a.add(str.length).readU8() === 0) {
                        var kk = a.toString();
                        if (!seen[kk]) { seen[kk] = true; results.push(a); }
                    }
                } catch (e) {}
            }
        } catch (e) {}
    }

    return results;
}

/**
 * Scan .text for every ADRP+ADD pair (any register, with register continuity)
 * that computes `targetAddr`. Returns array of NativePointer at each ADRP.
 */
function _A_findAdrpAddXrefs(mod, targetAddr) {
    // Scan EVERY executable subrange — see _A_getAllTextRanges comment for why.
    var ranges = _A_getAllTextRanges(mod);
    var results = [];
    var pageMask = ptr("0xfffffffffffff000");

    for (var ri = 0; ri < ranges.length; ri++) {
        var rng = ranges[ri];
        var p = rng.base;
        var end = rng.base.add(rng.size);

        while (p.compare(end) < 0) {
            var insn;
            // On unreadable page, skip to next page boundary and KEEP SCANNING.
            // A `break` here would silently truncate scans of large .text regions
            // if any single page fails — observed on this target.
            try { insn = p.readU32(); } catch (e) {
                var aligned = p.and(pageMask).add(0x1000);
                p = aligned;
                continue;
            }

            // ADRP: bits 31=1, 28-24=10000 (mask 0x9F000000, value 0x90000000)
            // Note: `0x90000000 | 0` forces signed-Int32 comparison since JS bitwise ops
            // return signed Int32 and the high bit of the mask produces a negative result.
            if ((insn & 0x9f000000) === (0x90000000 | 0)) {
                var adrpRd = insn & 0x1f;
                var immhi = (insn >>> 5) & 0x7ffff;
                var immlo = (insn >>> 29) & 0x3;
                var imm = (immhi << 2) | immlo;
                if (imm & 0x100000) imm |= ~0x1fffff; // sign-extend 21-bit
                var pcPage = p.and(pageMask);
                var adrpTarget = pcPage.add(imm * 0x1000);

                try {
                    var next = p.add(4).readU32();
                    // ADD (immediate) 64-bit: top 9 bits = 100100010 (0x91 with sh=0 at pos 22)
                    if ((next & 0x7fc00000) === 0x11000000) {
                        var shift = (next >>> 22) & 0x3;
                        var addImm = (next >>> 10) & 0xfff;
                        if (shift === 1) addImm <<= 12;
                        var addRn = (next >>> 5) & 0x1f;
                        var addRd = next & 0x1f;
                        if (addRn === adrpRd && addRd === adrpRd) {
                            var computed = adrpTarget.add(addImm);
                            if (computed.equals(targetAddr)) {
                                results.push(p);
                            }
                        }
                    }
                } catch (e) { /* past readable */ }
            }
            p = p.add(4);
        }
    }
    return results;
}

function _A_walkToPrologue(addr, maxBack) {
    var limit = maxBack || 0x2000;
    for (var off = 0; off < limit; off += 4) {
        var p = addr.sub(off);
        var parsed;
        try { parsed = Instruction.parse(p); } catch (e) { continue; }
        if (!parsed) continue;

        var m = parsed.mnemonic;
        var ops = parsed.opStr || "";
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
function _A_isStubAtAdrp(addr) {
    for (var i = 0; i < 6; i++) {
        var insn;
        try { insn = addr.add(i * 4).readU32(); } catch (e) { return false; }
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
function _A_scoreAsVerifyCertChain(addr, size) {
    var score = 0;
    var scanLen = Math.min(size, 0x100);
    var lastMovValue = -1;
    for (var off = 0; off < scanLen; off += 4) {
        var insn;
        try { insn = addr.add(off).readU32(); } catch (e) { break; }

        // Track most-recent `mov w?, #imm` values — the alert code is usually
        // loaded into a register just before being stored.
        // MOVZ W register: bits 31-23 = 010100101, imm16 at bits 20-5
        if ((insn & 0xff800000) === 0x52800000) {
            var imm16 = (insn >>> 5) & 0xffff;
            lastMovValue = imm16;
        }

        // STRB (immediate, unsigned offset) base=x2, variant 32-bit:
        // 0011 1001 00 imm12 Rn Rt  where Rn = 2 (x2) → mask ffc003e0 value 39000040
        // STRB base=x2: bits 9-5 (Rn) = 00010, so low 10 bits of word = ...0001_0xxxxx
        // Simpler: check (insn & 0xffc003e0) === 0x39000040
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
function _A_functionSize(addr, opts) {
    opts = opts || {};
    var min = opts.min || 0x10;
    var max = opts.max || 0x2000;
    for (var off = 0; off < max; off += 4) {
        var parsed;
        try { parsed = Instruction.parse(addr.add(off)); } catch (e) { return 0; }
        if (!parsed) return 0;
        if (parsed.mnemonic === "ret" && off >= min) return off + 4;
    }
    return 0;
}

/**
 * Scan .text for every `bl <targetFn>` instruction. Returns array of NativePointer
 * at each BL instruction.
 */
function _A_findBlCallers(mod, targetFn) {
    // Scan EVERY executable subrange — see _A_getAllTextRanges comment for why.
    var ranges = _A_getAllTextRanges(mod);
    var results = [];
    var pageMask = ptr("0xfffffffffffff000");

    for (var ri = 0; ri < ranges.length; ri++) {
        var rng = ranges[ri];
        var p = rng.base;
        var end = rng.base.add(rng.size);

        while (p.compare(end) < 0) {
            var insn;
            // Skip unreadable pages instead of bailing out of the whole scan.
            try { insn = p.readU32(); } catch (e) {
                p = p.and(pageMask).add(0x1000);
                continue;
            }
            // BL opcode: bits 31-26 = 100101 (mask 0xFC000000, value 0x94000000)
            // See ADRP note above re: `| 0` for signed Int32 comparison.
            if ((insn & 0xfc000000) === (0x94000000 | 0)) {
                var imm26 = insn & 0x03ffffff;
                if (imm26 & 0x02000000) imm26 |= ~0x03ffffff; // sign-extend
                var dest = p.add(imm26 * 4);
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
 * -----------------------------------------------------------------------------
 */
function _A_selfTest() {
    var errors = [];

    // ADRP mask/value — top bit set, must use `| 0`
    var adrp_word = 0xd0ffd441; // adrp x1, <page> (observed in this sample)
    if ((adrp_word & 0x9f000000) !== (0x90000000 | 0)) {
        errors.push("ADRP opcode mask check failed (Rule A regression?)");
    }
    // ADRP field extraction
    var rd = adrp_word & 0x1f;
    if (rd !== 1) errors.push("ADRP Rd extraction wrong: got " + rd + " expected 1");

    // ADD (imm, 64-bit) — top bit NOT set, simpler check
    var add_word = 0x913e2821; // add x1, x1, #0xf8a
    if ((add_word & 0x7fc00000) !== 0x11000000) {
        errors.push("ADD immediate mask check failed");
    }
    var add_imm = (add_word >>> 10) & 0xfff;
    if (add_imm !== 0xf8a) errors.push("ADD imm12 extraction wrong: got 0x" + add_imm.toString(16));

    // BL mask/value — top bit set, must use `| 0`
    var bl_word = 0x940c31d4; // bl <target>
    if ((bl_word & 0xfc000000) !== (0x94000000 | 0)) {
        errors.push("BL opcode mask check failed (Rule A regression?)");
    }

    // RET — exact word comparison
    var ret_word = 0xd65f03c0;
    if (ret_word !== 0xd65f03c0) errors.push("RET literal comparison broken");
    if ((ret_word & (0xfffffc1f | 0)) !== (0xd65f0000 | 0)) {
        errors.push("RET generic mask check failed (Rule A regression?)");
    }

    if (errors.length > 0) {
        console.error("[self-test] FAILED — decoder bit-math is broken. Aborting to avoid silent wrong answers:");
        for (var i = 0; i < errors.length; i++) console.error("  - " + errors[i]);
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
 * -----------------------------------------------------------------------------
 */
/*
 * These are DIAGNOSTIC thresholds — intentionally loose. The real gate for
 * "did we find the right function" is `_A_validateVerifyCertChainCandidate`,
 * which uses structural signals (strb [x2], stub BL, prologue shape) that
 * survive compiler codegen changes.
 *
 * `min` is the lower bound below which something is almost certainly broken
 * at the DECODER layer (e.g. the Int32 bug silently returned 0 matches). A
 * legitimate Flutter/BoringSSL build should always meet these. If a future
 * build legitimately drops a count below the minimum (e.g. LTO fully inlines
 * the stub so no BL callers exist), you'll see a warning but the script
 * continues — the candidate validator decides whether resolution succeeded.
 *
 * No `max` — upper counts aren't a correctness signal, just noise.
 */
var GROUND_TRUTH = {
    ssl_x509_cc_string_hits:  { min: 1 },   // __FILE__ literal must exist in .rodata
    ssl_x509_cc_xrefs:        { min: 1 },   // at least one ADRP+ADD reference
    ssl_x509_cc_stub_callers: { min: 1 },   // if a stub exists, someone must call it
};

function _A_assertRange(label, actual, range) {
    if (actual < range.min) {
        console.warn("[ground-truth] " + label + " = " + actual +
            " (expected >= " + range.min + "). " +
            "Unusual — likely a decoder regression or a genuine compiler change. " +
            "Continuing; candidate validator will decide if resolution succeeded.");
        return false;
    }
    return true;
}

/* -----------------------------------------------------------------------------
 * Auto-diagnostic. Dumps runtime state to a timestamped file on the device
 * whenever something unexpected happens (self-test fails, no candidate
 * qualifies, hook never fires during TLS activity, retval always 1, etc.).
 * Means the next debug trip has concrete data instead of "rerun diag.js".
 *
 * Paths tried in order: /data/local/tmp, /sdcard, the app's files dir.
 * Pull with: adb pull /data/local/tmp/flutter-bypass-diag-<ts>.txt
 * -----------------------------------------------------------------------------
 */
var _A_diagState = {
    written: false,                   // only dump once per session
    hookEnterCount: 0,                // how many times verify_cert_chain fired
    hookRetvalZeroCount: 0,           // retval=0 observations (bypass fired)
    hookRetvalOneCount: 0,            // retval=1 (already-passing)
    socketOverwriteCount: 0,          // Burp redirect fires — TLS is happening
    resolvedVccAddr: null,
    resolvedVccVia: null,
    candidatesDump: "",
};

function _A_writeAutoDiag(reason, modOrNull) {
    if (_A_diagState.written) return;   // dump once
    _A_diagState.written = true;

    var lines = [];
    var push = function (s) { lines.push(s); };

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

    var mod = modOrNull;
    if (!mod) { try { mod = Process.findModuleByName("libflutter.so"); } catch (e) {} }

    if (mod) {
        push("--- Module ---");
        push("name: " + mod.name);
        push("path: " + mod.path);
        push("base: " + mod.base);
        push("size: 0x" + mod.size.toString(16));
        push("");

        push("--- Process.enumerateRanges (intersected with module window) ---");
        ["r--", "r-x", "rw-", "--x"].forEach(function (filter) {
            var rs;
            try { rs = _A_getModuleSubranges(mod, filter); } catch (e) { rs = []; }
            push("  '" + filter + "' : " + rs.length);
            for (var i = 0; i < rs.length; i++) {
                push("    " + rs[i].base + "  size=0x" + rs[i].size.toString(16) + "  prot=" + rs[i].protection);
            }
        });
        push("");

        // Fresh string + xref scans
        ["../../../flutter/third_party/boringssl/src/ssl/ssl_x509.cc",
         "../../../flutter/third_party/boringssl/src/ssl/handshake.cc",
         "ssl_client",
         "ssl_server"].forEach(function (s) {
            push("--- String scan: " + s + " ---");
            var hits;
            try { hits = _A_findAllStringsInModule(mod, s); } catch (e) { hits = []; }
            push("  hits: " + hits.length);
            for (var h = 0; h < hits.length && h < 10; h++) {
                var hit = hits[h];
                push("    " + hit);
                try {
                    var xrefs = _A_findAdrpAddXrefs(mod, hit);
                    push("      adrp+add xrefs: " + xrefs.length);
                    for (var x = 0; x < xrefs.length && x < 8; x++) {
                        var ax = xrefs[x];
                        var isStub = _A_isStubAtAdrp(ax);
                        var line = "        " + ax + "  isStub=" + isStub;
                        try {
                            var mnemo = Instruction.parse(ax).mnemonic + " " + (Instruction.parse(ax).opStr || "");
                            line += "  (" + mnemo + ")";
                        } catch (e) {}
                        push(line);
                    }
                } catch (e) { push("      (xref scan threw: " + e.message + ")"); }
            }
            push("");
        });
    }

    push("=== end diag ===");

    var body = lines.join("\n");
    var ts = Date.now();
    var pkg = "unknown";
    try {
        pkg = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext().getPackageName().toString();
    } catch (e) {}

    var paths = [
        "/data/local/tmp/flutter-bypass-diag-" + ts + ".txt",
        "/sdcard/flutter-bypass-diag-" + ts + ".txt",
        "/data/data/" + pkg + "/files/flutter-bypass-diag-" + ts + ".txt",
    ];
    var written = null;
    for (var pi = 0; pi < paths.length; pi++) {
        try {
            var f = new File(paths[pi], "w");
            f.write(body);
            f.flush();
            f.close();
            written = paths[pi];
            break;
        } catch (e) {}
    }

    if (written) {
        console.error("[auto-diag] " + reason + " — wrote " + body.length + " bytes to " + written);
        console.error("[auto-diag] pull with: adb pull " + written);
    } else {
        console.error("[auto-diag] " + reason + " — failed to write file, dumping inline:");
        console.error(body);
    }
}

/* -----------------------------------------------------------------------------
 * Validate that a candidate function "looks like" verify_cert_chain before
 * hooking it. Requires at least 2 positive signals out of:
 *   (1) strb w?, [x2] signature (writes to out_alert)
 *   (2) function size in the plausible range [0x100, 0x800]
 *   (3) body contains a BL to a neighboring ssl_x509.cc stub
 *   (4) prologue saves at least 2 callee-reg pairs (STP x19..x22)
 * Returns { ok, signals, reasons } so the caller can log WHY rejection happened.
 * -----------------------------------------------------------------------------
 */
function _A_validateVerifyCertChainCandidate(addr, size, sslX509StubAddr) {
    var signals = 0;
    var reasons = [];

    // (1) strb [x2] — cheapest, most discriminating
    var score = _A_scoreAsVerifyCertChain(addr, size);
    if (score > 0) { signals++; reasons.push("+strb[x2](score=" + score + ")"); }
    else           { reasons.push("-no strb[x2]"); }

    // (2) size plausibility
    if (size >= 0x100 && size <= 0x800) { signals++; reasons.push("+size ok (0x" + size.toString(16) + ")"); }
    else                                { reasons.push("-size 0x" + size.toString(16) + " out of range"); }

    // (3) BL to ssl_x509.cc stub inside body
    if (sslX509StubAddr) {
        var scanLen = Math.min(size, 0x600);
        var foundStubCall = false;
        for (var off = 0; off < scanLen; off += 4) {
            var insn;
            try { insn = addr.add(off).readU32(); } catch (e) { break; }
            if ((insn & 0xfc000000) !== (0x94000000 | 0)) continue;
            var imm26 = insn & 0x03ffffff;
            if (imm26 & 0x02000000) imm26 |= ~0x03ffffff;
            if (addr.add(off).add(imm26 * 4).equals(sslX509StubAddr)) { foundStubCall = true; break; }
        }
        if (foundStubCall) { signals++; reasons.push("+bl(ssl_x509.cc_stub)"); }
        else               { reasons.push("-no stub BL"); }
    }

    // (4) multi-register prologue
    var stpCount = 0;
    for (var po = 0; po < 0x20; po += 4) {
        var pi;
        try { pi = addr.add(po).readU32(); } catch (e) { break; }
        // STP (signed offset, 64-bit) encoding: 1010100Xsss imm7 Rt2 Rn Rt
        //   top byte pattern for stp [sp, ...]: 0xa9 or 0xa8 (pre-index)
        if (((pi >>> 22) & 0x3ff) === 0x2a4 || ((pi >>> 22) & 0x3ff) === 0x2a6) stpCount++;
    }
    if (stpCount >= 2) { signals++; reasons.push("+prologue-stp(" + stpCount + ")"); }
    else               { reasons.push("-prologue-stp(" + stpCount + ")"); }

    return { ok: signals >= 2, signals: signals, reasons: reasons };
}

/* ===================================================================
 * Global variables
 * =================================================================== */

var appId = null;
var appId_iOS = null;

var BURP_PROXY_IP = null;
var BURP_PROXY_PORT = null;

var flutter_base = null;
var flutter_module = null;

var PT_LOAD_rodata_p_memsz = null;
var PT_LOAD_text_p_vaddr = null;
var PT_LOAD_text_p_memsz = null;
var PT_GNU_RELRO_p_vaddr = null;
var PT_GNU_RELRO_p_memsz = null;

var TEXT_segment_text_section_offset = null;
var TEXT_segment_text_section_size = null;
var TEXT_segment_cstring_section_offset = null;
var TEXT_segment_cstring_section_size = null;
var DATA_segment_const_section_offset = null;
var DATA_segment_const_section_size = null;

var verify_cert_chain_func_addr = null;
var verify_peer_cert_func_addr = null;
var verify_cert_chain_strategy = null; // "attach-replace-1" or "replace-return-0"

var Socket_CreateConnect_string_pattern_found_addr = null;
var Socket_CreateConnect_func_addr = null;

var GetSockAddr_func_addr = null;
var sockaddr = null;

/* ===================================================================
 * Util functions
 * =================================================================== */

function findAppId() {
    if (Process.platform === "linux") {
        var pm = Java.use('android.app.ActivityThread').currentApplication();
        return pm.getApplicationContext().getPackageName();
    } else {
        return ObjC.classes.NSBundle.mainBundle().bundleIdentifier().toString();
    }
}

function convertHexToByteString(hexString) {
    var cleanHexString = hexString.startsWith('0x') ? hexString.slice(2) : hexString;
    if (cleanHexString.length % 2 !== 0) cleanHexString = '0' + cleanHexString;
    var byteArray = cleanHexString.match(/.{1,2}/g);
    byteArray.reverse();
    return byteArray.join(' ');
}

function convertIpToByteArray(ipString) {
    return ipString.split('.').map(function (o) { return parseInt(o, 10); });
}

function byteFlip(number) {
    var highByte = (number >> 8) & 0xFF;
    var lowByte = number & 0xFF;
    return (lowByte << 8) | highByte;
}

/* ===================================================================
 * Android-specific: resolve verify_cert_chain via ssl_x509.cc anchor chain
 * =================================================================== */

/**
 * Try to find ssl_crypto_x509_session_verify_cert_chain in libflutter.so.
 *
 * Strategy 1 (stub-caller): find the ssl_x509.cc __FILE__ string, find its
 *   ADRP+ADD xrefs. For each xref, walk back to the enclosing function. If
 *   the enclosing function is a tiny stub (<= 0x20 bytes), enumerate the
 *   BL callers of the stub and pick the largest one.
 *
 * Strategy 2 (direct ssl_client): register-agnostic ADRP+ADD scan for the
 *   ssl_client string, walk back to prologue, accept only if function size
 *   is > 0x100 bytes (skips the new-build string dispatcher).
 *
 * Returns {addr, via, size} or null.
 */
function resolveVerifyCertChain(mod) {
    // --- Strategy 1: ssl_x509.cc path → stub → biggest caller ---
    var ssl_x509_paths = _A_findAllStringsInModule(mod, "../../../flutter/third_party/boringssl/src/ssl/ssl_x509.cc");
    console.log("[anchor] ssl_x509.cc string hits: " + ssl_x509_paths.length);
    _A_assertRange("ssl_x509.cc_string_hits", ssl_x509_paths.length, GROUND_TRUTH.ssl_x509_cc_string_hits);

    var candidates = [];
    var sslX509StubAddr = null;  // remember for later candidate validation
    var totalXrefs = 0;
    var totalStubCallers = 0;

    for (var i = 0; i < ssl_x509_paths.length; i++) {
        var strAddr = ssl_x509_paths[i];
        var xrefs = _A_findAdrpAddXrefs(mod, strAddr);
        totalXrefs += xrefs.length;
        console.log("[anchor]   " + strAddr + " -> " + xrefs.length + " ADRP+ADD xref(s)");
        for (var j = 0; j < xrefs.length; j++) {
            var xref = xrefs[j];
            var isStubHere = _A_isStubAtAdrp(xref);
            console.log("[anchor]     xref @ " + xref + "  isStub=" + isStubHere);

            // Stub: the xref IS the stub entry (ADRP+ADD+MOV+RET within ~6 insns).
            // Don't try to walk back to a prologue — stubs are often placed at the
            // start of a code page with no preceding function for walkback to anchor
            // on (observed: "no prologue within 0x2000" on the target target,
            // which previously caused the script to skip BL-caller enumeration
            // entirely and fall through to weaker strategies).
            if (isStubHere) {
                if (!sslX509StubAddr) sslX509StubAddr = xref;
                var blSites = _A_findBlCallers(mod, xref);
                totalStubCallers += blSites.length;
                console.log("[anchor]       stub -> " + blSites.length + " BL caller(s)");
                for (var k = 0; k < blSites.length; k++) {
                    var callerPrologue = _A_walkToPrologue(blSites[k]);
                    if (!callerPrologue) continue;
                    var callerSize = _A_functionSize(callerPrologue);
                    if (callerSize >= 0x80) {
                        candidates.push({ addr: callerPrologue, size: callerSize, via: "ssl_x509.cc-stub" });
                    }
                }
                continue;
            }

            // Non-stub xref: walk back to the enclosing function's prologue.
            var prologue = _A_walkToPrologue(xref);
            if (!prologue) { console.log("[anchor]       (no prologue within 0x2000)"); continue; }
            var size = _A_functionSize(prologue);
            if (size >= 0x100) {
                candidates.push({ addr: prologue, size: size, via: "ssl_x509.cc-direct" });
            }
        }
    }

    // Ground-truth assertions: fail loud if runtime scan came up short.
    _A_assertRange("ssl_x509.cc_xrefs", totalXrefs, GROUND_TRUTH.ssl_x509_cc_xrefs);
    if (sslX509StubAddr) {
        _A_assertRange("ssl_x509.cc_stub_callers", totalStubCallers, GROUND_TRUTH.ssl_x509_cc_stub_callers);
    }

    // Dedupe by address
    var seen = {};
    var unique = [];
    for (var m = 0; m < candidates.length; m++) {
        var key = candidates[m].addr.toString();
        if (!seen[key]) { seen[key] = true; unique.push(candidates[m]); }
    }

    // Validate each candidate with multi-signal check (strb [x2], size, stub BL,
    // multi-STP prologue). Requires >= 2 signals to qualify. Rejecting weak
    // candidates up front turns "hooked the wrong sibling, no bypass" silent
    // failures into loud "no candidate passed validation" errors.
    for (var u = 0; u < unique.length; u++) {
        var c = unique[u];
        c.score = _A_scoreAsVerifyCertChain(c.addr, c.size);
        c.validation = _A_validateVerifyCertChainCandidate(c.addr, c.size, sslX509StubAddr);
    }

    console.log("[anchor] ssl_x509.cc candidates:");
    var candidateLines = [];
    for (var u2 = 0; u2 < unique.length; u2++) {
        var c2 = unique[u2];
        var line = "  " + c2.addr + "  size=0x" + c2.size.toString(16) +
            "  score=" + c2.score + "  signals=" + c2.validation.signals +
            "  via=" + c2.via + "  [" + c2.validation.reasons.join(" ") + "]";
        console.log(line);
        candidateLines.push(line);
    }
    _A_diagState.candidatesDump = candidateLines.join("\n");

    // Only consider candidates that passed validation.
    var qualified = unique.filter(function (c) { return c.validation.ok; });
    if (qualified.length) {
        qualified.sort(function (a, b) {
            if (b.score !== a.score) return b.score - a.score;
            if (b.validation.signals !== a.validation.signals) return b.validation.signals - a.validation.signals;
            return b.size - a.size;
        });
        return qualified[0];
    }

    // If nothing qualified, loud warning and fall through to Strategy 2 / 3.
    console.warn("[anchor] No ssl_x509.cc candidate passed validation — falling back to weaker strategies.");
    console.warn("[anchor] This usually means: (a) wrong binary; (b) new compiler codegen; (c) a decoder regression.");

    // --- Strategy 2: ssl_client direct xref with function-size filter ---
    var ssl_client_addrs = _A_findAllStringsInModule(mod, "ssl_client");
    for (var n = 0; n < ssl_client_addrs.length; n++) {
        // Require exact "ssl_client\0" — already guaranteed by findAllStringsInModule
        var xrefs2 = _A_findAdrpAddXrefs(mod, ssl_client_addrs[n]);
        for (var q = 0; q < xrefs2.length; q++) {
            var pro = _A_walkToPrologue(xrefs2[q]);
            if (!pro) continue;
            var sz = _A_functionSize(pro);
            if (sz >= 0x100) {
                return { addr: pro, size: sz, via: "ssl_client-direct" };
            }
        }
    }

    return null;
}

/**
 * Fallback: resolve ssl_verify_peer_cert via handshake.cc path xref.
 * Uses Interceptor.replace semantics (return 0 = ssl_verify_ok).
 */
function resolveVerifyPeerCert(mod) {
    var handshake_paths = _A_findAllStringsInModule(mod, "../../../flutter/third_party/boringssl/src/ssl/handshake.cc");
    var best = null;
    for (var i = 0; i < handshake_paths.length; i++) {
        var xrefs = _A_findAdrpAddXrefs(mod, handshake_paths[i]);
        for (var j = 0; j < xrefs.length; j++) {
            var xref = xrefs[j];

            // Same stub-handling fix as resolveVerifyCertChain: if the xref IS a
            // stub entry, enumerate BL callers directly. Don't predicate on
            // walkback success — stubs at code-page boundaries have no preceding
            // function to anchor on.
            if (_A_isStubAtAdrp(xref)) {
                var blSites = _A_findBlCallers(mod, xref);
                for (var k = 0; k < blSites.length; k++) {
                    var cp = _A_walkToPrologue(blSites[k]);
                    if (!cp) continue;
                    var cs = _A_functionSize(cp);
                    if (cs >= 0x80 && (!best || cs > best.size)) {
                        best = { addr: cp, size: cs, via: "handshake.cc-stub" };
                    }
                }
                continue;
            }

            var pro = _A_walkToPrologue(xref);
            if (!pro) continue;
            var sz = _A_functionSize(pro);
            if (sz >= 0x100) {
                if (!best || sz > best.size) best = { addr: pro, size: sz, via: "handshake.cc-direct" };
            }
        }
    }
    return best;
}

/* ===================================================================
 * iOS-specific: handshake.cc pattern scan (unchanged from original)
 * =================================================================== */

var handshake_string_pattern_found_addr = null;

function scanMemoryIOSHandshake(scan_start_addr, scan_size, pattern, for_what) {
    Memory.scan(scan_start_addr, scan_size, pattern, {
        onMatch: function (address, size) {
            if (for_what === "handshake") {
                for (var off = 0; ; off += 1) {
                    var arrayBuff = new Uint8Array(ptr(address).sub(0x6).sub(off).readByteArray(6));
                    var hex = [];
                    for (var b of arrayBuff) hex.push(b.toString(16).padStart(2, '0'));
                    if (hex.join(' ') === "2e 2e 2f 2e 2e 2f") {
                        handshake_string_pattern_found_addr = ptr(address).sub(0x6).sub(off);
                        console.log("[*] handshake string pattern found at: " + address);
                        break;
                    }
                }
                if (appId_iOS == null) {
                    Thread.sleep(0.1);
                    appId_iOS = findAppId();
                }
            }
            else if (for_what === "handshake_adrp_add") {
                var disasm = Instruction.parse(address);
                if (disasm.mnemonic === "adrp") {
                    var adrp = disasm.operands.find(function (o) { return o.type === 'imm'; }) || { value: undefined };
                    disasm = Instruction.parse(disasm.next);
                    if (disasm.mnemonic !== "add") disasm = Instruction.parse(disasm.next);
                    var addOp = disasm.operands.find(function (o) { return o.type === 'imm'; });
                    if (adrp.value !== undefined && addOp && ptr(adrp.value).add(addOp.value).toString() === handshake_string_pattern_found_addr.toString()) {
                        for (var off = 0; ; off += 4) {
                            var di = Instruction.parse(address.sub(off));
                            if (di.mnemonic === "sub") {
                                var di2 = Instruction.parse(di.next);
                                if (di2.mnemonic === "stp" || di2.mnemonic === "str") {
                                    verify_peer_cert_func_addr = address.sub(off);
                                    console.log("[*] Found verify_peer_cert function address: " + verify_peer_cert_func_addr);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            else if (for_what === "Socket_CreateConnect") {
                Socket_CreateConnect_string_pattern_found_addr = address;
                console.log("[*] Socket_CreateConnect string pattern found at: " + address);
            }
            else if (for_what === "Socket_CreateConnect_func_addr") {
                Socket_CreateConnect_func_addr = address.sub(0x10).readPointer();
                console.log("[*] Found Socket_CreateConnect function address: " + Socket_CreateConnect_func_addr);
                resolveGetSockAddrFromSocketCreateConnect();
            }
        },
        onComplete: function () {
            if (for_what === "handshake" && handshake_string_pattern_found_addr != null) {
                var adrp_add_pattern = "?2 ?? 00 ?0 42 ?? ?? 91 00 02 80 52 21 22 80 52 c3 29 80 52";
                if (appId_iOS === "com.alibaba.sourcing") {
                    adrp_add_pattern = "?3 ?? 00 ?0 63 ?? ?? 91 00 02 80 52 01 00 80 52 22 22 80 52 84 25 80 52";
                }
                scanMemoryIOSHandshake(flutter_base.add(TEXT_segment_text_section_offset), TEXT_segment_text_section_size, adrp_add_pattern, "handshake_adrp_add");
            }
            else if (for_what === "Socket_CreateConnect" && Socket_CreateConnect_string_pattern_found_addr != null) {
                var addr_to_find = convertHexToByteString(Socket_CreateConnect_string_pattern_found_addr.toString());
                scanMemoryIOSHandshake(flutter_base.add(DATA_segment_const_section_offset), DATA_segment_const_section_size, addr_to_find, "Socket_CreateConnect_func_addr");
            }
            console.log("[*] scan memory done");
        }
    });
}

/* ===================================================================
 * Android: locate Socket_CreateConnect + GetSockAddr
 * (Same logic as original; still works on both builds.)
 * =================================================================== */

function resolveSocketCreateConnectAndroid() {
    var Socket_CreateConnect_string = '53 6f 63 6b 65 74 5f 43 72 65 61 74 65 43 6f 6e 6e 65 63 74 00';

    Memory.scan(flutter_base, PT_LOAD_rodata_p_memsz, Socket_CreateConnect_string, {
        onMatch: function (address) {
            Socket_CreateConnect_string_pattern_found_addr = address;
            console.log("[*] Socket_CreateConnect string pattern found at: " + address);
        },
        onComplete: function () {
            console.log("[*] Socket_CreateConnect string scan done");
            if (Socket_CreateConnect_string_pattern_found_addr == null) {
                console.log("[!] Socket_CreateConnect string not found — can't redirect traffic");
                return;
            }
            var addr_to_find = convertHexToByteString(Socket_CreateConnect_string_pattern_found_addr.toString());
            Memory.scan(flutter_base.add(PT_GNU_RELRO_p_vaddr), PT_GNU_RELRO_p_memsz, addr_to_find, {
                onMatch: function (address) {
                    Socket_CreateConnect_func_addr = address.sub(0x10).readPointer();
                    console.log("[*] Found Socket_CreateConnect function address: " + Socket_CreateConnect_func_addr);
                    resolveGetSockAddrFromSocketCreateConnect();
                },
                onComplete: function () { console.log("[*] relro scan done"); }
            });
        }
    });
}

function resolveGetSockAddrFromSocketCreateConnect() {
    if (Process.arch === 'arm64') {
        var bl_count = 0;
        for (var off = 0; ; off += 4) {
            var disasm = Instruction.parse(Socket_CreateConnect_func_addr.add(off));
            if (disasm.mnemonic === "bl") {
                bl_count++;
                if (bl_count === 2) {
                    var immOp = disasm.operands.find(function (o) { return o.type === 'imm'; });
                    GetSockAddr_func_addr = ptr(immOp.value);
                    console.log("[*] Found GetSockAddr function address: " + GetSockAddr_func_addr);
                    break;
                }
            }
        }
    } else if (Process.arch === 'x64') {
        var call_count = 0;
        for (var off = 0; ; off += 1) {
            try {
                var disasm = Instruction.parse(Socket_CreateConnect_func_addr.add(off));
                if (disasm.mnemonic === "call") {
                    call_count++;
                    if (call_count === 2) {
                        var immOp = disasm.operands.find(function (o) { return o.type === 'imm'; });
                        GetSockAddr_func_addr = ptr(immOp.value);
                        console.log("[*] Found GetSockAddr function address: " + GetSockAddr_func_addr);
                        break;
                    }
                }
            } catch (e) { continue; }
        }
    }
}

/* ===================================================================
 * Hook functions
 * =================================================================== */

function hookGetSockAddr() {
    Interceptor.attach(GetSockAddr_func_addr, {
        onEnter: function (args) { sockaddr = args[1]; },
        onLeave: function (retval) {}
    });
    Interceptor.attach(Module.getGlobalExportByName("socket"), {
        onEnter: function (args) {
            var overwrite = false;
            if (Process.platform === 'linux' && sockaddr != null && ptr(sockaddr).readU16() === 2) overwrite = true;
            else if (Process.platform === 'darwin' && sockaddr != null && ptr(sockaddr).add(0x1).readU8() === 2) overwrite = true;
            if (overwrite) {
                console.log("[*] Overwrite sockaddr as our burp proxy ip and port --> " + BURP_PROXY_IP + ":" + BURP_PROXY_PORT);
                ptr(sockaddr).add(0x2).writeU16(byteFlip(BURP_PROXY_PORT));
                ptr(sockaddr).add(0x4).writeByteArray(convertIpToByteArray(BURP_PROXY_IP));
                _A_diagState.socketOverwriteCount++;
            }
        },
        onLeave: function (retval) {}
    });
}

function hookVerifyCertChainAttach() {
    // Semantics of ssl_crypto_x509_session_verify_cert_chain: bool — true=valid.
    // Force retval 0 → 1 on return.
    Interceptor.attach(verify_cert_chain_func_addr, {
        onEnter: function (args) {
            _A_diagState.hookEnterCount++;
            console.log("[trace] verify_cert_chain ENTER  arg0=" + args[0] + "  arg1=" + args[1] + "  arg2=" + args[2]);
        },
        onLeave: function (retval) {
            var v = retval.toInt32();
            if (v === 0) _A_diagState.hookRetvalZeroCount++;
            else if (v === 1) _A_diagState.hookRetvalOneCount++;
            console.log("[trace] verify_cert_chain LEAVE  retval=" + v);
            if (v === 0) {
                console.log("[*] verify cert bypass (return 0 -> 1)");
                retval.replace(ptr(0x1));
            }
        }
    });
}

function hookVerifyPeerCertReplace() {
    // Semantics of ssl_verify_peer_cert: enum — ssl_verify_ok = 0.
    // Replace whole function with `mov w0, #0; ret`.
    Interceptor.replace(verify_peer_cert_func_addr, new NativeCallback(function () {
        console.log("[*] verify peer cert bypass (return 0 = ssl_verify_ok)");
        return 0;
    }, 'int', ['pointer', 'int']));
}

/* ===================================================================
 * ELF parsing (unchanged from original script)
 * =================================================================== */

var O_RDONLY = 0, SEEK_SET = 0;
var p_types = {
    "PT_NULL": 0, "PT_LOAD": 1, "PT_DYNAMIC": 2, "PT_INTERP": 3, "PT_NOTE": 4,
    "PT_SHLIB": 5, "PT_PHDR": 6, "PT_TLS": 7, "PT_NUM": 8, "PT_LOOS": 0x60000000,
    "PT_GNU_EH_FRAME": 0x6474e550, "PT_GNU_STACK": 0x6474e551,
    "PT_GNU_RELRO": 0x6474e552, "PT_GNU_PROPERTY": 0x6474e553,
};

function getExportFunction(name, ret, args) {
    var funcPtr = Module.getGlobalExportByName(name);
    if (funcPtr === null) return null;
    return new NativeFunction(funcPtr, ret, args);
}

var open_fn = getExportFunction("open", "int", ["pointer", "int", "int"]);
var read_fn = getExportFunction("read", "int", ["int", "pointer", "int"]);
var lseek_fn = getExportFunction("lseek", "int", ["int", "int", "int"]);

function parseElf(base) {
    base = ptr(base);
    var module = Process.findModuleByAddress(base);
    var fd = null;
    if (module !== null) fd = open_fn(Memory.allocUtf8String(module.path), O_RDONLY, 0);

    var is32bit = Process.arch === "arm" ? 1 : 0;
    var size_of_Elf64_Ehdr = 0x40;
    var off_of_Elf64_Ehdr_phentsize = 54;
    var off_of_Elf64_Ehdr_phnum = 56;

    var phoff = is32bit ? 0x34 : size_of_Elf64_Ehdr;
    var phentsize = is32bit ? 32 : base.add(off_of_Elf64_Ehdr_phentsize).readU16();
    if (!is32bit && phentsize !== 56) phentsize = 56;
    var phnum = is32bit ? base.add(44).readU16() : base.add(off_of_Elf64_Ehdr_phnum).readU16();
    if (phnum === 0 && fd != null && fd !== -1) {
        var ehdrs_from_file = Memory.alloc(64);
        lseek_fn(fd, 0, SEEK_SET);
        read_fn(fd, ehdrs_from_file, 64);
        phnum = ehdrs_from_file.add(off_of_Elf64_Ehdr_phnum).readU16();
        if (phnum === 0) phnum = 10;
    }

    var phdrs = base.add(phoff);
    for (var i = 0; i < phnum; i++) {
        var phdr = phdrs.add(i * phentsize);
        var p_type = phdr.readU32();
        var p_type_sym = null;
        for (var key in p_types) if (p_types[key] === p_type) { p_type_sym = key; break; }
        if (p_type_sym == null) break;

        var p_vaddr = is32bit ? phdr.add(0x8).readU32() : phdr.add(0x10).readU64();
        var p_memsz = is32bit ? phdr.add(0x14).readU32() : phdr.add(0x28).readU64();

        if (p_type_sym === 'PT_LOAD' && p_vaddr == 0) { PT_LOAD_rodata_p_memsz = p_memsz; continue; }
        if (p_type_sym === 'PT_LOAD' && p_vaddr != 0) {
            if (PT_LOAD_text_p_vaddr == null) { PT_LOAD_text_p_vaddr = p_vaddr; PT_LOAD_text_p_memsz = p_memsz; }
            continue;
        }
        if (p_type_sym === 'PT_GNU_RELRO') { PT_GNU_RELRO_p_vaddr = p_vaddr; PT_GNU_RELRO_p_memsz = p_memsz; break; }
    }
}

function parseMachO(base) {
    base = ptr(base);
    var magic = base.readU32();
    if (magic !== 0xfeedfacf) { console.log("Unknown magic"); return; }
    var cmdnum = base.add(0x10).readU32();
    var cmdoff = 0x20;
    for (var i = 0; i < cmdnum; i++) {
        var cmd = base.add(cmdoff).readU32();
        var cmdsize = base.add(cmdoff + 0x4).readU32();
        if (cmd === 0x19) {
            var segname = base.add(cmdoff + 0x8).readUtf8String();
            var nsects = base.add(cmdoff + 0x40).readU8();
            var secbase = base.add(cmdoff + 0x48);
            var tIdx = 0, cIdx = 0, dIdx = 0;
            for (var j = 0; j < nsects; j++) {
                var secname = secbase.add(j * 0x50).readUtf8String();
                var sstart = secbase.add(j * 0x50 + 0x30).readU32();
                if (segname === '__TEXT' && secname === '__text') { tIdx = j; TEXT_segment_text_section_offset = sstart; }
                else if (segname === '__TEXT' && j === tIdx + 1) { TEXT_segment_text_section_size = sstart - TEXT_segment_text_section_offset; }
                else if (segname === '__TEXT' && secname === '__cstring') { cIdx = j; TEXT_segment_cstring_section_offset = sstart; }
                else if (segname === '__TEXT' && j === cIdx + 1) { TEXT_segment_cstring_section_size = sstart - TEXT_segment_cstring_section_offset; }
                else if (segname === '__DATA' && secname === '__const') { dIdx = j; DATA_segment_const_section_offset = sstart; }
                else if (segname === '__DATA' && j === dIdx + 1) { DATA_segment_const_section_size = sstart - DATA_segment_const_section_offset; }
            }
        }
        cmdoff += cmdsize;
    }
}

/* ===================================================================
 * Main
 * =================================================================== */

var target_flutter_library = ObjC.available ? "Flutter.framework/Flutter" : (Java.available ? "libflutter.so" : null);

if (target_flutter_library != null) {
    BURP_PROXY_IP = "127.0.0.1";
    BURP_PROXY_PORT = 8080;

    var awaitForCondition = function (callback) {
        var module_loaded = 0, base = null;
        var handle = setInterval(function () {
            Process.enumerateModules()
                .filter(function (m) { return m.path.indexOf(target_flutter_library) !== -1; })
                .forEach(function (m) {
                    if (ObjC.available) target_flutter_library = target_flutter_library.split('/').pop();
                    console.log("[*] " + target_flutter_library + " loaded!");
                    flutter_module = Process.getModuleByName(target_flutter_library);
                    base = flutter_module.base;
                    module_loaded = 1;
                });
            if (module_loaded) { clearInterval(handle); callback(+base); }
        }, 0);
    };

    function init(base) {
        flutter_base = ptr(base);
        console.log("[*] " + target_flutter_library + " base: " + flutter_base);

        // Fail loud if the decoder bit-math is broken before we waste time
        // scanning a 10 MB .text region for nothing.
        _A_selfTest();

        if (Process.platform === 'linux') {
            appId = findAppId();
            console.log("[*] package name: " + appId);

            parseElf(flutter_base);

            // --- Resolve verify_cert_chain via new anchor chain ---
            var vcc = resolveVerifyCertChain(flutter_module);
            if (vcc) {
                verify_cert_chain_func_addr = vcc.addr;
                verify_cert_chain_strategy = "attach-replace-1";
                _A_diagState.resolvedVccAddr = vcc.addr.toString();
                _A_diagState.resolvedVccVia = vcc.via;
                console.log("[*] verify_cert_chain resolved via " + vcc.via +
                    " @ " + vcc.addr + " (size=0x" + vcc.size.toString(16) + ")");
            } else {
                console.log("[!] verify_cert_chain NOT resolved — trying ssl_verify_peer_cert fallback");
                var vpc = resolveVerifyPeerCert(flutter_module);
                if (vpc) {
                    verify_peer_cert_func_addr = vpc.addr;
                    verify_cert_chain_strategy = "replace-return-0";
                    _A_diagState.resolvedVccAddr = vpc.addr.toString();
                    _A_diagState.resolvedVccVia = vpc.via;
                    console.log("[*] ssl_verify_peer_cert resolved via " + vpc.via +
                        " @ " + vpc.addr + " (size=0x" + vpc.size.toString(16) + ")");
                } else {
                    console.log("[!] BOTH strategies failed — SSL pinning bypass UNAVAILABLE.");
                    console.log("[!] Re-run /flutter-frida-repair against this libflutter.so to regenerate anchors.");
                    _A_writeAutoDiag("resolution failed: both strategies returned null", flutter_module);
                }
            }

            // --- Socket_CreateConnect → GetSockAddr (unchanged) ---
            resolveSocketCreateConnectAndroid();

            // --- Runtime watchdogs: catch the "hooked but wrong/silent" failure modes ---
            //
            // Watchdog A: at 15s, if TLS traffic happened (socket overwrites fired) but
            // verify_cert_chain never entered, we almost certainly hooked the wrong sibling.
            //
            // Watchdog B: at 20s, if the hook fired >=5 times and ALL returned 1 (never 0),
            // either we're on the wrong sibling OR Flutter uses Dart-side pinning. Either
            // way the Frida bypass isn't doing anything; the user needs the diag dump.
            setTimeout(function () {
                if (_A_diagState.socketOverwriteCount > 0 && _A_diagState.hookEnterCount === 0) {
                    _A_writeAutoDiag("watchdog A: TLS activity observed (" +
                        _A_diagState.socketOverwriteCount + " socket overwrites) but " +
                        "verify_cert_chain never entered — hook is on the wrong function",
                        flutter_module);
                }
            }, 15000);
            setTimeout(function () {
                if (_A_diagState.hookEnterCount >= 5 &&
                    _A_diagState.hookRetvalZeroCount === 0 &&
                    _A_diagState.hookRetvalOneCount === _A_diagState.hookEnterCount) {
                    _A_writeAutoDiag("watchdog B: hook fired " + _A_diagState.hookEnterCount +
                        " times, all returned 1 — either wrong sibling or Dart-side pinning",
                        flutter_module);
                }
            }, 20000);
        }
        else if (Process.platform === 'darwin') {
            parseMachO(flutter_base);
            var handshake_string = '74 68 69 72 64 5f 70 61 72 74 79 2f 62 6f 72 69 6e 67 73 73 6c 2f 73 72 63 2f 73 73 6c 2f 68 61 6e 64 73 68 61 6b 65 2e 63 63';
            var Socket_CreateConnect_string = '53 6f 63 6b 65 74 5f 43 72 65 61 74 65 43 6f 6e 6e 65 63 74 00';
            scanMemoryIOSHandshake(flutter_base.add(TEXT_segment_cstring_section_offset), TEXT_segment_cstring_section_size, handshake_string, "handshake");
            scanMemoryIOSHandshake(flutter_base.add(TEXT_segment_cstring_section_offset), TEXT_segment_cstring_section_size, Socket_CreateConnect_string, "Socket_CreateConnect");
            verify_cert_chain_strategy = "replace-return-0";
        }

        // --- Install hooks once addresses resolve ---
        var getSockPoll = setInterval(function () {
            if (GetSockAddr_func_addr != null) {
                console.log("[*] Hook GetSockAddr function");
                hookGetSockAddr();
                clearInterval(getSockPoll);
            }
        }, 0);

        var verifyPoll = setInterval(function () {
            if (verify_cert_chain_strategy === "attach-replace-1" && verify_cert_chain_func_addr != null) {
                console.log("[*] Hook verify_cert_chain function (attach + retval.replace(1))");
                hookVerifyCertChainAttach();
                clearInterval(verifyPoll);
            } else if (verify_cert_chain_strategy === "replace-return-0" && verify_peer_cert_func_addr != null) {
                console.log("[*] Hook verify_peer_cert function (Interceptor.replace -> 0)");
                hookVerifyPeerCertReplace();
                clearInterval(verifyPoll);
            }
        }, 0);

        // Stop polling after 10 seconds if nothing resolved
        setTimeout(function () { clearInterval(verifyPoll); }, 10000);
    }

    awaitForCondition(init);
}
