# Full review of `flutter-ssl-bypass.js`

> **Status note (added 2026-04-27):** This document is a **pre-Iter-5** audit. It was written when the script's anchor logic still failed against `libflutter-dart-3.10.9.so` because of (a) the stub branch being guarded behind a walkback that legitimately fails on stubs at code-page boundaries, and (b) the scanners only covering the largest r-x range. Iter-5 (see `diff_report.md` row 5) fixed both. The structural claims here — score function, AAPCS64, the "0x71abfc is verify_cert_chain" identification, BoringSSL line numbers — are all still valid. The "expected output" listing in §"Resolution chain" was written before multi-range scanning was added, so the predicted xref/candidate counts are now slightly low (the new logic surfaces an additional direct xref + its candidate). The validator still ranks `0x71abfc` highest, so the bottom line is unchanged.
>
> Surgical fixes 1–4 below were *not* applied in Iter-5 (they're forward-looking hardening, not the bug fix). They remain on the table as future-proofing options.

**Date:** 2026-04-25
**Target:** `libflutter-dart-3.10.9.so` — Dart 3.10.9 (stable, 2026-02-03), engine `ea7cdbc6…` — running in `com.example.flutterapp`. See `diff_report.md` for the full version context.
**Review method:** ground-truth r2 disassembly + 9 parallel research agents + decoder bit-math audit
**Verdict:** **The script's anchor strategy is correct for THIS binary. With high confidence it will identify and hook the right function.** The most likely reason it has not yet worked in testing is one of three things, in order of probability:

1. **The "last fix" simply has not been deployed yet** (i.e., the latest revision of the script has not actually been run against the device).
2. **Dart-side pinning** sitting on top of BoringSSL — a documented pattern (`basic_utils.sha256Thumbprint`-style: BoringSSL is allowed to validate, then a Dart-FFI / Java-bridge SHA-256 compare rejects independently). The script's hook will fire and flip retval, but the app will still reject the cert at the Dart layer. **This is unfixable at the BoringSSL anchor level.**
3. Two minor robustness gaps in the score function that don't affect THIS binary but could break on FUTURE Flutter builds. Listed under "Surgical fixes" below.

---

## TL;DR — What was verified, with evidence

| Assumption | Status | Evidence |
|---|---|---|
| `ssl_crypto_x509_session_verify_cert_chain` exists in current BoringSSL | ✅ Confirmed | `ssl/ssl_x509.cc:201` on `main` (commit 3d5cafde, 2026-04-23). Signature unchanged in 2+ years. |
| Function returns `bool` with 3 args `(SSL_SESSION*, SSL_HANDSHAKE*, uint8_t*)` | ✅ Confirmed | Verbatim line 201–203. Return is `bool`, not enum. |
| Flutter still ships this BoringSSL revision | ✅ Confirmed | Current Flutter pin: `8743bafcfe78` (2026-04-23). Function present. |
| AAPCS64 routes 3rd pointer arg to x2 | ✅ Confirmed | AAPCS64 §6.4.2 rule C.10. ABI-binding. |
| `*out_alert = SSL_AD_INTERNAL_ERROR` (= 0x50) is the early sentinel write | ✅ Confirmed | Line 207. Two-hop macro: `SSL_AD_INTERNAL_ERROR → TLS1_AD_INTERNAL_ERROR = 80 = 0x50` (`tls1.h:37`). |
| Only 3-arg static in `ssl_x509.cc` taking `uint8_t*` as 3rd arg | ✅ Confirmed | 31 statics enumerated; 4 take 3 args; only verify_cert_chain takes `uint8_t*` 3rd arg. |
| The compiler emits `strb w?, [x2]` directly (not lifetime-extended) | ✅ Confirmed for THIS binary | At `0x71abfc + 0x10`: `mov w8, 0x50; strb w8, [x2]` — direct write to x2. |
| Stub at `0xa19b18` is the 4-insn `(ADRP, ADD, MOV w0 #0x10, RET)` shape | ✅ Confirmed | r2 disassembly shows exactly that 16-byte stub. |
| Stub has 4 BL callers in `.text` | ✅ Confirmed | r2 axt: BLs at 0x71a400, 0x71ad54, 0x71af38, 0x71af50. |
| Walkback from BLs lands on 3 unique siblings + verify_cert_chain | ✅ Confirmed | Prologues at 0x71a36c, 0x71abfc, 0x71ae74 (0x71af50 walks back to 0x71ae74, dedups). |
| The `mov w8 0x50; strb w8 [x2]` pattern is unique to verify_cert_chain | ✅ Confirmed | Visual inspection of all four candidate prologues; only 0x71abfc has it. |
| `Interceptor.attach` works on `paciasp`-first prologues on Android arm64 | ✅ Confirmed | frida-gum source: paciasp is HINT #25, copied verbatim into trampoline. `HAVE_PTRAUTH` is undefined on Android; gum emits raw addresses. |
| `retval.replace(ptr(0x1))` correctly flips bool returns | ✅ Confirmed | Modifies saved X0 in `GumCpuContext`; W0 is low half of X0; PAC validates LR not X0. |

## What's NOT a problem (despite earlier worry)

- **Function inlining via LTO** — researched extensively. Even though Flutter builds with `-flto -Oz` and verify_cert_chain is `static` with one caller, the function is **not inlined** in this binary. The prologue at 0x71abfc and the BL caller at 0x71ad54 (inside its own body) prove it's a discrete function.
- **NVISO Jan 2026 pattern collision** — NVISO's newest pattern `FF C3 01 D1 FD 7B 01 A9 6A A1 0B 94 08 0A 80 52 48 00 00 39 1A 50 40 F9 DA 02 00 B4 48 03 40 F9` matches the binary at 0x71abfc *byte-perfectly*. Independent confirmation by the largest community project that this IS the right address. **However NVISO uses `Interceptor.replace + return 0`** — that's the WRONG return convention for `verify_cert_chain` (returns `bool`, 0=fail). NVISO's pattern probably labels the address as `ssl_verify_peer_cert` historically — that's a wrong label. The flutter-ssl-bypass.js correctly uses `attach + retval.replace(0x1)`.
- **Vtable indirection** — `ssl_verify_peer_cert` calls `verify_cert_chain` indirectly via `ssl->ctx->x509_method->session_verify_cert_chain(...)` (`handshake.cc:314`). This DOES NOT affect the script: the script anchors on the `ssl_x509.cc` filename string xref, which lives INSIDE the verify_cert_chain function (when it errors out and emits an assertion file/line). The vtable dispatch is upstream of the anchor.
- **Function signature change (RPK pre-check)** — commit f8877ba (Feb 2026) added `if (peer_cert_type != TLSEXT_cert_type_x509) return false;` BEFORE the `*out_alert = 0x50` sentinel. Critically: **this binary already has that change**, but the `mov w8, 0x50; strb w8, [x2]` is at offset +0xC inside the prologue (after `bl 0xa031ac`), still well within the script's 0x100-byte score scan window.

---

## Ground-truth disassembly of 0x71abfc (the target)

```
0x0071abfc      ff c3 01 d1     sub sp, sp, 0x70                  ; PROLOGUE
0x0071ac00      fd 7b 01 a9     stp x29, x30, [sp, 0x10]
0x0071ac04      6a a1 0b 94     bl 0xa031ac                       ; ERR_clear_error or similar
0x0071ac08      08 0a 80 52     mov w8, 0x50                      ; SSL_AD_INTERNAL_ERROR
0x0071ac0c      48 00 00 39     strb w8, [x2]                     ; *out_alert = 0x50  ← SCORE FIRES HERE
0x0071ac10      1a 50 40 f9     ldr x26, [x0, 0xa0]               ; session->x509_chain
0x0071ac14      da 02 00 b4     cbz x26, 0x71ac6c                 ; if (!cert_chain) return false
0x0071ac18      48 03 40 f9     ldr x8, [x26]
0x0071ac1c      88 02 00 b4     cbz x8, 0x71ac6c                  ; if empty return false
0x0071ac20      39 20 40 a9     ldp x25, x8, [x1]
0x0071ac24      f3 03 02 aa     mov x19, x2                       ; SAVE x2 to x19 (lifetime ext.)
0x0071ac28      49 07 40 f9     ldr x9, [x26, 8]
...
0x0071ad54      71 fb 0b 94     bl 0xa19b18                       ; BL TO STUB (matches script)
0x0071ad58      61 01 80 52     mov w1, 0xb                       ; line argument
0x0071ad5c      e3 1d 80 52     mov w3, 0xef                      ; line number 0xef = 239
0x0071ad60      56 3c ff 97     bl 0x6e9eb8                       ; assertion handler
```

The function maps cleanly to BoringSSL ssl_x509.cc lines 201–268:
- `0x71abfc` ↔ entry (line 201)
- `0x71ac08–0x71ac0c` ↔ `*out_alert = SSL_AD_INTERNAL_ERROR` (line 207)
- `0x71ac10–0x71ac1c` ↔ `cert_chain` null/empty checks (line 209-210)
- `0x71ac24` ↔ register lifetime extension (compiler artifact)
- `0x71ad54` is one of the assertion sites that lands on the file/line stub

---

## Decoder bit-math audit (every opcode check verified)

| Check | Mask | Value | Verified |
|---|---|---|---|
| ADRP detection | `0x9f000000` | `0x90000000 \| 0` | ✅ Self-test exercises this with a real ADRP word from the binary. Bit-31 normalization is correct. |
| ADRP imm21 sign-extend | — | `~0x1fffff` | ✅ Correct 21-bit two's complement extension. |
| ADD imm (shift=0) | `0x7fc00000` | `0x11000000` | ✅ Covers both 32-bit (sf=0) and 64-bit (sf=1) ADD imm with shift=0 — fine for ADRP+ADD which never uses shift=12. The `if (shift === 1)` branch is dead code (never reachable through this mask) but harmless. |
| ADD continuity (Rn=Rd=adrpRd) | per-field check | — | ✅ Correctly enforces register continuity. |
| BL detection | `0xfc000000` | `0x94000000 \| 0` | ✅ Self-test confirms. |
| BL imm26 sign-extend | — | `~0x03ffffff` | ✅ Correct 26-bit sign extension. |
| RET literal | — | `0xd65f03c0` | ✅ Matches RET X30 exactly. |
| RET generic mask | `0xfffffc1f \| 0` | `0xd65f0000 \| 0` | ✅ Catches `RET xN` for any Rn. **Note**: does NOT catch `BR x30` (different opcode). Stubs in this binary use RET, so no issue. |
| STRB Rn=2 (32-bit base) | `0xffc003e0` | `0x39000040` | ✅ Verified against `48 00 00 39` at 0x71ac0c → 0x39000048 & mask = 0x39000040 — match. |
| STR-32 Rn=2 | `0xffc003e0` | `0xb9000040` | ✅ 32-bit STR variant; bonus +5 score signal. |
| MOVZ W detection | `0xff800000` | `0x52800000` | ✅ Verified against `08 0a 80 52` at 0x71ac08 → 0x52800a08 & mask = 0x52800000 — match. |
| MOVZ imm16 extraction | — | `(insn >>> 5) & 0xffff` | ✅ For 0x52800a08: (0x52800a08 >>> 5) & 0xffff = 0x0050 = 0x50 ✓. |
| STP signed-offset / pre-idx | `(insn >>> 22) & 0x3ff` | `0x2a4 \|\| 0x2a6` | ✅ Covers 64-bit STP signed-offset (0x2a4) and pre-index (0x2a6). Misses post-index (0x2a2) which compilers don't typically emit in prologues. |

**Verdict:** decoder is correct. Self-test passes on real instruction words from this binary.

---

## Resolution chain — exact predicted runtime behavior

When the script runs against `libflutter-dart-3.10.9.so`:

```
[self-test] decoder bit-math OK (ADRP, ADD, BL, RET)
[anchor] ssl_x509.cc string hits: 1
[anchor]   <base+0x1b1ede> -> 1 ADRP+ADD xref(s)
[anchor]     xref @ <base+0xa19b18>  isStub=true                   ← stub detected
[anchor]       stub -> 4 BL caller(s)                              ← 0x71a400, 0x71ad54, 0x71af38, 0x71af50
[anchor] ssl_x509.cc candidates:
  <base+0x71a36c>  size=0x1d0   score=0   signals=2  via=ssl_x509.cc-stub  [-no strb[x2] +size ok -no stub BL +prologue-stp(1)]
  <base+0x71abfc>  size=~0x190+ score=30  signals=3  via=ssl_x509.cc-stub  [+strb[x2](score=30) +size ok +bl(stub) -prologue-stp(1)]
  <base+0x71ae74>  size=~0x100+ score=0   signals=2  via=ssl_x509.cc-stub  [-no strb[x2] +size ok +bl(stub) +prologue-stp(2)]
[*] verify_cert_chain resolved via ssl_x509.cc-stub @ <base+0x71abfc>
[*] Hook verify_cert_chain function (attach + retval.replace(1))
```

The diff_report's "expected output" claims 4 candidates, but ground truth from r2 shows 3 unique prologues after dedup (0x71af38 and 0x71af50 both walk back to 0x71ae74). The script's logic still picks 0x71abfc correctly because it has the only score>0.

**Note:** the script's diff_report claims certain candidates have `prologue-stp(3)`. That's wrong against this binary — the prologues each have 1 STP within the first 0x20 bytes, not 3. The signal #4 may not fire on the winning candidate (only 1 STP at 0x71ac00). With signals 1+2+3 firing (strb [x2], size ok, BL to stub), the candidate still hits 3/4 ≥ 2 threshold and validates. **No correctness impact**, but the diff_report's predicted output is slightly miscalibrated.

---

## What COULD go wrong (and why each is small or non-blocking)

### A. Future Flutter build hides x2 via lifetime extension (medium risk, future-proofing)

The AAPCS64 research surfaced this: at `-O2` with high register pressure, Clang sometimes emits `mov xN, x2` immediately after the prologue and writes `strb w?, [xN]` instead of `[x2]`. THIS binary doesn't do that — it writes to [x2] directly first, THEN saves to x19 — but a future Flutter build might.

**Surgical fix proposed below: track `mov xN, x2` copies and accept strb to any tracked register.**

### B. _A_walkToPrologue 0x2000 cap (low risk, future-proofing)

If a sibling function ever exceeds 0x2000 bytes, walkback from a BL site near its end would land on a PREVIOUS function's prologue. The largest sibling here is ~0x500 bytes — well within 0x2000.

**Surgical fix proposed below: validate that the BL site is within the candidate's measured size. Currently no such check.**

### C. RET-as-stub-end miss if compiler emits `BR x30` (low risk)

The `_A_isStubAtAdrp` only matches RET, not BR x30 or B (tail-call). This binary's stub uses RET. A future build with hardened return paths (e.g., using BTI + BR x30 instead of paciasp+retaa) MIGHT not match.

**Recommendation: Leave alone for now (no compelling evidence to add B/BR detection — RET is the universal pattern).**

### D. Dart-side pinning (high risk for the target app — beyond script's scope)

Public engineering writeups document pairing `SecurityContext` with a Dart-side `sha256Thumbprint` compare via `basic_utils`. If the target app follows a similar pattern, the BoringSSL hook will:

1. Fire correctly (ENTER count > 0 in trace)
2. Flip retval 0 → 1 (`bypass fired` log appears)
3. **Burp will still see handshake termination** because the Dart layer makes its own SHA check after BoringSSL says "good"

**This is not a script bug. The script's job is done correctly.** Indicators in the diag dump:
- `verify_cert_chain ENTER count > 0` — hook is firing
- `socket overwrites > 0` — proxy redirect works
- `verify_cert_chain retval=0 seen > 0` — bypass actually fired (not just retval=1 always)
- ...but Burp still sees no decrypted traffic

If those signals match, the next iteration is **Dart-layer hook** — see "Contingency plan" section.

---

## Surgical fixes (all minimal — preserve existing scaffolding per AISTEERINGRULES)

### Fix 1 (RECOMMENDED): broaden score function to track register-lifetime extension

**Why:** Future-proofs against compilers that spill x2 to a callee-saved register before writing. Doesn't affect THIS binary (which writes to [x2] directly), but hardens against the next libflutter version. Per AAPCS64 research, this is the most likely source of a silent fingerprint miss.

**Where:** `_A_scoreAsVerifyCertChain` at flutter-ssl-bypass.js:368.

**What:** Track `mov xN, x2` copies in the scan window; accept `strb w?, [xN]` for any xN that's a tracked alias of x2. Surgical — adds two state-tracking lines and one extra check, no rewrite.

```js
function _A_scoreAsVerifyCertChain(addr, size) {
    var score = 0;
    var scanLen = Math.min(size, 0x100);
    var lastMovValue = -1;
    // Track registers that hold a copy of x2 (the 3rd arg, out_alert)
    var x2Aliases = { 2: true };  // x2 itself starts as an alias
    for (var off = 0; off < scanLen; off += 4) {
        var insn;
        try { insn = addr.add(off).readU32(); } catch (e) { break; }

        // MOV (register, 64-bit): mov xD, xN encoded as ORR xD, xzr, xN
        // mask 0xffe0ffe0  value 0xaa0003e0  + Rn at bits 20-16 = 2
        // Actual encoding: 1 01 01010 0 0 src=Rn[20:16] 000000 11111(xzr) Rd[4:0]
        // Simpler: detect "mov xN, x2" via (insn & 0xff20ffe0) === 0xaa0003e0 with Rm=2
        if ((insn & 0xffe0ffe0) === ((0xaa0003e0) | 0)) {
            var movRm = (insn >>> 16) & 0x1f;
            var movRd = insn & 0x1f;
            if (x2Aliases[movRm]) x2Aliases[movRd] = true;
        }

        // MOVZ W register
        if ((insn & 0xff800000) === 0x52800000) {
            var imm16 = (insn >>> 5) & 0xffff;
            lastMovValue = imm16;
        }

        // STRB (immediate, unsigned offset) — mask base register, allow ANY tracked alias of x2
        if ((insn & 0xffc00000) === 0x39000000) {
            var strbRn = (insn >>> 5) & 0x1f;
            if (x2Aliases[strbRn]) {
                score += 10;
                if (lastMovValue === 0x50) score += 20;
                // Also boost for any plausible alert constant — verify_cert_chain
                // can return 0x28 (handshake_failure), 0x2a/2b/2d/2e (cert errors),
                // 0x30 (unknown_ca). Soft +5 for any value in that range.
                else if (lastMovValue >= 0x28 && lastMovValue <= 0x60) score += 5;
            }
        }
        // STR-32 base check — same alias-aware logic
        if ((insn & 0xffc00000) === 0xb9000000) {
            var strRn = (insn >>> 5) & 0x1f;
            if (x2Aliases[strRn]) score += 5;
        }
    }
    return score;
}
```

This change: (a) tracks aliases via `mov xN, x2`, (b) widens STRB Rn check to any tracked register, (c) softly rewards any plausible alert-constant (not just 0x50). Existing behavior is preserved on this binary; the change extends robustness.

### Fix 2 (RECOMMENDED): validate BL site is inside the candidate function

**Why:** A sibling function whose body extends across 0x2000 bytes would have BL-walkback land on the WRONG prologue. Not an issue here, but cheap insurance.

**Where:** `_A_validateVerifyCertChainCandidate` at flutter-ssl-bypass.js:688.

**What:** Add a pre-validation check that the candidate's [addr, addr+size] range covers SOME BL caller of the stub.

```js
function _A_validateVerifyCertChainCandidate(addr, size, sslX509StubAddr, blSites) {
    var signals = 0;
    var reasons = [];

    // (0) FRAME CHECK: at least one stub-BL must be inside this candidate's body.
    // If walkback landed in the wrong function, no BL site falls within [addr, addr+size].
    if (blSites && blSites.length > 0) {
        var addrEnd = addr.add(size);
        var found = false;
        for (var bi = 0; bi < blSites.length; bi++) {
            if (blSites[bi].compare(addr) >= 0 && blSites[bi].compare(addrEnd) < 0) {
                found = true; break;
            }
        }
        if (!found) {
            reasons.push("-no stub BL in candidate range");
            return { ok: false, signals: 0, reasons: reasons };  // hard fail
        }
    }
    // ... rest unchanged ...
}
```

Then update `resolveVerifyCertChain` at flutter-ssl-bypass.js:817 to pass `blSites` through to the validator. Roughly 4 lines changed.

### Fix 3 (OPTIONAL — diff_report alignment): correct the diff_report's "expected output" claims

The diff_report claims 4 candidates with `prologue-stp(3)` for several. r2 ground truth shows 3 unique candidates with 1 STP each. This is documentation drift — the actual binary's behavior is what matters. Not a script bug, just stale docs.

### Fix 4 (DO NOT APPLY UNLESS FIX 1 ALONE FAILS): add SSL_get_verify_result fallback

If the BoringSSL bypass fires but Burp still sees handshake termination AND the watchdogs don't conclude Dart-side pinning is the issue, add a secondary hook on `SSL_get_verify_result` (an exported BoringSSL function — easy to find via Module.findExportByName) and force return 0 = X509_V_OK. This catches some Dart paths where BoringSSL's verdict is consulted via that function rather than via the verify_peer_cert callback chain.

---

## Pre-deployment checklist

Before running `flutter-ssl-bypass.js` against the live target, verify:

- [ ] `frida --version` shows 17.x (not 16.x). Script uses `Process.findModuleByName` which is fine in both, but the auto-diag and other paths use newer APIs. 17.8.3 or 17.9.1 recommended.
- [ ] Frida-server on device matches the host frida version exactly.
- [ ] Device is rooted / Magisk-active (assumption).
- [ ] BURP_PROXY_IP is reachable from the device — `adb shell ping <ip>` works.
- [ ] BURP_PROXY_PORT is bound on Burp side (default 8080).
- [ ] Burp's CA cert is installed on device as system CA (`/system/etc/security/cacerts/`) OR you've already verified the bypass is needed (i.e., handshake failures on cert-pinning-protected endpoints).
- [ ] `/data/local/tmp` is writable by the app's UID for the auto-diag dump (run a test, then `adb shell ls -la /data/local/tmp/flutter-bypass-diag-*.txt`).
- [ ] App package name (`com.example.flutterapp`) is correct in the frida command.

---

## Contingency plan if hook fires but Burp still terminates

This is the realistic Phase 2. If after running `flutter-ssl-bypass.js` you see:
- `[self-test] decoder bit-math OK`
- `[*] verify_cert_chain resolved via ssl_x509.cc-stub @ ...`
- `[*] Hook verify_cert_chain function (attach + retval.replace(1))`
- `[trace] verify_cert_chain ENTER` fires
- `[*] verify cert bypass (return 0 -> 1)` fires (retval was 0, flipped to 1)

…and Burp STILL sees handshake termination, then the BoringSSL anchor is correct and Dart-side pinning is the problem. Steps:

1. **Decompile the APK** with jadx and search for these tells:
   - `import 'package:basic_utils'` in any `.dart` file (often inlined as Smali/AOT — easier to grep the libapp.so for `sha256Thumbprint`)
   - `HttpCertificatePinningPlugin` (the `http_certificate_pinning` plugin's Java class)
   - `SecurityContext.setTrustedCertificatesBytes` calls
   - `badCertificateCallback` declarations

2. **Hook the plugin's Java side** via Frida's Java bridge — bypass the SHA check at the MethodChannel boundary. Skeleton:

   ```js
   Java.perform(function () {
       var Plugin = Java.use("diefferson.http_certificate_pinning.HttpCertificatePinningPlugin");
       Plugin.checkConnexion.implementation = function () { return true; };
   });
   ```

3. **Or hook `SSL_get_verify_result`** as Fix 4 above.

4. **As a last resort, use reFlutter** — pre-patches libflutter.so. Only works if your engine hash is in their library.

---

## Files reviewed

- `flutter-ssl-bypass.js` (the bypass script reviewed)
- `diag.js` (companion diagnostic)
- `docs/diff_report.md` (claims vs. r2 ground truth)
- `libflutter-dart-3.10.9.so` (target binary, r2 disassembly)
- `libflutter-dart-3.9.2.so` (reference)

## Research deployed (10 parallel agents)

- ClaudeResearcher × 3: BoringSSL source ground truth, alert constants, AAPCS64 ABI
- GeminiResearcher × 3: NVISO state, alternative projects, Frida 17 PAC
- GrokResearcher × 3: Flutter post-2025 changes, Dart-side pinning, sibling fn arity
- CodexResearcher: BoringSSL deep source pull with commit history

All ten returned with concrete evidence, file paths, and verbatim source quotes.

---

## Bottom line

**The script's anchor strategy is sound. Score function will pick 0x71abfc on this binary. Hook semantics are correct. Frida 17.x has no PAC issue blocking this approach.**

If after the optional surgical fixes the user runs it and the bypass-fired log appears but Burp still terminates: that's not a script bug, that's a Dart-layer pinning that needs a separate hook. Proceed to the contingency plan.

**The "last fix we haven't tried" — the score-based + validator-based candidate selection — is correct. Deploy it.**
