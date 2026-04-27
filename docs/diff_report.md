# Flutter Frida script repair — review document

**Binaries compared:**
- `libflutter-dart-3.9.2.so` — Dart 3.9.2 (stable, 2025-08-27), engine `fec78c0d…`
- `libflutter-dart-3.10.9.so` — Dart 3.10.9 (stable, 2026-02-03), engine `ea7cdbc6…`

Throughout this document, **"old"** and **"new"** refer to those two libflutter builds. The repair was triggered by porting the bypass from the older build to the newer one — the old script's hardcoded `ADRP X9 / ADD X9` pattern stopped matching when the compiler produced different codegen in the newer build.

Last update: 2026-04-27 (Iter 5: stub-no-prologue + multi-range fixes).

---

## TL;DR

The original Frida script's SSL pinning bypass died on the new `libflutter.so` because:

1. It used a **register-specific** byte pattern (`?9 ?? ?? ?0 29 ?? ?? 91`) for `ADRP X9 / ADD X9` against the `"ssl_client"` string. The new build no longer emits that pair in `verify_cert_chain` — only an `X1` xref to `"ssl_client"` survives, and it points at a 144-byte string-dispatcher function, not the cert-verify function.
2. Newer BoringSSL/Flutter builds factor `__FILE__` (`ssl_x509.cc`, `handshake.cc`) into a **16-byte shared stub** (`adrp / add / mov w0,#0x10 / ret`). Static-analysis tools find the xref inside the stub; walking back from the xref lands on whatever function is placed before the stub in memory — wrong answer.

The repaired script (`flutter-ssl-bypass.js`) replaces the broken anchor with a **stub-caller chain**: find the `ssl_x509.cc` path string, detect the stub at the xref site, enumerate `BL` callers of the stub, walk each back to its prologue, and pick the candidate that matches `ssl_crypto_x509_session_verify_cert_chain`'s structural signature (writes to `[x2]` = `*out_alert`, has a sane prologue, calls back into the stub).

The script also includes a self-test, ground-truth assertions, a multi-signal candidate validator, and an **auto-diagnostic dump** that fires on resolution failure or suspicious runtime behavior — designed so the next debugging trip starts with concrete data, not "rerun a separate diag script."

---

## Files delivered

| File | Purpose |
|---|---|
| `flutter-ssl-bypass.js` | The bypass script — drop-in single file, no external `require`. Lines 1-160 are a self-contained header with usage, key insights, generic rules, anchor-chain explanation, and debugging guidance. |
| `tools/diag.js` | Standalone diagnostic dumper for fresh-binary triage. Run before writing a new resolver. Writes runtime ranges, string hits, ADRP+ADD xref disasm to `/data/local/tmp/flutter-diag.txt`. |
| `tools/frida-anchors.js` | Reusable anchor-resolution library (the bypass script inlines its functions under the `_A_*` prefix). Kept for reference. |
| `docs/fingerprint-dart-3.10.9.txt`, `docs/fingerprint-dart-3.9.2.txt` | Output of `fingerprint_so.py` for the two libflutter builds compared in this document — section sizes, exports, candidate anchor strings. |
| `docs/diff_report.md` | This document. |

Run:

```
frida -U -f com.example.flutterapp -l flutter-ssl-bypass.js --no-pause
```

---

## Iteration journey

This took four rounds. Each round revealed a stacked silent failure that masked the next one. Documented because the same failure modes are likely to bite the next person.

| # | What happened | Root cause | Caught by (in final script) |
|---|---|---|---|
| 1 | "BOTH strategies failed — SSL pinning bypass UNAVAILABLE" — script returned null with no useful log | `mod.enumerateRanges(filter)` returns empty on this Android+Frida combo. Every scan's "text range" was effectively zero-sized. | `_A_getModuleSubranges` (uses `Process.enumerateRanges` intersected with module window) |
| 2 | After fixing range enumeration: scan ran to completion, found 0 ADRP+ADD xrefs to known-present strings | JS bitwise gotcha. `(insn & 0x9f000000)` returns signed Int32 `-1879048192`; `0x90000000` literal is positive `2415919104`; strict-equality `===` is always false. Same bug on BL (`0x94000000`). | `_A_selfTest` runs at script start; `(VALUE \| 0)` rule documented in header as Rule A |
| 3 | Picked candidate `0x71a9a4` (a sibling, not verify_cert_chain). Hook fired once with `retval=1`; Burp still saw handshake termination. | Two things: (a) `try { readU32 } catch { break }` in scan loops silently truncated when one page was unreadable, so the stub xref at `0xa19b18` was never reached; (b) candidate selection was just "biggest function" with no structural validation. | Page-skip-on-error (Rule B in header); `_A_validateVerifyCertChainCandidate` requires ≥ 2 of 4 structural signals |
| 4 | After scan fix: 4 candidates surface. Need to disambiguate which is the real verify_cert_chain. | Sibling functions in `ssl_x509.cc` all reference the file path the same way. Need a feature unique to verify_cert_chain. | `_A_scoreAsVerifyCertChain` matches `strb w?, [x2]` with `mov w?, #0x50` nearby — the `*out_alert = SSL_AD_INTERNAL_ERROR (0x50)` write that's distinctive to the 3-arg verify_cert_chain. |
| 5 | Re-run on the target binary returned the broken candidate `0x745e9e99a4` (signals=1, score=0) and "BOTH strategies failed". Stub xref at `0x745ece8b18` was correctly detected (`isStub=true`) but logged "(no prologue within 0x2000)" — its BL callers were never enumerated. | Two compounding bugs: (a) the stub branch was guarded by `if (!prologue) continue` BEFORE the `isStubHere` check — but stubs sit at code-page boundaries with no preceding function, so walkback legitimately fails, and `continue` skipped the stub-caller path that was the whole point of detecting the stub; (b) `_A_findAdrpAddXrefs` and `_A_findBlCallers` only scanned the SINGLE largest r-x range (the 7 MB main `.text`), but on this binary the BoringSSL stub + ssl_x509.cc functions are placed in tiny rwx pages between the secondary r-x sections — completely outside the biggest-range scan window. The first round only found 2 xrefs by accident, because `Process.enumerateRanges("r-x")` returned empty during the cold-start call and the scanner fell through to "scan whole module"; on subsequent calls (e.g. the diag re-scan reporting `adrp+add xrefs: 0`) the scan was correctly bounded and silently returned nothing. | (a) Stub branch now runs UNCONDITIONALLY when `_A_isStubAtAdrp(xref)` is true — walkback isn't needed, the xref IS the stub entry. Same fix applied to `resolveVerifyPeerCert`. (b) New `_A_getAllTextRanges` returns ALL executable subranges; both scanners iterate over every one. Verified statically: 4 BL callers of stub at offset `0xa19b18` walk back to prologues at `0x71a36c`, `0x71ac00`, `0x71ae74` (deduped); the `0x71ac00` candidate has `mov w8, 0x50; strb w8, [x2]` at +0x8 → score=30, signals=3, beats the others. |

This is the methodology lesson: **silent wrong answers are the default failure mode** in RE/Frida work. A scan that returns 0 hits looks identical to "no hits exist." A decoder with a bit-math bug looks identical to a clean module. Without active validation, every layer can be wrong and you'll only find out when the bypass quietly doesn't fire on a TLS request.

Iter-5 corollary: the iteration order of guards matters as much as the guards themselves. The `_A_walkToPrologue → continue` guard was correct for direct-xref handling but wrong for stubs; placing it before the `isStubHere` branch silently disabled the entire stub-caller chain on any binary where the stub happened to land at a page boundary. **Always run stub detection BEFORE prologue walkback, not after.**

---

## Final architecture of `flutter-ssl-bypass.js`

```
                         ┌────────────────────┐
                         │  init()            │
                         └─────────┬──────────┘
                                   │
                ┌──────────────────┴───────────────────┐
                │  _A_selfTest()                       │   ← Catches Rule A regressions
                │  Asserts decoder bit-math against    │     before scanning anything
                │  known ADRP/ADD/BL/RET words         │
                └──────────────────┬───────────────────┘
                                   │
                ┌──────────────────┴───────────────────┐
                │  resolveVerifyCertChain(mod)         │
                │  1. find ssl_x509.cc string          │
                │     ├── _A_assertRange (≥1 hit)      │   ← Diagnostic, not gate
                │  2. ADRP+ADD xref scan               │
                │     ├── _A_assertRange (≥1 xref)     │
                │  3. for each xref:                   │
                │     ├── _A_isStubAtAdrp?             │   ← Stub detection
                │     │   ├── true: BL-caller scan     │
                │     │   │       ├── _A_assertRange   │
                │     │   │       │   (≥1 caller)      │
                │     │   │       └── candidates.push  │
                │     │   └── false: walk-back, push   │
                │  4. score each candidate             │   ← Real correctness gate
                │     ├── _A_scoreAsVerifyCertChain    │     uses structural signals
                │     │   (strb [x2] + mov w?,#0x50)   │     (codegen-stable)
                │     └── _A_validateVerifyCertChainCandidate
                │         (≥2 of 4 signals)            │
                │  5. return highest-scoring qualified │
                └──────────────────┬───────────────────┘
                                   │
                          ┌────────┴────────┐
                          │ resolved?       │
                          └───┬───────┬─────┘
                              │ yes   │ no → resolveVerifyPeerCert (handshake.cc)
                              │       │     │ no → _A_writeAutoDiag(); abort SSL bypass
                              ▼       ▼     ▼
                          ┌────────────────────┐
                          │  Hook + watchdogs  │
                          │  ── 15s WD: TLS    │
                          │     happened but   │
                          │     hook silent →  │
                          │     auto-diag      │
                          │  ── 20s WD: hook   │
                          │     fires only with│
                          │     retval=1 →     │
                          │     auto-diag      │
                          └────────────────────┘
```

**Key invariants:**

- `_A_assertRange` is **diagnostic** — it warns, never aborts. Real gate is the candidate validator.
- `_A_validateVerifyCertChainCandidate` requires ≥ 2 of 4 signals: `strb [x2]`, function size in [0x100, 0x800], BL to ssl_x509.cc stub in body, ≥ 2 STPs in prologue. Each signal is independently codegen-stable.
- `_A_writeAutoDiag` is **single-shot per session** (guarded by `_A_diagState.written`) and writes a timestamped file with hook stats, candidate dump, fresh range/string/xref scan. User pulls with `adb pull <path>` from the logged success message.

---

## The verify_cert_chain disambiguation (why `0x71abfc` and not `0x71a9a4`)

In `libflutter-dart-3.10.9.so`, the `ssl_x509.cc` stub at file offset `0xa19b18` has 4 BL callers across 3 distinct enclosing functions:

| Prologue addr | Approx size | Args (heuristic) | Distinctive body bytes | Likely identity |
|---|---|---|---|---|
| `0x71a36c` | ~464 | multi (uses `x1`) | calls `0xa05c84`, then `cbz x1` | sibling — possibly `auto_chain_if_needed` |
| `0x71a9a4` | ~552 | 1 (`x0` only, saved to `x19`) | `ldr x24, [x0, 0x88]` | sibling — likely `cache_objects` |
| **`0x71abfc`** | **~750** | **3 (`x0,x1,x2`)** | **`mov w8, 0x50; strb w8, [x2]`** | **`ssl_crypto_x509_session_verify_cert_chain`** |
| `0x71ae74` | ~? | 1 | `ldr x21, [x0]; ldrb w8, [x21, 0x84]` | sibling — possibly `flush_cached_ca_names` |

Why `0x71abfc` is the right one: BoringSSL's signature is

```cpp
bool ssl_crypto_x509_session_verify_cert_chain(SSL_SESSION *session,
                                                SSL_HANDSHAKE *hs,
                                                uint8_t *out_alert);
```

The 3rd arg `out_alert` is a `uint8_t*`. On error paths the function does `*out_alert = SSL_AD_INTERNAL_ERROR;` — that's a `mov w?, #0x50` followed by `strb w?, [x2]` (because `x2` is the 3rd arg under AAPCS64). None of the sibling functions take 3 args, so none of them write to `[x2]` near the top.

`_A_scoreAsVerifyCertChain` walks the first 0x100 bytes, awards +10 for any `strb w?, [x2]` and an additional +20 if a `mov w?, #0x50` was the most recent immediate. The winning candidate gets `score=30`, others get 0.

---

## Generic Rules (encoded in script header, lines ~166-188)

These three rules cost a round each on the way to the final script. They're now documented at the top of the script so the next person doesn't have to learn them by losing a debug cycle.

**Rule A** — JS bitwise ops return signed Int32. Any opcode comparison with a 32-bit literal whose bit 31 is set must normalize:

```js
if ((insn & 0x9f000000) === (0x90000000 | 0))   // GOOD
if ((insn & 0x9f000000) === 0x90000000)         // SILENTLY ALWAYS FALSE
```

**Rule B** — every `readU32()` (or any pointer read) inside a scan loop must skip the page on error, never `break`:

```js
try { insn = p.readU32(); } catch (e) {
    p = p.and(pageMask).add(0x1000);            // GOOD: skip to next page
    continue;
}
// `break` here silently truncates the whole scan if any single page is unreadable.
```

**Rule C** — `Module.enumerateRanges(filter)` returns empty on some Android+Frida combos. Always go through a helper that falls back to `Process.enumerateRanges(filter)` intersected with the module window. (`_A_getModuleSubranges` does this.)

The self-test at script start exercises Rule A and the helper covers Rule C; Rule B is enforced by inspection (every scan loop in the file has page-skip).

---

## Ground-truth assertions (deliberately loose)

```js
var GROUND_TRUTH = {
    ssl_x509_cc_string_hits:  { min: 1 },   // __FILE__ literal must exist
    ssl_x509_cc_xrefs:        { min: 1 },   // at least one ADRP+ADD reference
    ssl_x509_cc_stub_callers: { min: 1 },   // if a stub exists, someone calls it
};
```

No `max` bounds. All `min = 1`. These trip ONLY when something is broken at the decoder layer (which is what we want to catch); they don't trip on legitimate codegen drift in future Flutter releases. The real "did we resolve correctly" gate is the structural validator.

If a future Flutter build genuinely strips assertion file paths, `ssl_x509_cc_string_hits` will be 0, the warning fires, and the fallback strategies (ssl_client direct xref, then handshake.cc) take over. The script doesn't abort.

---

## Auto-diagnostic dumps

Triggered on:

| Trigger | When |
|---|---|
| Self-test failure | Decoder bit-math broken — written before throw |
| Resolution failure | Both strategy 1 and strategy 2 returned null |
| Watchdog A (15s) | Socket overwrites > 0 (TLS happened) but hook ENTER count = 0 → wrong function hooked |
| Watchdog B (20s) | Hook fired ≥ 5 times, all retval=1, none = 0 → wrong sibling OR Dart-side pinning |

Dump file: `/data/local/tmp/flutter-bypass-diag-<timestamp>.txt` (falls back to `/sdcard` then app `files/` dir).

Contents:

- Hook state: ENTER count, retval distribution, socket-overwrite count, resolved address + via
- Candidates list from the resolution attempt
- Fresh `Process.enumerateRanges` view of the module
- Fresh string + ADRP+ADD xref scan for `ssl_x509.cc`, `handshake.cc`, `ssl_client`, `ssl_server` with disasm context

Single-shot per session. The first suspicious signal wins; no spam.

---

## Sample expected runtime output

Healthy run on the current target:

```
[*] libflutter.so loaded!
[*] libflutter.so base: 0x...
[self-test] decoder bit-math OK (ADRP, ADD, BL, RET)
[*] package name: com.example.flutterapp
[anchor] ssl_x509.cc string hits: 1
[anchor]   0x...0ede -> 2 ADRP+ADD xref(s)
[anchor]     xref @ 0x...aaf8  isStub=false
[anchor]     xref @ 0x...9b18  isStub=true
[anchor]       stub -> 4 BL caller(s)
[anchor] ssl_x509.cc candidates:
  0x...71a36c  size=0x1d0  score=0   signals=2  via=ssl_x509.cc-stub    [-no strb[x2] +size ok -no stub BL +prologue-stp(3)]
  0x...71a9a4  size=0x228  score=0   signals=2  via=ssl_x509.cc-direct  [-no strb[x2] +size ok -no stub BL +prologue-stp(3)]
  0x...71abfc  size=0x...  score=30  signals=4  via=ssl_x509.cc-stub    [+strb[x2](score=30) +size ok +bl(stub) +prologue-stp(3)]
  0x...71ae74  size=0x...  score=0   signals=2  via=ssl_x509.cc-stub    [-no strb[x2] +size ok +bl(stub) +prologue-stp(2)]
[*] verify_cert_chain resolved via ssl_x509.cc-stub @ 0x...71abfc (size=0x...)
... (Socket_CreateConnect / GetSockAddr resolve cleanly) ...
[*] Hook GetSockAddr function
[*] Hook verify_cert_chain function (attach + retval.replace(1))
[*] Overwrite sockaddr as our burp proxy ip and port --> 127.0.0.1:8080
[trace] verify_cert_chain ENTER  arg0=... arg1=... arg2=...
[trace] verify_cert_chain LEAVE  retval=0
[*] verify cert bypass (return 0 -> 1)
```

If the trace shows `retval=1` repeatedly without any `retval=0`, watchdog B fires at 20s and dumps diag — that signals either a sibling mis-hook or Dart-side pinning, and the next investigation pivots accordingly.

---

## Open questions for review

1. **Score threshold**. `_A_scoreAsVerifyCertChain` uses `+30` for `mov #0x50; strb [x2]` and `+10` for any `strb [x2]`. Is `0x50` (SSL_AD_INTERNAL_ERROR) the only alert constant we should boost? `0x2a` (SSL_AD_BAD_CERTIFICATE), `0x2b` (UNSUPPORTED_CERTIFICATE), `0x2e` (CERTIFICATE_UNKNOWN) are also plausible. Probably worth boosting any 0x20-0x60 range as a softer signal.

2. **`_A_walkToPrologue` 0x2000 cap**. Functions that combine inlined helpers can exceed 0x2000 bytes between an internal xref and the actual prologue. Hasn't bitten us yet on this target, but a future Flutter build with heavier LTO might.

3. **Watchdog B threshold (5 ENTERs all retval=1)**. Is "5" the right cutoff? On apps that establish many connections quickly it might fire too aggressively; on slow apps it might never reach 5. Could swap to "30 seconds elapsed since first ENTER and zero retval=0 seen" to make it event-driven rather than count-based.

4. **iOS path** is unchanged from the original script — still uses the X2-register byte pattern against `handshake.cc`. Untested on a current iOS Flutter build. If the user needs iOS, run the same diag-first methodology against `Flutter.framework/Flutter`.

5. **No Dart-side pinning hook**. If the Burp handshake termination persists after `[*] verify cert bypass (return 0 -> 1)` actually fires, the next iteration should hook Dart's `SecurityContext.badCertificateCallback` or the `HandshakeException` path — not at BoringSSL level.

---

## References

- Original NVISO discussion of this exact symptom: [issue #51](https://github.com/NVISOsecurity/disable-flutter-tls-verification/issues/51) — community pivoted from `ssl_verify_peer_cert` to `ssl_crypto_x509_session_verify_cert_chain` with `retval.replace(0x1)`.
- BoringSSL source: [ssl/ssl_x509.cc](https://boringssl.googlesource.com/boringssl/+/refs/heads/main/ssl/ssl_x509.cc) (function at line 201), [ssl/handshake.cc](https://boringssl.googlesource.com/boringssl/+/refs/heads/main/ssl/handshake.cc) (`ssl_verify_peer_cert` at line 268).
- `flutter-frida-repair` Claude skill (in `~/.claude/skills/flutter-frida-repair/`) has the underlying methodology.
