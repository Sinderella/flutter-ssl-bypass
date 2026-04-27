# INSIGHTS — flutter-ssl-bypass anchor chain

How `flutter-ssl-bypass.js`'s anchor chain works, why it was built that way, and what to do when codegen breaks. If you're just installing and running the agent, see [README.md](../README.md). If you're picking up the project for repair, start here.

---

## Why this exists

The classic public Flutter TLS-bypass scripts use **register-specific byte patterns** (`?9 ?? ?? ?0 29 ?? ?? 91` — "ADRP X9 / ADD X9" against the `"ssl_client"` string). When the compiler picks a different register or factors out repeated code into a shared stub, the pattern silently misses and the bypass quietly does nothing — which on a modern Flutter build with Dart-side pinning looks indistinguishable from "the bypass worked but something else is rejecting the cert."

This repo grew out of repairing one of those scripts against a new build. Each round of debugging revealed a stacked silent failure: empty range enumeration, JS Int32 signedness in opcode masks, single-page scan truncation, walkback into the wrong sibling function, stub detection running after a guard that always fails on stubs. The full iteration log is in [diff_report.md](diff_report.md).

The end product is `flutter-ssl-bypass.js` — a single-file bypass plus a small reusable anchor library, all of which fail loud on resolution failure and write a self-contained diagnostic dump for the next debug trip.

The framing matters: this is not a script that "tries harder" than the upstream — it's a script that fails differently. When a register-specific byte-pattern script misses, you see no error and a working-looking handshake that gets rejected. When this script misses, you see a diagnostic dump on the device pointing at the layer that broke (decoder self-test, range enumeration, string scan, xref resolution, validator scoring), so the next iteration is targeted rather than archaeological. The cost is more code; the payoff is repair triage in minutes instead of hours.

The wider point is that "fail loudly" is the property worth optimising for in compatibility-fragile reverse-engineering tooling. Anything that runs against a moving target — Flutter releases, BoringSSL bumps, Frida server upgrades — *will* break. The question is whether breakage produces a clear signal or a misleading one. Every layer of this agent is structured so that broken looks different from working: the decoder self-test catches a class of bugs synchronously at startup, the candidate validator refuses to commit on tied scores, the watchdogs distinguish "wrong function" from "right function, wrong layer," and the auto-diagnostic dump captures the exact state needed to start the next iteration. The methodology generalises beyond Flutter — anywhere you're hooking native code through structural anchors, the same architecture earns its keep.

---

## How it works (high-level)

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. Wait for libflutter.so to load, parse its ELF in-memory.     │
└────────────────────────┬────────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────────┐
│ 2. Decoder self-test                                            │
│    Asserts ADRP/ADD/BL/RET bit-math against known instruction   │
│    words BEFORE scanning anything. Catches Int32-signedness     │
│    regressions (Rule A in the script header).                   │
└────────────────────────┬────────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────────┐
│ 3. Anchor chain — find verify_cert_chain                        │
│                                                                 │
│    a. Scan .rodata for the ssl_x509.cc __FILE__ string.         │
│    b. Find every ADRP+ADD pair (any register) that loads it.    │
│    c. For each xref site:                                       │
│         - If it looks like a 4-insn stub                        │
│           (ADRP, ADD, MOV w0,#0x10, RET):                       │
│             → enumerate every BL caller of the stub             │
│             → walk each caller back to its prologue             │
│             → those are the candidates                          │
│         - Otherwise (direct xref into a real function):         │
│             → walk back to the prologue, accept if size ≥ 0x100 │
│    d. Score each candidate by structural signature:             │
│         - mov w?, #0x50 ; strb w?, [x2]                         │
│           (the *out_alert = SSL_AD_INTERNAL_ERROR write that's  │
│           distinctive to verify_cert_chain's 3-arg signature)   │
│         - function size in [0x100, 0x800]                       │
│         - body contains a BL back to the ssl_x509.cc stub       │
│         - prologue saves ≥ 2 callee-reg pairs                   │
│         Validator requires ≥ 2 of 4 signals; highest score wins │
└────────────────────────┬────────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────────┐
│ 4. Hook + redirect                                              │
│    - Interceptor.attach on verify_cert_chain, retval 0 → 1      │
│    - Resolve dart::bin::Socket::CreateConnect via the           │
│      "Socket_CreateConnect" string → RELRO pointer trick;       │
│      follow the 2nd BL inside it to GetSockAddr                 │
│    - Hook GetSockAddr to capture the outbound sockaddr; hook    │
│      libc socket() to rewrite IP:port to the Burp proxy.        │
│      MITM works even when the app ignores system DNS/proxy.     │
└────────────────────────┬────────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────────┐
│ 5. Watchdogs & auto-diagnostic                                  │
│    - WD-A (15s): TLS happened but verify_cert_chain never fired │
│      → wrong function hooked                                    │
│    - WD-B (20s): hook fired ≥5 times, all retval=1              │
│      → wrong sibling, OR Dart-side pinning above BoringSSL      │
│    - On any failure, dumps runtime ranges, string hits, xref    │
│      disassembly to a timestamped file on the device.           │
└─────────────────────────────────────────────────────────────────┘
```

The fallback chain (if Strategy 1 doesn't qualify a candidate): scan `"ssl_client"` directly with a function-size filter, then `"handshake.cc"` for `ssl_verify_peer_cert` (uses `Interceptor.replace` semantics — different convention).

The strategies are tried in order; first success wins:

1. **`ssl_x509.cc` stub-caller (PRIMARY)** — used on the current target. Scans `.rodata` for the `ssl_x509.cc` `__FILE__` string, walks the stub-caller chain, scores candidates by structural signature.
2. **`ssl_client` register-agnostic xref (FALLBACK)** — for builds where the old X9 pattern happens to still be present. Scans for ANY `ADRP+ADD` resolving to `"ssl_client"`, walks back, keeps the first candidate with size ≥ 0x100 (rejects the dispatcher).
3. **`handshake.cc` → `ssl_verify_peer_cert` (LAST-RESORT)** — different function, different semantics. Uses `Interceptor.replace` and returns 0 (`ssl_verify_ok`). Only fires if the cert-chain target couldn't be resolved. Same stub-caller logic as strategy 1.

Each strategy is independently testable and produces an explicit failure-mode message when it bottoms out, so the diagnostic dump tells you which strategy ran out of signals rather than just "no anchor found."

---

## Key insights from the repair

These are the same insights the JS file's preamble carries (`flutter-ssl-bypass.js` lines 44-99) — they're surfaced here so a reader doesn't have to read 1431 lines of agent code to recover the architectural "why."

### 1. The `ssl_client` / `ssl_server` ADRP+ADD pattern is NOT error reporting

It feeds `X509_STORE_CTX_set_default(ctx, purpose)` — the strings are X.509 verify-purpose identifiers, picked based on `ssl->server`. Confirmed against BoringSSL source (`ssl/ssl_x509.cc:234` as of 2026). That misreading is what made the old register-specific byte-pattern scripts seem to work for years: they were anchoring on the right function for the wrong reason.

The implication is uncomfortable: the public byte-pattern scripts were correct *behaviourally* for ~3 years on builds where the codegen happened to keep the two string loads inside `verify_cert_chain`'s body. The moment a compiler version consolidated those loads into the dispatcher (insight #2), the pattern still found exactly one xref — but the xref now points at the wrong function. That's why the failure mode is so confusing: the pattern still matches, the walkback still produces a function, the hook still installs cleanly. The only signal that anything is wrong is that the hook never fires during the handshake. That's invisible unless you trace `Interceptor` enter/leave events explicitly, which most TLS-bypass scripts do not.

### 2. Newer builds consolidate the two string loads

In the current target the compiler folded the per-purpose loads. On this sample only ONE ADRP+ADD to `"ssl_client"` survives, inside a 144-byte string DISPATCHER function (sequential `strcmp` against `"ssl_client"`, `"ssl_server"`, `"pkcs7"`, … — looks like an OBJ/name lookup, NOT the cert-verify function). The old anchor approach walks back from that xref and hooks the dispatcher → no bypass.

The dispatcher is an easy mistake to make because it's the *only* function the byte-pattern scan finds. With one xref and a working walkback, it looks correct from every angle except behaviour — the hook fires zero times during the handshake because nothing inside `ssl_x509.cc::session_verify_cert_chain` actually calls into the dispatcher. The fix isn't a smarter byte pattern; it's pivoting the anchor entirely to the `(__FILE__, __LINE__)` stub, which `verify_cert_chain` *does* call (insight #3).

### 3. `(__FILE__, __LINE__)` is factored into a shared stub

Newer BoringSSL/Flutter builds factor the per-assertion `(__FILE__, __LINE__)` load into a 16-byte shared stub:

```
ADRP xN, <page>        ; load page of ssl_x509.cc path
ADD  xN, xN, #<off>    ; fully-formed path pointer
MOV  w0, #0x10         ; line number (constant)
RET
```

Every `ssl_x509.cc` function that wants to report "I errored out here" does `BL` to this stub. Static tools (r2's `axt` on the string) find the xref inside the STUB, not inside the real caller function. Walking back from the xref falls into WHATEVER function happens to be placed before the stub in memory — garbage.

The stub itself is detectable by shape: a 4-instruction sequence of `ADRP / ADD / MOV w0,#0x10 / RET` at the xref site, with the `#0x10` immediate matching the line number BoringSSL hardcodes for that error. The compiler is consistent enough that this exact shape has been observed across multiple BoringSSL revisions. If a future compiler bumps the instruction count (e.g., a 5-insn stub that adds a branch-protection insn) or replaces `RET` with `BR x30`, the stub detector needs updating; that's the only piece of the agent that's tightly coupled to a specific codegen quirk. Everything downstream (BL enumeration, walkback, validator) operates on shape that's stable across BoringSSL rev sets.

### 4. The fix is stub-caller enumeration

Detect the stub shape at the xref, scan `.text` for `BL` instructions targeting the stub's entry, then walk each `BL` site back to its enclosing function. Those are the candidates. This is the single architectural move that makes the anchor chain robust to compiler reshuffles.

The "walk each BL site back to its enclosing function" step is itself non-trivial: a BL points at the stub, but the calling function's prologue might be 4 instructions back or 400 instructions back. The agent walks backward word-by-word looking for a recognisable prologue pattern (paired `STP` of callee-saved registers, or a `SUB sp, sp, #N` frame setup), bounded by a maximum walk distance to avoid drifting into the previous function. If the walkback hits the maximum without finding a prologue, the candidate is discarded — better to drop a real caller than to misidentify which function it belongs to.

### 5. Pick verify_cert_chain by signature: `strb w?, [x2]`

Among multiple stub callers in `ssl_x509.cc` (typically 3-4), the one that's actually `ssl_crypto_x509_session_verify_cert_chain` can be picked by function signature: it's the only one with

```
strb w?, [x2]   ; *out_alert = <SSL_AD_*>
```

near the top, because its C signature is

```c
bool verify_cert_chain(SSL_SESSION*, SSL_HANDSHAKE*, uint8_t* out_alert)
```

and its error paths set `out_alert = SSL_AD_INTERNAL_ERROR (0x50)`. Other siblings (`cache_objects`, `flush_cached_ca_names`, etc.) take 1-2 args and never touch `x2`. `_A_scoreAsVerifyCertChain()` uses this; the validator requires ≥ 2 of 4 structural signals before accepting a candidate.

The four signals the validator checks are:

1. **`mov w?, #0x50` ; `strb w?, [x2]`** near the function top — the `*out_alert = SSL_AD_INTERNAL_ERROR` write that requires a 3-arg signature.
2. **Function size in [0x100, 0x800] bytes** — sibling functions are smaller (`cache_objects` ~0x80) or larger (helper functions that touch the cert store directly).
3. **Body contains a `BL` back to the `ssl_x509.cc` stub** — `verify_cert_chain` reports errors from at least one error path; pure-success paths never reach the stub and would not match this signal.
4. **Prologue saves ≥ 2 callee-register pairs** — `verify_cert_chain` has enough local state (the cert chain, the SSL_HANDSHAKE pointer, the alert byte) that the compiler keeps multiple callee-saved registers live; the smaller siblings save 0-1 pair.

Tied scores are broken by function size (larger wins, on the rationale that the real `verify_cert_chain` does meaningful work). If two candidates pass the threshold and tie on score *and* size, the agent fails loudly — that's a "needs a sixth signal" condition, not a "guess and hope" condition.

### 6. JavaScript Int32 gotcha — `| 0` on opcode comparisons

JS bitwise ops return signed Int32. A literal like `0x90000000` in source is a POSITIVE Number (2,415,919,104), but `(insn & 0x9f000000)` returns -1,879,048,192 when the top bit is set. Strict equality `=== 0x90000000` FAILS silently — the first cut of the ADRP/BL decoders found zero matches because of this. Fix:

```js
if ((insn & MASK) === (VALUE | 0))   // force both sides to Int32
```

Any opcode comparison with bit 31 set needs this dance. This is documented as Rule A at the top of `flutter-ssl-bypass.js`'s anchor block, and the agent runs a decoder self-test at startup to catch any regression.

### 7. Frida `mod.enumerateRanges(filter)` is unreliable

`mod.enumerateRanges(filter)` returns an empty array on some Android + Frida combinations (confirmed on this target — A142 device, frida-server 17.x). `Process.enumerateRanges(filter)` works and can be intersected with the module window to achieve the same result. The agent uses that fallback throughout (`_A_getModuleSubranges`).

The bug is silent: a scan layer that calls `mod.enumerateRanges("r-x")` and gets `[]` proceeds normally, finds zero string hits, and returns "no candidate found." Without the self-test layer warning that the range enumeration produced zero ranges (when the module clearly has executable pages), you would read the result as "the string isn't in the binary" and start questioning whether you have the right Flutter version. The agent specifically asserts that `_A_getModuleSubranges(mod, "r-x")` returns at least one non-empty range before any string scan runs — that turns this whole class of failure into a single explicit error message at startup.

### Bonus: the 2nd-BL Dart trick

The Burp redirect side of the agent resolves `dart::bin::Socket::CreateConnect` through the `"Socket_CreateConnect"` string → RELRO pointer trick, then follows the **2nd BL** inside the resolved function to reach `dart::bin::SocketAddress::GetSockAddr`. Hooking `GetSockAddr` captures the outbound sockaddr; hooking libc `socket()` rewrites IP:port to the Burp proxy. This is what makes the MITM work even when the app ignores system DNS / proxy settings.

The reason this works structurally: `dart::bin::Socket::CreateConnect` is registered as a Dart natives entry — its address is exposed via a name table in `.data.rel.ro` (RELRO), looked up by string. From the function entry, the prologue + first arg-shuffle BL is the bookkeeping `Dart_NativeArguments` boilerplate; the **second BL** is the actual `SocketAddress::GetSockAddr(...)` call that resolves the host the app intends to connect to. The "2nd BL" rule is brittle in principle (a refactor that adds a helper call between them would shift the index) but has been stable across the Dart VM revisions tested. If a future Dart bumps the index, the same diagnostic dump that identifies anchor failures would surface this — `[diag] Socket_CreateConnect → CreateConnect @ 0x… BL[0..3]: 0x…, 0x…, 0x…, 0x…` — and one register-watching iteration finds the new index.

### Decoder self-test as documentation

Insight 6 is the JS Int32 gotcha; insight 7 is the Frida range-enumeration gotcha. Both are silent failure modes. The agent runs a decoder self-test at startup that asserts ADRP/ADD/BL/RET bit-math against known-good instruction words BEFORE any real scanning runs. If the self-test fails, the agent refuses to proceed and prints the exact opcode that didn't decode — turning a silent class of bugs into a loud one. The self-test is documented as the first thing that runs in the diagram above (stage 2) because it earns its place: every JS-bitwise regression and every Frida-API breakage shows up here first, not deep inside an anchor scan.

---

## Methodology lessons

If you take nothing else from this repo:

1. **Silent wrong answers are the default failure mode in RE/Frida work.** A scan that returns 0 hits looks identical to "no hits exist." A decoder with a bit-math bug looks identical to a clean module. A walkback into the wrong sibling looks identical to "the right function returns the wrong value." Bake validation into every layer — every scan asserts a non-zero count, every decoder runs against known-good words at startup, every candidate function is structurally validated before it gets hooked. The cost is a few extra `_assert(...)` calls; the payoff is that "broken" reliably looks different from "working but useless."

2. **JS opcode comparisons need `| 0` whenever bit 31 is set.** `(insn & 0x9f000000) === 0x90000000` is silently always-false because JS bitwise returns Int32 and `0x90000000` is a positive Number. Forces a generation of resolvers to fail invisibly. Use `(VALUE | 0)` on both sides. Hard-code this as a Rule A in any project header so the next person who writes a decoder sees the warning before they shoot themselves in the foot.

3. **`mod.enumerateRanges(filter)` is unreliable on some Android+Frida combos.** Use `Process.enumerateRanges(filter)` and intersect with the module window. The bug surfaces only on certain device + Frida-server combinations and only on the module-scoped variant — `Process.enumerateRanges` itself is reliable. Wrap the helper once and use it everywhere; never call the module-scoped form directly.

4. **Order of operations in guard chains matters.** The Iter-5 fix was nothing more than moving stub detection BEFORE the prologue-walkback guard — but that one guard ordering was the difference between "always succeeds" and "always silently falls through to a weaker strategy." When a chain has both a "is this a stub?" and a "is this a real function with size ≥ N?" check, the stub check has to run first or the size guard rejects every stub before you get the chance to enumerate its callers.

5. **Scan ALL executable subranges, not just the biggest.** Some libflutter builds split BoringSSL/libcxx/icu into smaller r-x sections separated by tiny rwx pages; scanning only the biggest .text region misses them entirely. The seductive optimization is "find the largest r-x range and scan that"; the correct implementation is "find every r-x range that intersects the module window and scan all of them, deduplicating hits."

6. **Diagnostic dumps are the difference between a 30-minute repair and a 3-hour one.** When the agent fails, it writes a timestamped file on the device containing: every executable range Frida saw, every string hit, the full disassembly around every xref site, and the score breakdown for every candidate the validator rejected. The next iteration starts from that file rather than from "the bypass didn't work, let me re-instrument and re-run." Build this in early; it pays for itself on iteration 2.

---

## Operational notes — watchdogs and failure-mode pivots

Two watchdogs run after the hook is attached, and both produce specific actionable signals rather than generic "something is wrong":

- **WD-A (15s)** — TLS happened but `verify_cert_chain` never fired. This means the wrong function was hooked. The fix is in the candidate-scoring layer: re-check the `[anchor] ssl_x509.cc candidates:` log to see which candidate the validator picked, and either tighten the scorer or add a sixth structural signal that distinguishes the real one. The auto-diag dump shows every candidate's score breakdown so you can see exactly which signal misfired.

- **WD-B (20s)** — the hook fired ≥ 5 times and every call returned 1 (the bypass override) but Burp still sees handshake termination. This is the classic "right BoringSSL function, but Dart-side pinning above it" scenario. The agent's bypass is doing its job at the BoringSSL layer; something higher up (Dart `SecurityContext.badCertificateCallback`, the `http_certificate_pinning` plugin, a hand-rolled `basic_utils` SHA-256 fingerprint check) is rejecting independently. [FAILURE-MODES.md §Layer 6](FAILURE-MODES.md) walks through the contingency.

The two watchdogs together cover the two failure modes that confused early iterations: "wrong function" (WD-A) and "right function, wrong layer" (WD-B). Anything else (script never starts, decoder self-test fails, no string hits in `.rodata`) surfaces synchronously at startup with a loud error rather than waiting on a timer.

---

## Repair archive

These are the deep-dive layers behind this writeup. Click through when you need the evidence rather than the summary.

- **[diff_report.md](diff_report.md)** — full 5-iteration repair log: what broke each round, what fixed it. Read this first if you're picking up the script for repair.
- **[FAILURE-MODES.md](FAILURE-MODES.md)** — pre-deployment checklist plus a 7-layer failure taxonomy and the indicator chain to walk during a run when something goes wrong.
- **[REVIEW.md](REVIEW.md)** — evidence-backed verification that the anchor strategy is correct on the target binary (BoringSSL line numbers, AAPCS64 refs, byte sequences cross-checked against NVISO's patterns).
- **[fingerprint-dart-3.10.9.txt](fingerprint-dart-3.10.9.txt)** — `fingerprint_so.py` output for the tested-confirmed build (Feb 2026, Dart 3.10.9).
- **[fingerprint-dart-3.9.2.txt](fingerprint-dart-3.9.2.txt)** — `fingerprint_so.py` output for the earlier reference build (Aug 2025, Dart 3.9.2).

---

## The TS port

The TypeScript source under `src/` is a strict-parity port of `flutter-ssl-bypass.js`. The bundled artifact users download from Releases is `dist/flutter-ssl-bypass.js`, generated by `bun run build`. The port preserves every hook site, log line, and return override of the JS source — and adds compile-time checking on `NativePointer` arithmetic, `Memory.read*` arity, and Frida 17 API usage so a codegen-time bug surfaces during `bun run typecheck` rather than mid-handshake on a real device.

End users running the prebuilt agent never need to touch the TS.

The port's strict-parity contract says: same hooks fire in the same order, the same log lines appear with the same wording, and the same return overrides take effect. There is no "improved" version of the agent in TypeScript form — improvements would defeat the parity check that's in CI. When the next codegen-driven repair is needed, the TS source gets updated, the parity baselines under `tests/parity/` are re-captured deliberately as part of the repair commit, and the new build inherits the same compile-time guard against the next round of `NativePointer` arithmetic / arity bugs. The TypeScript layer is a *durability* layer, not a *capability* layer.

This separation is also why the published artifact name (`flutter-ssl-bypass.js`) doesn't track the source language: users download the bundle, run it through Frida, and get the same hook surface they'd get from the JS upstream. The TS-vs-JS distinction is purely an internal maintenance choice.

---

## A note on the iOS path

The agent ships an iOS code path inherited from the upstream `hackcatml/frida-flutterproxy` script — Mach-O parser, `__DATA __const` walking, the original `handshake.cc` pattern scan. It is **explicitly untested** on recent Flutter iOS builds. If it breaks, the same stub-caller logic from the Android path is the right fix; the structural anchors (`(__FILE__, __LINE__)` stubs, three-arg signature with `out_alert`) are BoringSSL invariants and translate directly. Until someone exercises the iOS path against a current build, treat it as a starting point rather than a ready-to-use surface.

The README's tested-against table reflects this honestly: only Android arm64 is listed, with an explicit "Won't work" row noting non-arm64 ABIs. The iOS path lives in the source for archaeology and easy revival rather than as a supported surface; the parity baselines under `tests/parity/` cover only the Android JSON output. If someone wants to revive the iOS path, the cleanest move is a separate phase that adds an iOS parity baseline and brings the iOS code under the same structural-anchor discipline as the Android side.
