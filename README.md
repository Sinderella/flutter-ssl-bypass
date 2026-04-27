# flutter-ssl-bypass

A resilient Frida-based SSL pinning bypass for **Android arm64 Flutter apps**, plus the static-analysis methodology that makes it survive Flutter version bumps.

The script targets `ssl_crypto_x509_session_verify_cert_chain` inside `libflutter.so` and forces it to return success — same goal as the long-standing community scripts ([hackcatml/frida-flutterproxy](https://github.com/hackcatml/frida-flutterproxy) — the direct upstream of this work — and [NVISO disable-flutter-tls-verification](https://github.com/NVISOsecurity/disable-flutter-tls-verification)), but with an anchor strategy designed to fail loudly rather than silently when a future Flutter build moves things around.

> **Authorized testing only.** This is for security research, CTFs, your own apps, and authorized engagements. Don't point it at apps you don't have permission to analyse.

---

## Why this exists

The classic public Flutter TLS-bypass scripts use **register-specific byte patterns** (`?9 ?? ?? ?0 29 ?? ?? 91` — "ADRP X9 / ADD X9" against the `"ssl_client"` string). When the compiler picks a different register or factors out repeated code into a shared stub, the pattern silently misses and the bypass quietly does nothing — which on a modern Flutter build with Dart-side pinning looks indistinguishable from "the bypass worked but something else is rejecting the cert."

This repo grew out of repairing one of those scripts against a new build. Each round of debugging revealed a stacked silent failure: empty range enumeration, JS Int32 signedness in opcode masks, single-page scan truncation, walkback into the wrong sibling function, stub detection running after a guard that always fails on stubs. The full iteration log is in [docs/diff_report.md](docs/diff_report.md).

The end product is `flutter-ssl-bypass.js` — a single-file bypass plus a small reusable anchor library, all of which fail loud on resolution failure and write a self-contained diagnostic dump for the next debug trip.

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

---

## Compatibility

| | Dart VM | Flutter (approx.) | Engine SHA prefix | Status |
|---|---|---|---|---|
| **Tested — confirmed working** | 3.10.9 (stable, 2026-02-03) | ~3.36 / 3.38 era | `ea7cdbc6…` | ✅ Bypass resolves and hooks `ssl_crypto_x509_session_verify_cert_chain` correctly. Iter-5 fixes were validated against this build. |
| **Tested — earlier reference build** | 3.9.2 (stable, 2025-08-27) | ~3.32 era | `fec78c0d…` | ✅ The original script (now retired) worked on this build via the legacy `ADRP X9 / ADD X9` byte pattern. The new anchor-chain strategy was validated to also resolve correctly here. |
| **Expected to work** | any Dart 3.x with current BoringSSL (≥ 2024-ish) | Flutter 3.10+ | n/a | The anchor strategy keys off structural invariants that have been stable in BoringSSL `ssl_x509.cc` for 2+ years (3-arg signature, `*out_alert = SSL_AD_INTERNAL_ERROR (0x50)`, the file:line stub shape `ADRP+ADD+MOV w0,#0x10+RET`). Anything in this range *should* resolve; if it doesn't, the auto-diag dump will tell you which layer broke. |
| **Won't work** | — | — | — | Non-arm64 ABIs (`armeabi-v7a`, `x86_64`); builds where `ssl_crypto_x509_session_verify_cert_chain` has been fully inlined (theoretically possible under aggressive LTO; not observed in any current Flutter build); apps that link `libcronet.so` instead of doing TLS in `libflutter.so`. |

If you run against a build outside the tested range and it works (or doesn't), the auto-diag dump from a failed run is the easiest way to tell what to update — see the "Repairing for a new Flutter version" section below.

---

## Quick start

```bash
# Edit the IP/port at the top of init() in flutter-ssl-bypass.js first.
# BURP_PROXY_IP = "192.168.x.x"
# BURP_PROXY_PORT = 8080

frida -U -f <package.name> -l flutter-ssl-bypass.js --no-pause
```

Then, in Burp / your proxy:
- Listen on the IP/port set above.
- Make sure your CA is installed as a **system** CA on the device (`/system/etc/security/cacerts/`), not just user.

A healthy run looks like:

```
[self-test] decoder bit-math OK (ADRP, ADD, BL, RET)
[anchor] ssl_x509.cc string hits: 1
[anchor]   0x...0ede -> 2 ADRP+ADD xref(s)
[anchor]     xref @ 0x...9b18  isStub=true
[anchor]       stub -> 4 BL caller(s)
[anchor] ssl_x509.cc candidates:
  ... 0x...ac00 ... score=30 signals=3 ... +strb[x2](score=30) +size ok +bl(stub) ...
[*] verify_cert_chain resolved via ssl_x509.cc-stub @ 0x...ac00
[*] Hook verify_cert_chain function (attach + retval.replace(1))
[trace] verify_cert_chain ENTER ...
[trace] verify_cert_chain LEAVE  retval=0
[*] verify cert bypass (return 0 -> 1)
```

If the bypass fires but Burp still sees handshake termination → that's almost certainly **Dart-side pinning** sitting on top of BoringSSL (a documented pattern: BoringSSL is allowed to validate, then a Dart-FFI / Java-bridge SHA-256 fingerprint check rejects independently). See [docs/FAILURE-MODES.md §Layer 6](docs/FAILURE-MODES.md) — pivot to jadx and hook the Dart-side check.

---

## Repo layout

```
.
├── README.md                  ← you are here
├── flutter-ssl-bypass.js      ← the bypass (drop-in single file, no external require)
├── tools/
│   ├── frida-anchors.js       ← reusable anchor-resolution library
│   │                            (flutter-ssl-bypass.js inlines its functions
│   │                             under the _A_* prefix; this copy is for
│   │                             reference and for use in other Frida scripts)
│   └── diag.js                ← standalone diagnostic dumper for fresh-binary
│                                triage; run before writing a new resolver to
│                                capture ranges, string hits, xref disasm
├── .gitignore                 ← excludes *.so by default (see "Binaries" below)
└── docs/
    ├── diff_report.md       ← full repair iteration journey (5 rounds, what
    │                          broke, what fixed it). Read this if you're
    │                          repairing the script for a new Flutter version.
    ├── FAILURE-MODES.md     ← pre-deployment checklist, 7-layer failure
    │                          taxonomy, indicator chain to walk during a run
    ├── REVIEW.md            ← evidence-backed verification that the anchor
    │                          strategy is correct on the target binary
    │                          (BoringSSL line numbers, AAPCS64 refs, byte
    │                          sequences confirmed by NVISO patterns, etc.)
    ├── fingerprint-dart-3.10.9.txt  ← fingerprint_so.py output for the
    │                                   tested-confirmed build (Feb 2026)
    └── fingerprint-dart-3.9.2.txt   ← fingerprint_so.py output for the
                                        earlier reference build (Aug 2025)
```

### Binaries

The two `libflutter.so` files used during this repair came from real third-party Android apps and are **not redistributable**. They're `.gitignore`d. To reproduce the analysis end-to-end, drop your own arm64 `libflutter.so` into the working directory.

To extract one from an APK:

```bash
unzip -p your-app.apk lib/arm64-v8a/libflutter.so > libflutter.so
```

---

## When to use this vs. when not to

**Use this when:**
- The target is an Android arm64 Flutter app.
- Public byte-pattern scripts no longer find the function on a new build.
- You want to know *why* a bypass attempt failed, not just that it did.

**Don't use this when:**
- The target is `armeabi-v7a` or `x86_64` Flutter — the decoder is arm64-only.
- The app does Dart-side or Java-bridge pinning above BoringSSL — the BoringSSL-level bypass will fire perfectly and the app will still reject. You need a different hook (Dart `SecurityContext.badCertificateCallback`, `http_certificate_pinning` plugin, `basic_utils` SHA-256 fingerprint). [docs/FAILURE-MODES.md](docs/FAILURE-MODES.md) §Layer 6 has the contingency plan.
- The app links `libcronet.so` — TLS happens there, not in libflutter.so.

---

## Repairing for a new Flutter version

When the next Flutter version inevitably moves something:

1. Run `tools/diag.js` against the new binary first — captures string hits, range map, xref disasm, all in one file. Don't edit `flutter-ssl-bypass.js` until you've seen this.
2. Read [docs/diff_report.md](docs/diff_report.md). Each iteration row documents a failure mode and the structural signal that catches it. The patterns repeat.
3. The validator's signature (`mov #0x50; strb [x2]` near the top of a 3-arg function) has been stable across BoringSSL versions for years — verify it's still in the current binary before touching anything else.
4. If `_A_isStubAtAdrp` returns false on a stub that *should* match, the compiler probably changed the stub's instruction count or replaced `RET` with `BR x30`. Update the detector, run `tools/diag.js` again.
5. Keep the auto-diag dump from a failed run — it tells you exactly which layer broke.

There's a companion Claude Code skill that automates this — `flutter-frida-repair` — which uses radare2 to fingerprint old vs new `libflutter.so`, replay the broken anchors, and propose a new strategy. Not required to use, but useful for quick triage.

---

## Methodology lessons (the bit that's actually generalisable)

These are documented in more detail in `flutter-ssl-bypass.js`'s file-level comment block and in [docs/diff_report.md](docs/diff_report.md), but if you take nothing else from this repo:

1. **Silent wrong answers are the default failure mode in RE/Frida work.** A scan that returns 0 hits looks identical to "no hits exist." A decoder with a bit-math bug looks identical to a clean module. Bake validation into every layer.
2. **JS opcode comparisons need `| 0` whenever bit 31 is set.** `(insn & 0x9f000000) === 0x90000000` is silently always-false because JS bitwise returns Int32 and `0x90000000` is a positive Number. Forces a generation of resolvers to fail invisibly. Use `(VALUE | 0)` on both sides.
3. **`mod.enumerateRanges(filter)` is unreliable on some Android+Frida combos.** Use `Process.enumerateRanges(filter)` and intersect with the module window.
4. **Order of operations in guard chains matters.** The Iter-5 fix was nothing more than moving stub detection BEFORE the prologue-walkback guard — but that one guard ordering was the difference between "always succeeds" and "always silently falls through to a weaker strategy."
5. **Scan ALL executable subranges, not just the biggest.** Some libflutter builds split BoringSSL/libcxx/icu into smaller r-x sections separated by tiny rwx pages; scanning only the biggest .text region misses them entirely.

---

## Credits and prior work

- **[hackcatml/frida-flutterproxy](https://github.com/hackcatml/frida-flutterproxy)** — **direct upstream**. This repo started as a repair of that script against a newer libflutter build. The pieces that survive unchanged or near-unchanged include:
  - The ELF / Mach-O in-memory parser (`parseElf`, `parseMachO`).
  - The Socket_CreateConnect → GetSockAddr → libc `socket()` redirect trick — the entire mechanism that lets the proxy work even when Flutter ignores the system proxy.
  - The overall control-flow shape (await for libflutter, parse, resolve, hook).

  Everything anchor-related — `_A_*` helpers, multi-signal validator, stub-caller chain, auto-diag — is new in this fork. Credit for the foundation goes to the original author.
- [NVISOsecurity/disable-flutter-tls-verification](https://github.com/NVISOsecurity/disable-flutter-tls-verification) — community-maintained byte-pattern catalog. Their patterns labelled the address as `ssl_verify_peer_cert` historically, then pivoted to `ssl_crypto_x509_session_verify_cert_chain` in Jan 2026 ([issue #51](https://github.com/NVISOsecurity/disable-flutter-tls-verification/issues/51)) — same pivot we ended up on.
- [BoringSSL source](https://boringssl.googlesource.com/boringssl) — `ssl/ssl_x509.cc` (`session_verify_cert_chain` at line 201), `ssl/handshake.cc` (`ssl_verify_peer_cert` at line 268).

---

## License

[MIT](LICENSE) — same as upstream [hackcatml/frida-flutterproxy](https://github.com/hackcatml/frida-flutterproxy).

The `LICENSE` file preserves the original upstream copyright (`Copyright (c) 2024 hackcatml`) and adds the fork's copyright (`Copyright (c) 2026 Sinderella`) for the new material — primarily the anchor-resolution layer, multi-signal validator, stub-caller chain, and auto-diagnostic. Both are covered by the same MIT terms.

If you redistribute or fork further, keep the `LICENSE` file intact and add your own copyright line if you make substantive changes.
