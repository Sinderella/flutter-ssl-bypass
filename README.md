# flutter-ssl-bypass

A resilient Frida-based SSL pinning bypass for **Android arm64 Flutter apps**. Targets `ssl_crypto_x509_session_verify_cert_chain` inside `libflutter.so` via a register-agnostic, structure-validated anchor chain — designed to fail loudly rather than silently when a future Flutter build moves things around.

> **Authorized testing only.** This is for security research, CTFs, your own apps, and authorized engagements. Don't point it at apps you don't have permission to analyse.

---

## Quick start

Download the latest release artifact and its sha256 sibling:

```bash
curl -L -O https://github.com/Sinderella/flutter-ssl-bypass/releases/latest/download/flutter-ssl-bypass.js
curl -L -O https://github.com/Sinderella/flutter-ssl-bypass/releases/latest/download/flutter-ssl-bypass.js.sha256
```

Run the agent (parameter-driven — no source edits required):

```bash
frida -U -l flutter-ssl-bypass.js -P '{"proxyIp":"<IP>","proxyPort":<PORT>}' -f <package.name>
```

Replace `<IP>`, `<PORT>`, and `<package.name>` with your proxy and target. Make sure your CA is installed as a **system** CA on the device (`/system/etc/security/cacerts/`), not just a user CA.

### Troubleshooting

If you see `[!] flutter-ssl-bypass requires Frida 17.x runtime APIs`, your `frida-server` is too old. Upgrade to Frida 17.x; older releases removed `Module.findExportByName` and the agent will fail loudly rather than silently misbehave.

---

## Verify the artifact

```bash
curl -L -O https://github.com/Sinderella/flutter-ssl-bypass/releases/latest/download/flutter-ssl-bypass.js
curl -L -O https://github.com/Sinderella/flutter-ssl-bypass/releases/latest/download/flutter-ssl-bypass.js.sha256
sha256sum -c flutter-ssl-bypass.js.sha256
# expected output: flutter-ssl-bypass.js: OK
```

If the check fails, do not run the agent — re-download or open an issue. The same sha256 sibling is auto-attached to every Release; the integrity guarantee comes from GitHub's release-asset URLs, not from re-hosting. The same command appears in the Release notes' verification stanza — repetition is intentional for security-critical UX.

---

## Tested against

| Component | Version | Notes |
|---|---|---|
| libflutter (Dart VM) | 3.9.2 (stable, 2025-08-27, ~Flutter 3.32 era, engine `fec78c0d…`) | Bypass resolves correctly; legacy `ADRP X9 / ADD X9` byte pattern also worked here |
| libflutter (Dart VM) | 3.10.9 (stable, 2026-02-03, ~Flutter 3.36/3.38 era, engine `ea7cdbc6…`) | Bypass resolves correctly; primary tested-confirmed build |
| frida-server runtime | 17.x | Required — older Frida releases removed `Module.findExportByName` |
| Target ABI | Android arm64 only | Decoder is arm64-only |

Anything outside this matrix may still work — the anchor chain is structural — but isn't tested. If you run against a build outside the tested range, the script's auto-diagnostic dump tells you which layer broke; see [docs/INSIGHTS.md](docs/INSIGHTS.md) for the repair playbook.

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

## Want the deep dive?

If you want to know *why* the anchor chain looks the way it does, or you're picking up the project for repair, start with [docs/INSIGHTS.md](docs/INSIGHTS.md). It carries the architectural diagram, the key insights from the repair, and links to the full repair archive (iteration log, failure-mode taxonomy, evidence-backed verification, and the fingerprint files for the two tested builds).

---

## Credits and prior work

- **[hackcatml/frida-flutterproxy](https://github.com/hackcatml/frida-flutterproxy)** — **direct upstream**. This repo started as a repair of that script against a newer libflutter build. The pieces that survive unchanged or near-unchanged include:
  - The ELF / Mach-O in-memory parser (`parseElf`, `parseMachO`).
  - The Socket_CreateConnect → GetSockAddr → libc `socket()` redirect trick — the entire mechanism that lets the proxy work even when Flutter ignores the system proxy.
  - The overall control-flow shape (await for libflutter, parse, resolve, hook).

  Everything anchor-related — `_A_*` helpers, multi-signal validator, stub-caller chain, auto-diag — is new in this fork. Credit for the foundation goes to the original author.
- [NVISOsecurity/disable-flutter-tls-verification](https://github.com/NVISOsecurity/disable-flutter-tls-verification) — community-maintained byte-pattern catalog. Their patterns labelled the address as `ssl_verify_peer_cert` historically, then pivoted to `ssl_crypto_x509_session_verify_cert_chain` in Jan 2026 ([issue #51](https://github.com/NVISOsecurity/disable-flutter-tls-verification/issues/51)) — same pivot we ended up on.
- [BoringSSL source](https://boringssl.googlesource.com/boringssl) — `ssl/ssl_x509.cc` (`session_verify_cert_chain` at line 201), `ssl/handshake.cc` (`ssl_verify_peer_cert` at line 268).
- [kittichat](https://github.com/kittichat) — research and testing contributions.

---

## License

[MIT](LICENSE) — same as upstream [hackcatml/frida-flutterproxy](https://github.com/hackcatml/frida-flutterproxy).

The `LICENSE` file preserves the original upstream copyright (`Copyright (c) 2024 hackcatml`) and adds the fork's copyright (`Copyright (c) 2026 Sinderella`) for the new material — primarily the anchor-resolution layer, multi-signal validator, stub-caller chain, and auto-diagnostic. Both are covered by the same MIT terms.

If you redistribute or fork further, keep the `LICENSE` file intact and add your own copyright line if you make substantive changes.
