# Failure-mode catalog for `flutter-ssl-bypass.js`

**Date:** 2026-04-25
**Companion to:** `REVIEW.md`
**Purpose:** Pre-deployment checklist — what could go wrong, what each failure looks like in the Frida console / auto-diag dump, and how likely it is on the target binary this script was built against.

Use this when running the script: walk down the layers, confirm each indicator before assuming the layer is clear.

---

## Layer 1 — Script never starts working

Cheapest layer to diagnose. Before any anchor work happens.

| Failure | Observable signal | Likelihood |
|---|---|---|
| **Frida server / host version mismatch** | Frida CLI errors before script runs ("incompatible protocol", "connection closed") | Medium — NVISO issue #50 had this on iOS |
| **App detects Frida and exits before init** | Process dies in <1s; `frida -f` fails to attach | **Medium-high** for any app shipping commercial RASP (Promon, Guardsquare, et al.) |
| **Self-test fails** (decoder regression) | `[self-test] FAILED — decoder bit-math is broken. Aborting.` + auto-diag | Very low — verified against real instruction words |
| **Wrong package name** in `frida -f` argument | Frida: "unable to find process" | Low |
| **`/data/local/tmp` not writable for app uid** | Auto-diag dumps fail silently; falls back to `/sdcard` then app `files/` dir | Low — three fallbacks present |
| **Burp CA not installed as system CA** | Hook fires, retval flips, but Burp still terminates TLS | Possible — easy to miss as a precondition |

---

## Layer 2 — Resolution fails (script runs but can't find function)

| Failure | Observable signal | Likelihood |
|---|---|---|
| **`ssl_x509.cc` string not in module** | `[anchor] ssl_x509.cc string hits: 0` | Very low — confirmed at module+0x1b1ede |
| **Range enumeration returns empty** (some Frida 17.x + Android combos) | `[anchor]   <addr> -> 0 ADRP+ADD xref(s)` despite string being present | Possible — was the Iter 1 bug; helper covers it but a regression would re-introduce |
| **Stub not detected** (compiler emits `BR x30` instead of RET, or 5+ insns to RET) | `isStub=false` for the 0xa19b18 site | Very low — verified shape ADRP+ADD+MOV+RET |
| **Walkback lands on wrong prologue** (sibling exceeds 0x2000 bytes) | Candidate addr clearly outside ssl_x509 region; size weirdly large | Very low — siblings ≤ ~750 bytes here |
| **`_A_functionSize` measures wrong** (internal RET-like stops measurement < 0x100) | Candidate logged with `size=0xNN` < 0x100 → validator fails on size signal | Possible if function has tail-call BR before RET |
| **No candidate passes validator** | `[anchor] No ssl_x509.cc candidate passed validation` then falls to Strategy 2 | Should be impossible on this binary; if it happens → decoder regression |

---

## Layer 3 — Wrong function picked

| Failure | Observable signal | Likelihood |
|---|---|---|
| **Score tie between siblings** | Multiple candidates with `score=30` in the candidates dump | Very low — only 0x71abfc has `mov 0x50; strb [x2]`; others score 0 |
| **Strategy 2 fallback picks 144-byte string dispatcher** | `via=ssl_client-direct` selected — sibling, not verify_cert_chain | Low — only fires if Strategy 1 returned null; size filter rejects 144B |
| **Score hits a strb [x2] in unrelated 3-arg sibling** | Wrong candidate has score>0, beats verify_cert_chain | Verified not the case — visual inspection of all 4 candidate prologues |

---

## Layer 4 — Right function picked, but hook doesn't fire

| Failure | Observable signal | Likelihood |
|---|---|---|
| **TLS handshake fires before hook installs** | `[*] Hook verify_cert_chain function` logs AFTER first connection; `verify_cert_chain ENTER count = 0` despite traffic | Possible on `--no-pause` cold start — mitigated by polling on 0ms |
| **Frida 17.x trampoline fails on this prologue** | Crash on first invocation; abort in logcat | Very unlikely — frida-gum source confirms paciasp-first prologues are safe; this prologue is `sub sp` first anyway |
| **App doesn't use this code path for the requests you care about** | `verify_cert_chain ENTER count = 0` AND `socket overwrites > 0` (i.e., TCP traffic happens, but never reaches BoringSSL verify) | Possible — if app uses platform HTTP (Java OkHttp via MethodChannel) or Cronet instead of Dart HttpClient |
| **Multiple libflutter.so loaded** (split APK + isolate) | Hook installed on one but TLS happens in another | Low in practice |

---

## Layer 5 — Hook fires but retval flip ineffective

| Failure | Observable signal | Likelihood |
|---|---|---|
| **`retval.replace(0x1)` doesn't propagate** (struct return via x8 — hypothetical) | `LEAVE retval=0` then `[*] verify cert bypass` logged but Burp still terminates | Very unlikely — bool return is in W0; retval.replace works |
| **Function got inlined — "verify_cert_chain" is actually a sibling** | Hook fires with `retval=1` only, never `retval=0` → Watchdog B fires at 20s | Very low here; possible if Flutter version drifts heavily |
| **Function inlined — hook never fires at all** | `verify_cert_chain ENTER count = 0` despite real traffic → Watchdog A fires at 15s | Verified not inlined — BL caller at 0x71ad54 inside its own body proves it's a discrete function |

---

## Layer 6 — BoringSSL bypass fires correctly, but cert still rejected

**This is the most likely real-world hit on apps that combine native and Dart-side pinning.**

| Failure | Observable signal | Likelihood |
|---|---|---|
| **Dart-side SHA-256 fingerprint check** (`basic_utils.X509Utils.sha256Thumbprint`-style) | Hook fires, retval flipped 0→1, sockets redirected, `[*] verify cert bypass` logs — but Burp still sees handshake termination | **High** for any app that follows the documented "BoringSSL allowed, then Dart-side fingerprint compare rejects" pattern. Multiple public engineering writeups describe this approach. |
| **`http_certificate_pinning` plugin** (Java MethodChannel) | Same as above — all BoringSSL signals fire, traffic still rejected | Medium — popular plugin; jadx will reveal class name `HttpCertificatePinningPlugin` |
| **`SSL_get_verify_result` consulted independently** | Same | Medium — easy add-on hook if needed |
| **Additional post-connect check** (timing, JA3, ALPN) | Connection establishes briefly then drops mid-TLS record | Low |

**Diagnostic for Layer 6:** if all of these fire AND Burp still kills the handshake, you're in Dart-side pinning territory. Pivot to jadx and look for the tells in the contingency plan.

---

## Layer 7 — Traffic never reaches Burp

| Failure | Observable signal | Likelihood |
|---|---|---|
| **Flutter ignores system proxy** (known limitation) | Burp sees zero bytes; but `socket overwrites > 0` proves the script's redirect IS forcing it through | Mitigated — script's `GetSockAddr` socket-rewrite trick redirects regardless |
| **App uses HTTP/3 (QUIC)** | Burp sees no TCP for the relevant requests | Low today; growing |
| **Cert pinning at Cronet layer** (if app uses Cronet, not Dart HttpClient) | TLS happens in `libcronet.so` not `libflutter.so` — you're hooking the wrong library | Possible — jadx confirms whether app links Cronet |
| **App uses websocket pre-warmed before Frida attaches** | Persistent connection; Burp sees nothing for it | Low |

---

## Pre-deployment checklist (run in order)

1. Frida server version on device matches host — `frida --version` on both.
2. Device rooted / Magisk-active.
3. `BURP_PROXY_IP` reachable from device — `adb shell ping <ip>`.
4. `BURP_PROXY_PORT` bound on Burp side.
5. Burp CA installed as system CA on device (`/system/etc/security/cacerts/`).
6. Run `diag.js` first to confirm Layer 2 conditions (string hits, range map, xref disasm).
7. THEN deploy `flutter-ssl-bypass.js` and walk the indicator chain below.

---

## Indicator chain (watch in this order)

When you actually run the script, confirm each line appears in the Frida console:

1. `[self-test] decoder bit-math OK (ADRP, ADD, BL, RET)` → Layer 1 clear
2. `[anchor] ssl_x509.cc string hits: 1` → Layer 2 string check clear
3. Stub callers logged (4 BLs from inside ssl_x509 functions) → Layer 2 stub check clear
4. `score=30` candidate present in the candidates dump → Layer 3 clear
5. `[*] Hook verify_cert_chain function (attach + retval.replace(1))` → Layer 4 install clear
6. On first authenticated request: `[trace] verify_cert_chain ENTER` fires → Layer 4 invocation clear
7. At least one `[*] verify cert bypass (return 0 -> 1)` line → Layer 5 clear
8. Burp shows decrypted traffic → ALL CLEAR

**If 1–7 pass but step 8 fails:** Layer 6 — Dart-side pinning. Stop and pivot to jadx-based discovery of the pinning library/method, then add a Java-bridge hook on top of the existing script.

---

## Watchdogs already wired in the script

The auto-diag fires once per session on these conditions (already implemented in `flutter-ssl-bypass.js`):

- **Watchdog A (15s):** `socket overwrites > 0` AND `verify_cert_chain ENTER count = 0` → wrong function hooked, OR Layer 4 path-mismatch
- **Watchdog B (20s):** `hook fired ≥ 5 times, all retval=1` → wrong sibling, OR Layer 6 Dart-side pinning

The dump file path is logged at trigger; pull with `adb pull /data/local/tmp/flutter-bypass-diag-<ts>.txt`.

---

## What we don't yet know

- Whether the target app uses `http_certificate_pinning`, `ssl_pinning_plugin`, `basic_utils` SHA check, or raw `SecurityContext`. Decompile with jadx + grep for those class names BEFORE concluding "BoringSSL bypass insufficient."
- Whether the app links `libcronet.so` in addition to `libflutter.so`. Check with `adb shell dumpsys package <pkg>` or by enumerating loaded modules in Frida (`Process.enumerateModules()`).
- Whether RASP (Promon, Guardsquare) is in play — Layer 1 risk. Test by running a no-op Frida script first; if the app exits, pivot to anti-RASP work.
