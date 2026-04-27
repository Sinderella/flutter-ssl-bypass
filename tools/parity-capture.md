# Parity Baseline Capture Runbook

This runbook is **maintainer-only**. It captures the canonical normalized log files that the
TypeScript port's parity gate diffs against.

## When to run

- Whenever the placeholder `tests/parity/baseline-dart-*.log` files need to be replaced by
  real captures.
- Whenever a libflutter codegen change is suspected to have shifted behavior — re-baseline,
  re-diff, audit the drift.

## Prerequisites

- Real Android device (or emulator) with `frida-server` 17.x running.
- Two test apps: one bundling `libflutter-dart-3.9.2.so`, one bundling `libflutter-dart-3.10.9.so`.
  Same APKs as the originally-validated ones in PROJECT.md.
- `flutter-ssl-bypass.js` (root, JS source-of-truth) untouched in the repo.
- `tools/parity-normalize.sh` present and executable.
- Access to a Burp / mitmproxy listener on `<IP>:<PORT>`.

## Procedure (per Dart version)

For each Dart version `X.Y.Z` in `{3.9.2, 3.10.9}`:

1. **Boot the test device, ensure frida-server is running, ensure the test app is installed.**

2. **Spawn + attach with the JS source-of-truth:**

   ```sh
   frida -U \
     -l flutter-ssl-bypass.js \
     -P '{"proxyIp":"<IP>","proxyPort":<PORT>}' \
     -f <package> \
     2>&1 | tee /tmp/raw-js-dart-X.Y.Z.log
   ```

   Note: the JS form does not consume the Parameters API (`-P` is the new TS surface).
   The JS still hardcodes `BURP_PROXY_IP = "127.0.0.1"` and `BURP_PROXY_PORT = 8080` at
   lines 1308-1309. **Run the JS baseline against a Burp listener at `127.0.0.1:8080` so
   that the captured log matches the TS run when
   `-P '{"proxyIp":"127.0.0.1","proxyPort":8080}'` is passed.** The TS port emits the same
   Burp redirect log line; only the input mechanism differs.

3. **User flow on the target app:** make exactly **one outgoing HTTPS request** through the
   primary flow (e.g., open the home screen, login, or whatever triggers a real cert-chain
   verification). Wait until you see the `[trace] verify_cert_chain ENTER` / `LEAVE` lines
   in the Frida output. Hold for ~25 seconds total so both watchdogs have time to fire (or
   not) — captures should include the silence period as well.

4. **Detach from the agent:** Ctrl+C in the Frida terminal.

5. **Normalize:**

   ```sh
   tools/parity-normalize.sh < /tmp/raw-js-dart-X.Y.Z.log > tests/parity/baseline-dart-X.Y.Z.log
   ```

6. **Sanity check:**

   ```sh
   head -20 tests/parity/baseline-dart-X.Y.Z.log
   ```

   The first line MUST NOT begin with `# PLACEHOLDER`. The capture should contain at least
   `[self-test] decoder bit-math OK`, one `[anchor] ...` line, one `[*] verify_cert_chain
   resolved` line (or the fallback path), and one `[*] Hook GetSockAddr function` line.

7. **Commit:**

   ```sh
   git add tests/parity/baseline-dart-X.Y.Z.log
   git commit -m "test(parity): capture real baseline for Dart X.Y.Z from JS source-of-truth"
   ```

## TS-bundle parity diff

Once both baselines are captured and committed, run the TS bundle through the same flow on
the same devices:

```sh
frida -U \
  -l dist/flutter-ssl-bypass.js \
  -P '{"proxyIp":"127.0.0.1","proxyPort":8080}' \
  -f <package> \
  2>&1 | tee /tmp/raw-ts-dart-X.Y.Z.log

tools/parity-normalize.sh < /tmp/raw-ts-dart-X.Y.Z.log > /tmp/ts-X.Y.Z.normalized.log
diff tests/parity/baseline-dart-X.Y.Z.log /tmp/ts-X.Y.Z.normalized.log
```

**Pass criterion:** `diff` produces zero output (exit 0). Any non-empty diff is a
behavioral drift between JS and TS — investigate before shipping a new bundle.

## Failure modes

- **JS source-of-truth misbehaves on capture (e.g., resolution fails):** STOP. Do not commit
  a partial baseline. Investigate the JS itself (likely a libflutter codegen drift); if
  required, run the `flutter-frida-repair` skill against the new `.so` to regenerate the
  anchor logic before any TS-side parity work.
- **Watchdogs fire during capture:** If watchdog A or B writes an auto-diag dump, that
  diagnostic activity becomes part of the baseline. Capture it as-is and document the
  expected-warning state in the SUMMARY.
- **Non-determinism in JS run-to-run:** The normalize script handles timestamps, addresses,
  thread/PIDs, and version stamps. If a captured baseline still varies across runs, extend
  the regex set in `tools/parity-normalize.sh` and re-baseline.
