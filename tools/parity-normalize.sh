#!/bin/sh
#
# tools/parity-normalize.sh — normalize a Frida log so the JS-vs-TS parity
# diff compares only behavioral signal, not run-to-run noise.
#
# Strips:
#   - ISO timestamps                                    -> dropped
#   - Hex addresses (0x[0-9a-f]+)                       -> 0xADDR
#   - Thread IDs (tid=N)                                -> tid=TID
#   - Process IDs (pid=N)                               -> pid=PID
#   - Dart-version / libflutter-build stamps            -> libflutter-dart-X.Y.Z.so
#
# Preserves:
#   - Log prefixes ([*], [!], [anchor], [trace], [self-test], [auto-diag], [ground-truth])
#   - Anchor labels and `via=` strings
#   - Hook names, return-value lines, structural counts
#
# Usage:
#   tools/parity-normalize.sh < raw-frida-output.log > tests/parity/baseline-dart-X.Y.Z.log

set -e

sed -E \
  -e 's/[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.+-]+Z?//g' \
  -e 's/0x[0-9a-fA-F]+/0xADDR/g' \
  -e 's/tid=[0-9]+/tid=TID/g' \
  -e 's/pid=[0-9]+/pid=PID/g' \
  -e 's/libflutter-dart-[0-9]+\.[0-9]+\.[0-9]+\.so/libflutter-dart-X.Y.Z.so/g'
