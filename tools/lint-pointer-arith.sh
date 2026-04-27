#!/bin/sh
#
# tools/lint-pointer-arith.sh — enforce "zero `+` operators between
# NativePointer and number; use .add() / .sub() / .equals() / .compare()".
#
# Biome 2.4.x's custom-rule API does not yet expose type-aware operand checks,
# so this script is the fallback. Runs as part of `bun run lint`. Greps
# src/**/*.ts for suspicious pointer-arithmetic patterns and exits non-zero on
# any unallowed match.
#
# Heuristic — flag any `<lhs> + <rhs>` where the LHS ends in a known
# NativePointer-bearing identifier (addr, Ptr, _addr, flutter_base, vaddr, base,
# offset_addr) or is `ptr(...)`. Comments / string literals are excluded by
# stripping `//`-style comments before grepping; full-line strings catch a
# false-positive on JS source containers — exclude flutter-ssl-bypass.js
# explicitly (it's the parity reference, not src).
#
# Keep this conservative: a false negative leaks a real bug; a false positive
# is just a refactor request. Scope is `src/**/*.ts` only. Does NOT scan
# tests, tools, or scripts.

set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC_DIR="$ROOT/src"

if [ ! -d "$SRC_DIR" ]; then
  echo "lint-pointer-arith: $SRC_DIR not found"
  exit 0
fi

# Suspect identifiers that are conventionally NativePointer-bearing.
SUSPECT_RE='\b(addr|Ptr|_addr|flutter_base|vaddr|offset_addr|adrpTarget|pcPage|pageMask|computed)\b\s*\+\s*[A-Za-z0-9_]'

# Also catch direct `ptr(...) + ...` constructions and `.base + ...` access
# patterns common in Frida code.
EXTRA_RE='(\bptr\s*\([^)]*\)\s*\+\s*[A-Za-z0-9_]|\.base\s*\+\s*[A-Za-z0-9_])'

violations=0

# shellcheck disable=SC2044
for file in $(find "$SRC_DIR" -type f -name '*.ts'); do
  # Strip line-end comments so we don't false-positive on commentary.
  # Also skip lines that are obviously inside string literals (line starts/ends
  # in a quote with the suspect inside).
  if stripped="$(sed -E 's://.*$::' "$file")"; then
    matches="$(printf '%s\n' "$stripped" | grep -nE "$SUSPECT_RE|$EXTRA_RE" || true)"
    if [ -n "$matches" ]; then
      printf '\n[lint-pointer-arith] pointer-arithmetic violation in %s:\n%s\n' "$file" "$matches"
      violations=$((violations + 1))
    fi
  fi
done

if [ "$violations" -gt 0 ]; then
  printf '\n[lint-pointer-arith] FAIL: %d file(s) contain suspect pointer arithmetic.\n' "$violations" >&2
  printf '[lint-pointer-arith] Use NativePointer.add(...) / .sub(...) / .equals(...) / .compare(...)\n' >&2
  exit 1
fi

exit 0
