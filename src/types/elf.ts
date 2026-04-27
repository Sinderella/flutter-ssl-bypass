/**
 * ELF parser result type.
 *
 * Mirrors the JS-side module-level globals that `parseElf(base)` populates in
 * flutter-ssl-bypass.js (lines 778-782). The TS port returns this struct
 * instead of mutating module-level state — required because pure modules
 * can't have import-time side-effects.
 *
 * Field names:
 *   - `ptLoadRodataPMemsz` mirrors PT_LOAD_rodata_p_memsz (the rodata segment
 *     for the libflutter Socket_CreateConnect string scan)
 *   - `ptLoadTextPVaddr` / `ptLoadTextPMemsz` mirror PT_LOAD_text_p_vaddr / size
 *   - `ptGnuRelroPVaddr` / `ptGnuRelroPMemsz` mirror PT_GNU_RELRO_*
 *
 * All numeric fields are `UInt64 | number` — `phdr.add(0x10).readU64()` returns
 * a `UInt64`, while the 32-bit ARM path returns a JS `number` from `readU32()`.
 * The JS code passes both shapes through `.add()` / arithmetic via NativePointer
 * coercion, so we type as `NativePointerValue` to preserve that flexibility.
 */

/**
 * `UInt64` is a Frida runtime global declared via `@types/frida-gum` ambient
 * types — not exported as an ESM symbol — so we reference it without an
 * `import type` line.
 */
export type ElfNumericField = UInt64 | number;

export interface ElfParseResult {
  ptLoadRodataPMemsz: ElfNumericField | null;
  ptLoadTextPVaddr: ElfNumericField | null;
  ptLoadTextPMemsz: ElfNumericField | null;
  ptGnuRelroPVaddr: ElfNumericField | null;
  ptGnuRelroPMemsz: ElfNumericField | null;
}
