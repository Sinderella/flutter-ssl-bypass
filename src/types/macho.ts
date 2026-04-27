/**
 * Mach-O parser result type.
 *
 * Mirrors the JS-side module-level globals populated by `parseMachO(base)` in
 * flutter-ssl-bypass.js (lines 784-789). Same forced drift as src/types/elf.ts:
 * TS returns the struct; JS mutates globals.
 *
 * iOS path is preserved verbatim and explicitly marked untested on recent
 * Flutter builds in src/platform/macho.ts.
 */

export interface MachOTextSegment {
  textOffset: number | null;
  textSize: number | null;
  cstringOffset: number | null;
  cstringSize: number | null;
}

export interface MachODataSegment {
  constOffset: number | null;
  constSize: number | null;
}

export interface MachOParseResult {
  textSegment: MachOTextSegment;
  dataSegment: MachODataSegment;
}
