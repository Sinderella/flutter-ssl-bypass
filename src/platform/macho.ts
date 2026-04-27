/**
 * Mach-O parser for the iOS Flutter library — verbatim port from
 * flutter-ssl-bypass.js lines 1272-1304.
 *
 * **Untested on recent iOS Flutter builds.**
 *
 * The iOS path has been preserved from upstream and gated behind
 * `Process.platform === "darwin"`. We have no parity baseline for iOS because
 * no recent iOS Flutter build has been validated against this anchor scheme.
 * Treat any iOS hook firing as advisory only until a maintainer captures a
 * real iOS log under tools/parity-capture.md and adds it to tests/parity/.
 *
 * Forced drift from JS form: JS mutates module-level globals
 * (TEXT_segment_*, DATA_segment_*); TS form returns a `MachOParseResult`
 * struct so the module stays free of import-time side-effects.
 */

import "../types/globals";
import type { MachOParseResult } from "../types/macho";

export function parseMachO(base: NativePointer): MachOParseResult {
  const baseP = ptr(base.toString());

  const result: MachOParseResult = {
    textSegment: {
      textOffset: null,
      textSize: null,
      cstringOffset: null,
      cstringSize: null,
    },
    dataSegment: {
      constOffset: null,
      constSize: null,
    },
  };

  const magic = baseP.readU32();
  if (magic !== 0xfeedfacf) {
    console.log("Unknown magic");
    return result;
  }
  const cmdnum = baseP.add(0x10).readU32();
  let cmdoff = 0x20;
  for (let i = 0; i < cmdnum; i++) {
    const cmd = baseP.add(cmdoff).readU32();
    const cmdsize = baseP.add(cmdoff + 0x4).readU32();
    if (cmd === 0x19) {
      const segname = baseP.add(cmdoff + 0x8).readUtf8String();
      const nsects = baseP.add(cmdoff + 0x40).readU8();
      const secbase = baseP.add(cmdoff + 0x48);
      let tIdx = 0;
      let cIdx = 0;
      let dIdx = 0;
      for (let j = 0; j < nsects; j++) {
        const secname = secbase.add(j * 0x50).readUtf8String();
        const sstart = secbase.add(j * 0x50 + 0x30).readU32();
        if (segname === "__TEXT" && secname === "__text") {
          tIdx = j;
          result.textSegment.textOffset = sstart;
        } else if (segname === "__TEXT" && j === tIdx + 1) {
          const off = result.textSegment.textOffset;
          if (off !== null) result.textSegment.textSize = sstart - off;
        } else if (segname === "__TEXT" && secname === "__cstring") {
          cIdx = j;
          result.textSegment.cstringOffset = sstart;
        } else if (segname === "__TEXT" && j === cIdx + 1) {
          const off = result.textSegment.cstringOffset;
          if (off !== null) result.textSegment.cstringSize = sstart - off;
        } else if (segname === "__DATA" && secname === "__const") {
          dIdx = j;
          result.dataSegment.constOffset = sstart;
        } else if (segname === "__DATA" && j === dIdx + 1) {
          const off = result.dataSegment.constOffset;
          if (off !== null) result.dataSegment.constSize = sstart - off;
        }
      }
    }
    cmdoff += cmdsize;
  }

  return result;
}
