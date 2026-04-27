/**
 * Re-export aggregator for src/types/*.
 *
 * Keeps caller imports compact: `import type { ElfParseResult } from "../types"`
 * instead of `from "../types/elf"`.
 */

export type {
  AnchorCandidate,
  AnchorResolution,
  AnchorValidation,
  GroundTruthRange,
  GroundTruthTable,
} from "./anchor";
export type { ElfNumericField, ElfParseResult } from "./elf";
export type { MachODataSegment, MachOParseResult, MachOTextSegment } from "./macho";
export type { ProxyParameters } from "./parameters";
export { validateParameters } from "./parameters";
