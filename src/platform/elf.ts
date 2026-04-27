/**
 * ELF parser.
 *
 * Strict-verbatim port of flutter-ssl-bypass.js lines 1211-1271. Forced drift
 * from JS form:
 *   - JS form mutates module-level globals (PT_LOAD_*, PT_GNU_RELRO_*). TS
 *     form returns an `ElfParseResult` struct instead — required because pure
 *     modules cannot have import-time side-effects.
 *   - JS uses `getExportFunction(...)` returning `null` when symbol is missing
 *     and lets the caller crash if the table is incomplete. TS port uses the
 *     same null-on-missing pattern, but `parseElf` requires all three (open,
 *     read, lseek) to be available to function — caller must check.
 *
 * Discipline: zero `!` non-null assertions; zero `+` between pointer and
 * number (use `.add` / `.sub`); zero `Interceptor.*` and `Memory.scan*` calls
 * (verified by grep + tools/lint-pointer-arith.sh + biome's noNonNullAssertion
 * rule).
 */

import "../types/globals";
import type { ElfParseResult } from "../types/elf";

const O_RDONLY = 0;
const SEEK_SET = 0;

const p_types: Record<string, number> = {
  PT_NULL: 0,
  PT_LOAD: 1,
  PT_DYNAMIC: 2,
  PT_INTERP: 3,
  PT_NOTE: 4,
  PT_SHLIB: 5,
  PT_PHDR: 6,
  PT_TLS: 7,
  PT_NUM: 8,
  PT_LOOS: 0x60000000,
  PT_GNU_EH_FRAME: 0x6474e550,
  PT_GNU_STACK: 0x6474e551,
  PT_GNU_RELRO: 0x6474e552,
  PT_GNU_PROPERTY: 0x6474e553,
};

/**
 * Resolve a libc export and wrap it in a NativeFunction. Returns null if the
 * export is missing. Verbatim port of flutter-ssl-bypass.js lines 1219-1223.
 *
 * The Frida-17 form `Module.getGlobalExportByName` is already used in the JS
 * source (compatibility verified during the original repair).
 */
function getExportFunction(
  name: string,
  ret: NativeFunctionReturnType,
  args: NativeFunctionArgumentType[],
): NativeFunction<NativePointer | number, NativePointer[] | number[]> | null {
  const funcPtr = Module.getGlobalExportByName(name);
  if (funcPtr === null) return null;
  // biome-ignore lint/suspicious/noExplicitAny: NativeFunction generics for libc don't narrow well here
  return new NativeFunction(funcPtr, ret as any, args as any) as any;
}

/* eslint-disable @typescript-eslint/no-explicit-any */
const open_fn = getExportFunction("open", "int", ["pointer", "int", "int"]);
const read_fn = getExportFunction("read", "int", ["int", "pointer", "int"]);
const lseek_fn = getExportFunction("lseek", "int", ["int", "int", "int"]);
/* eslint-enable @typescript-eslint/no-explicit-any */

/**
 * Parse the in-memory ELF at `base` and return the relevant program-header
 * offsets and sizes. Returns an `ElfParseResult` with null fields when the
 * loader didn't produce a particular segment (matches the JS-form sentinel
 * `null` initial values at lines 778-782).
 */
export function parseElf(base: NativePointer): ElfParseResult {
  const baseP = ptr(base.toString());
  const module = Process.findModuleByAddress(baseP);
  let fd: number | null = null;
  if (module !== null && open_fn !== null) {
    // biome-ignore lint/suspicious/noExplicitAny: NativeFunction call signature is dynamic
    const openCall = open_fn as any;
    fd = openCall(Memory.allocUtf8String(module.path), O_RDONLY, 0) as number;
  }

  const is32bit = (Process.arch as string) === "arm" ? 1 : 0;
  const size_of_Elf64_Ehdr = 0x40;
  const off_of_Elf64_Ehdr_phentsize = 54;
  const off_of_Elf64_Ehdr_phnum = 56;

  const phoff = is32bit ? 0x34 : size_of_Elf64_Ehdr;
  let phentsize = is32bit ? 32 : baseP.add(off_of_Elf64_Ehdr_phentsize).readU16();
  if (!is32bit && phentsize !== 56) phentsize = 56;
  let phnum = is32bit ? baseP.add(44).readU16() : baseP.add(off_of_Elf64_Ehdr_phnum).readU16();
  if (phnum === 0 && fd != null && fd !== -1 && lseek_fn !== null && read_fn !== null) {
    const ehdrs_from_file = Memory.alloc(64);
    // biome-ignore lint/suspicious/noExplicitAny: NativeFunction call signature is dynamic
    (lseek_fn as any)(fd, 0, SEEK_SET);
    // biome-ignore lint/suspicious/noExplicitAny: NativeFunction call signature is dynamic
    (read_fn as any)(fd, ehdrs_from_file, 64);
    phnum = ehdrs_from_file.add(off_of_Elf64_Ehdr_phnum).readU16();
    if (phnum === 0) phnum = 10;
  }

  const result: ElfParseResult = {
    ptLoadRodataPMemsz: null,
    ptLoadTextPVaddr: null,
    ptLoadTextPMemsz: null,
    ptGnuRelroPVaddr: null,
    ptGnuRelroPMemsz: null,
  };

  const phdrs = baseP.add(phoff);
  for (let i = 0; i < phnum; i++) {
    const phdr = phdrs.add(i * phentsize);
    const p_type = phdr.readU32();
    let p_type_sym: string | null = null;
    for (const key in p_types) {
      if (p_types[key] === p_type) {
        p_type_sym = key;
        break;
      }
    }
    if (p_type_sym == null) break;

    const p_vaddr = is32bit ? phdr.add(0x8).readU32() : phdr.add(0x10).readU64();
    const p_memsz = is32bit ? phdr.add(0x14).readU32() : phdr.add(0x28).readU64();

    // JS form uses `==` (loose equality) for the `p_vaddr == 0` check so a UInt64
    // zero compares equal to a number 0. TS port matches the semantics by
    // coercing both via Number() — UInt64.toNumber() is the explicit form.
    const vaddrIsZero = typeof p_vaddr === "number" ? p_vaddr === 0 : p_vaddr.toNumber() === 0;

    if (p_type_sym === "PT_LOAD" && vaddrIsZero) {
      result.ptLoadRodataPMemsz = p_memsz;
      continue;
    }
    if (p_type_sym === "PT_LOAD" && !vaddrIsZero) {
      if (result.ptLoadTextPVaddr == null) {
        result.ptLoadTextPVaddr = p_vaddr;
        result.ptLoadTextPMemsz = p_memsz;
      }
      continue;
    }
    if (p_type_sym === "PT_GNU_RELRO") {
      result.ptGnuRelroPVaddr = p_vaddr;
      result.ptGnuRelroPMemsz = p_memsz;
      break;
    }
  }

  return result;
}
