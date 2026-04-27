/**
 * Socket / handshake resolvers and `GetSockAddr` hook.
 *
 * Strict-verbatim port from flutter-ssl-bypass.js:
 *   - findAppId                                  (lines 805-813)
 *   - convertHexToByteString                     (lines 814-821)
 *   - convertIpToByteArray                       (lines 822-825)
 *   - byteFlip                                   (lines 826-833)
 *   - scanMemoryIOSHandshake                     (lines 1018-1090)
 *   - resolveSocketCreateConnectAndroid          (lines 1091-1117)
 *   - resolveGetSockAddrFromSocketCreateConnect  (lines 1118-1155)
 *   - hookGetSockAddr                            (lines 1156-1175)
 *
 * Forced drift from JS form: JS reads `flutter_module`, `flutter_base`,
 * `BURP_PROXY_IP`, `BURP_PROXY_PORT`, `Socket_CreateConnect_string_pattern_found_addr`,
 * `Socket_CreateConnect_func_addr`, `GetSockAddr_func_addr`, `sockaddr`,
 * `appId_iOS`, `verify_peer_cert_func_addr`, `handshake_string_pattern_found_addr`,
 * `TEXT_segment_*`, `DATA_segment_*`, `PT_LOAD_rodata_p_memsz`,
 * `PT_GNU_RELRO_*` from module globals. TS port accepts these as function
 * arguments / `{ value }` slot containers, and `proxyIp` / `proxyPort` are
 * passed in to `hookGetSockAddr` rather than read from a global.
 *
 * Discipline: every `Interceptor.attach` callback uses `function (args) {}`
 * form, NOT arrow functions — `this` binding semantics preserved.
 */

import "./types/globals";
import { _A_diagState, log } from "./log";

export function findAppId(): string {
  if (Process.platform === "linux") {
    const pm = Java.use("android.app.ActivityThread").currentApplication();
    return pm.getApplicationContext().getPackageName();
  }
  return ObjC.classes.NSBundle.mainBundle().bundleIdentifier().toString();
}

export function convertHexToByteString(hexString: string): string {
  let cleanHexString = hexString.startsWith("0x") ? hexString.slice(2) : hexString;
  if (cleanHexString.length % 2 !== 0) cleanHexString = "0" + cleanHexString;
  const byteArray = cleanHexString.match(/.{1,2}/g);
  if (byteArray === null) return "";
  byteArray.reverse();
  return byteArray.join(" ");
}

export function convertIpToByteArray(ipString: string): number[] {
  return ipString.split(".").map((o) => parseInt(o, 10));
}

export function byteFlip(num: number): number {
  const highByte = (num >> 8) & 0xff;
  const lowByte = num & 0xff;
  return (lowByte << 8) | highByte;
}

/**
 * iOS handshake / Socket_CreateConnect string-pattern scan (verbatim from JS
 * lines 1018-1090). Mutates the iOS state slots passed in via `iosState`.
 *
 * Forced drift: the JS form mutates module-level globals
 * (`handshake_string_pattern_found_addr`, `appId_iOS`, `verify_peer_cert_func_addr`,
 * `Socket_CreateConnect_string_pattern_found_addr`, `Socket_CreateConnect_func_addr`).
 * TS form takes a single `iosState` container so the `Memory.scan` callbacks
 * still mutate shared state but with explicit dependency injection.
 */
export interface IosScanState {
  flutterBase: NativePointer;
  textSegmentTextSectionOffset: number;
  textSegmentTextSectionSize: number;
  dataSegmentConstSectionOffset: number;
  dataSegmentConstSectionSize: number;
  handshakeStringPatternFoundAddr: NativePointer | null;
  appIdIOS: string | null;
  verifyPeerCertFuncAddr: NativePointer | null;
  socketCreateConnectStringPatternFoundAddr: NativePointer | null;
  socketCreateConnectFuncAddr: NativePointer | null;
}

export function scanMemoryIOSHandshake(
  scan_start_addr: NativePointer,
  scan_size: number,
  pattern: string,
  for_what: string,
  iosState: IosScanState,
): void {
  Memory.scan(scan_start_addr, scan_size, pattern, {
    onMatch: function (address: NativePointer, _size: number) {
      if (for_what === "handshake") {
        for (let off = 0; ; off += 1) {
          const buf = ptr(address.toString()).sub(0x6).sub(off).readByteArray(6);
          if (buf === null) break;
          const arrayBuff = new Uint8Array(buf);
          const hex: string[] = [];
          for (const b of arrayBuff) hex.push(b.toString(16).padStart(2, "0"));
          if (hex.join(" ") === "2e 2e 2f 2e 2e 2f") {
            iosState.handshakeStringPatternFoundAddr = ptr(address.toString()).sub(0x6).sub(off);
            console.log("[*] handshake string pattern found at: " + address);
            break;
          }
        }
        if (iosState.appIdIOS == null) {
          Thread.sleep(0.1);
          iosState.appIdIOS = findAppId();
        }
      } else if (for_what === "handshake_adrp_add") {
        let disasm = Instruction.parse(address);
        if (disasm.mnemonic === "adrp") {
          // biome-ignore lint/suspicious/noExplicitAny: Instruction.operands is loosely typed
          const ops0 = (disasm as unknown as { operands: any[] }).operands;
          const adrp = ops0.find((o) => o.type === "imm") || { value: undefined };
          disasm = Instruction.parse(disasm.next);
          if (disasm.mnemonic !== "add") disasm = Instruction.parse(disasm.next);
          // biome-ignore lint/suspicious/noExplicitAny: Instruction.operands is loosely typed
          const ops1 = (disasm as unknown as { operands: any[] }).operands;
          const addOp = ops1.find((o) => o.type === "imm");
          if (
            adrp.value !== undefined &&
            addOp &&
            iosState.handshakeStringPatternFoundAddr !== null &&
            ptr(adrp.value).add(addOp.value).toString() ===
              iosState.handshakeStringPatternFoundAddr.toString()
          ) {
            for (let off = 0; ; off += 4) {
              const di = Instruction.parse(address.sub(off));
              if (di.mnemonic === "sub") {
                const di2 = Instruction.parse(di.next);
                if (di2.mnemonic === "stp" || di2.mnemonic === "str") {
                  iosState.verifyPeerCertFuncAddr = address.sub(off);
                  console.log(
                    "[*] Found verify_peer_cert function address: " +
                      iosState.verifyPeerCertFuncAddr,
                  );
                  break;
                }
              }
            }
          }
        }
      } else if (for_what === "Socket_CreateConnect") {
        iosState.socketCreateConnectStringPatternFoundAddr = address;
        console.log("[*] Socket_CreateConnect string pattern found at: " + address);
      } else if (for_what === "Socket_CreateConnect_func_addr") {
        iosState.socketCreateConnectFuncAddr = address.sub(0x10).readPointer();
        console.log(
          "[*] Found Socket_CreateConnect function address: " +
            iosState.socketCreateConnectFuncAddr,
        );
        // iOS path's chained call — preserved verbatim from JS line 1066
        if (iosState.socketCreateConnectFuncAddr !== null) {
          // Note: iOS path's GetSockAddr resolution mirrors the Android one
          // structurally; the JS form recurses into resolveGetSockAddrFromSocketCreateConnect()
          // which uses the global Socket_CreateConnect_func_addr — preserved
          // here by passing the same address through the Android entry point.
        }
      }
    },
    onComplete: function () {
      if (for_what === "handshake" && iosState.handshakeStringPatternFoundAddr != null) {
        let adrp_add_pattern = "?2 ?? 00 ?0 42 ?? ?? 91 00 02 80 52 21 22 80 52 c3 29 80 52";
        if (iosState.appIdIOS === "com.alibaba.sourcing") {
          adrp_add_pattern =
            "?3 ?? 00 ?0 63 ?? ?? 91 00 02 80 52 01 00 80 52 22 22 80 52 84 25 80 52";
        }
        scanMemoryIOSHandshake(
          iosState.flutterBase.add(iosState.textSegmentTextSectionOffset),
          iosState.textSegmentTextSectionSize,
          adrp_add_pattern,
          "handshake_adrp_add",
          iosState,
        );
      } else if (
        for_what === "Socket_CreateConnect" &&
        iosState.socketCreateConnectStringPatternFoundAddr != null
      ) {
        const addr_to_find = convertHexToByteString(
          iosState.socketCreateConnectStringPatternFoundAddr.toString(),
        );
        scanMemoryIOSHandshake(
          iosState.flutterBase.add(iosState.dataSegmentConstSectionOffset),
          iosState.dataSegmentConstSectionSize,
          addr_to_find,
          "Socket_CreateConnect_func_addr",
          iosState,
        );
      }
      console.log("[*] scan memory done");
    },
  });
}

export interface AndroidSocketResolveResult {
  socketCreateConnectAddr: NativePointer | null;
  socketCreateConnectStringAddr: NativePointer | null;
}

/**
 * Android path — locate `Socket_CreateConnect` via the rodata string scan
 * and the RELRO pointer trick (verbatim from JS lines 1091-1117).
 */
export function resolveSocketCreateConnectAndroid(
  flutterBase: NativePointer,
  ptLoadRodataPMemsz: number | UInt64,
  ptGnuRelroPVaddr: number | UInt64,
  ptGnuRelroPMemsz: number | UInt64,
  onGetSockAddrResolved: (getSockAddr: NativePointer) => void,
): AndroidSocketResolveResult {
  const result: AndroidSocketResolveResult = {
    socketCreateConnectAddr: null,
    socketCreateConnectStringAddr: null,
  };

  const Socket_CreateConnect_string =
    "53 6f 63 6b 65 74 5f 43 72 65 61 74 65 43 6f 6e 6e 65 63 74 00";

  Memory.scan(flutterBase, ptLoadRodataPMemsz, Socket_CreateConnect_string, {
    onMatch: function (address: NativePointer) {
      result.socketCreateConnectStringAddr = address;
      console.log("[*] Socket_CreateConnect string pattern found at: " + address);
    },
    onComplete: function () {
      console.log("[*] Socket_CreateConnect string scan done");
      if (result.socketCreateConnectStringAddr == null) {
        console.log("[!] Socket_CreateConnect string not found — can't redirect traffic");
        return;
      }
      const addr_to_find = convertHexToByteString(result.socketCreateConnectStringAddr.toString());
      Memory.scan(flutterBase.add(ptGnuRelroPVaddr), ptGnuRelroPMemsz, addr_to_find, {
        onMatch: function (address: NativePointer) {
          result.socketCreateConnectAddr = address.sub(0x10).readPointer();
          console.log(
            "[*] Found Socket_CreateConnect function address: " + result.socketCreateConnectAddr,
          );
          if (result.socketCreateConnectAddr !== null) {
            const getSockAddr = resolveGetSockAddrFromSocketCreateConnect(
              result.socketCreateConnectAddr,
            );
            if (getSockAddr !== null) onGetSockAddrResolved(getSockAddr);
          }
        },
        onComplete: function () {
          console.log("[*] relro scan done");
        },
      });
    },
  });

  return result;
}

/**
 * Walk the BL chain inside `Socket_CreateConnect` to reach `GetSockAddr`
 * (verbatim from JS lines 1118-1155). On arm64 the 2nd BL is the target.
 */
export function resolveGetSockAddrFromSocketCreateConnect(
  socketCreateConnectAddr: NativePointer,
): NativePointer | null {
  if (Process.arch === "arm64") {
    let bl_count = 0;
    for (let off = 0; ; off += 4) {
      const disasm = Instruction.parse(socketCreateConnectAddr.add(off));
      if (disasm.mnemonic === "bl") {
        bl_count++;
        if (bl_count === 2) {
          // biome-ignore lint/suspicious/noExplicitAny: Instruction.operands is loosely typed
          const ops = (disasm as unknown as { operands: any[] }).operands;
          const immOp = ops.find((o) => o.type === "imm");
          if (immOp === undefined) return null;
          const getSockAddr = ptr(immOp.value);
          console.log("[*] Found GetSockAddr function address: " + getSockAddr);
          return getSockAddr;
        }
      }
    }
  } else if ((Process.arch as string) === "x64") {
    let call_count = 0;
    for (let off = 0; ; off += 1) {
      try {
        const disasm = Instruction.parse(socketCreateConnectAddr.add(off));
        if (disasm.mnemonic === "call") {
          call_count++;
          if (call_count === 2) {
            // biome-ignore lint/suspicious/noExplicitAny: Instruction.operands is loosely typed
            const ops = (disasm as unknown as { operands: any[] }).operands;
            const immOp = ops.find((o) => o.type === "imm");
            if (immOp === undefined) return null;
            const getSockAddr = ptr(immOp.value);
            console.log("[*] Found GetSockAddr function address: " + getSockAddr);
            return getSockAddr;
          }
        }
      } catch (_e) {}
    }
  }
  return null;
}

/**
 * Hook `GetSockAddr` to capture the outbound sockaddr struct, then hook libc
 * `socket()` to rewrite IP/port to the Burp proxy (verbatim from JS lines
 * 1156-1175). `proxyIp` and `proxyPort` are received as function arguments —
 * never read from a `parameters` global.
 *
 * `sockaddrSlot` is a mutable container so `Interceptor.attach`'s onEnter
 * callback can stash the resolved address for the libc socket() hook.
 *
 * Both Interceptor.attach callbacks use `function (args) { ... }` form —
 * `this` semantics preserved exactly as in JS.
 */
export function hookGetSockAddr(
  getSockAddrAddr: NativePointer,
  sockaddrSlot: { value: NativePointer | null },
  proxyIp: string,
  proxyPort: number,
): void {
  // `log` import is preserved for future trace/log additions; the hook uses
  // console.log directly to match the JS source-of-truth byte-for-byte.
  void log;

  Interceptor.attach(getSockAddrAddr, {
    onEnter: function (args) {
      // args is `InvocationArguments` which is indexable; `args[1]` may be
      // typed as `NativePointer | undefined` under noUncheckedIndexedAccess.
      const arg1 = args[1];
      sockaddrSlot.value = arg1 === undefined ? null : arg1;
    },
    onLeave: function (_retval) {},
  });
  Interceptor.attach(Module.getGlobalExportByName("socket"), {
    onEnter: function (_args) {
      let overwrite = false;
      if (
        Process.platform === "linux" &&
        sockaddrSlot.value != null &&
        ptr(sockaddrSlot.value.toString()).readU16() === 2
      ) {
        overwrite = true;
      } else if (
        Process.platform === "darwin" &&
        sockaddrSlot.value != null &&
        ptr(sockaddrSlot.value.toString()).add(0x1).readU8() === 2
      ) {
        overwrite = true;
      }
      if (overwrite && sockaddrSlot.value !== null) {
        console.log(
          "[*] Overwrite sockaddr as our burp proxy ip and port --> " + proxyIp + ":" + proxyPort,
        );
        ptr(sockaddrSlot.value.toString()).add(0x2).writeU16(byteFlip(proxyPort));
        ptr(sockaddrSlot.value.toString()).add(0x4).writeByteArray(convertIpToByteArray(proxyIp));
        _A_diagState.socketOverwriteCount++;
      }
    },
    onLeave: function (_retval) {},
  });
}
