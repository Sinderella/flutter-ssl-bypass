/**
 * flutter-ssl-bypass — Frida agent main entry.
 * Strict TypeScript port of flutter-ssl-bypass.js (root, parity reference).
 *
 * Initialization order:
 *   1. Parameters validation     — runs first, before any other code
 *   2. selfTest()                — decoder bit-math, before any hook installation
 *   3. Frida 17 API probe        — abort loudly on missing runtime methods
 *   4. Platform branching + main flow
 *   5. Hook polling
 *
 * User-visible strings use `flutter-ssl-bypass` (agent name), never
 * `reverse-libflutter` (repo name).
 */

import "./types/globals";

import { selfTest } from "./anchor-chain";
import { resolveVerifyCertChain, resolveVerifyPeerCert } from "./dart-resolver";
import { _A_diagState, _A_writeAutoDiag, mustResolve } from "./log";
import { parseElf } from "./platform/elf";
import { parseMachO } from "./platform/macho";
import { findAppId, hookGetSockAddr, resolveSocketCreateConnectAndroid } from "./socket-redirect";
import { hookVerifyCertChainAttach, hookVerifyPeerCertReplace } from "./ssl-hook";
import { validateParameters } from "./types/parameters";

// 1. Parameters validation — runs FIRST, before any other code.
const params = validateParameters((globalThis as { parameters: unknown }).parameters);

// 2. Decoder bit-math self-test — runs at script-load before any hook.
selfTest();

// 3. Frida 17 API probe. On any missing method, abort with the documented
// error message and throw so the agent never partially attaches.
const REQUIRED_FRIDA_APIS: ReadonlyArray<readonly [string, string]> = [
  ["Module", "getGlobalExportByName"],
  ["Process", "getModuleByName"],
  ["Process", "findModuleByName"],
];
for (const [obj, method] of REQUIRED_FRIDA_APIS) {
  // biome-ignore lint/suspicious/noExplicitAny: dynamic Frida runtime probe of two-tier global namespace
  const target = (globalThis as any)[obj];
  if (target == null || typeof target[method] !== "function") {
    console.error(
      "[!] flutter-ssl-bypass requires Frida 17.x runtime APIs. Missing: " +
        obj +
        "." +
        method +
        ". See README troubleshooting section.",
    );
    throw new Error("Frida 17.x required, found incompatible runtime");
  }
}

// 4. Platform branching — verbatim port of JS lines 1305-1431.
const target_flutter_library_initial: string | null = ObjC.available
  ? "Flutter.framework/Flutter"
  : Java.available
    ? "libflutter.so"
    : null;

if (target_flutter_library_initial != null) {
  let target_flutter_library = target_flutter_library_initial;
  let flutter_module: Module | null = null;

  const awaitForCondition = (callback: (base: NativePointer) => void): void => {
    let module_loaded = 0;
    let base: NativePointer | null = null;
    const handle = setInterval(() => {
      Process.enumerateModules()
        .filter((m) => m.path.indexOf(target_flutter_library) !== -1)
        .forEach((m) => {
          if (ObjC.available) {
            const split = target_flutter_library.split("/").pop();
            if (split !== undefined) target_flutter_library = split;
          }
          console.log("[*] " + target_flutter_library + " loaded!");
          flutter_module = Process.getModuleByName(target_flutter_library);
          base = flutter_module.base;
          module_loaded = 1;
        });
      if (module_loaded && base !== null) {
        clearInterval(handle);
        callback(base);
      }
    }, 0);
  };

  const init = (base: NativePointer): void => {
    const flutter_base = ptr(base.toString());
    console.log("[*] " + target_flutter_library + " base: " + flutter_base);

    let verify_cert_chain_func_addr: NativePointer | null = null;
    let verify_peer_cert_func_addr: NativePointer | null = null;
    let verify_cert_chain_strategy: "attach-replace-1" | "replace-return-0" | null = null;
    const sockaddrSlot: { value: NativePointer | null } = { value: null };
    let GetSockAddr_func_addr: NativePointer | null = null;

    if (Process.platform === "linux") {
      const appId = findAppId();
      console.log("[*] package name: " + appId);

      const elf = parseElf(flutter_base);
      void elf; // values consumed via the resolver helpers below

      const fm = mustResolve("flutter_module", () => flutter_module);
      const vcc = resolveVerifyCertChain(fm);
      if (vcc) {
        verify_cert_chain_func_addr = vcc.addr;
        verify_cert_chain_strategy = "attach-replace-1";
        _A_diagState.resolvedVccAddr = vcc.addr.toString();
        _A_diagState.resolvedVccVia = vcc.via;
        console.log(
          "[*] verify_cert_chain resolved via " +
            vcc.via +
            " @ " +
            vcc.addr +
            " (size=0x" +
            vcc.size.toString(16) +
            ")",
        );
      } else {
        console.log("[!] verify_cert_chain NOT resolved — trying ssl_verify_peer_cert fallback");
        const vpc = resolveVerifyPeerCert(fm);
        if (vpc) {
          verify_peer_cert_func_addr = vpc.addr;
          verify_cert_chain_strategy = "replace-return-0";
          _A_diagState.resolvedVccAddr = vpc.addr.toString();
          _A_diagState.resolvedVccVia = vpc.via;
          console.log(
            "[*] ssl_verify_peer_cert resolved via " +
              vpc.via +
              " @ " +
              vpc.addr +
              " (size=0x" +
              vpc.size.toString(16) +
              ")",
          );
        } else {
          console.log("[!] BOTH strategies failed — SSL pinning bypass UNAVAILABLE.");
          console.log(
            "[!] Re-run /flutter-frida-repair against this libflutter.so to regenerate anchors.",
          );
          _A_writeAutoDiag("resolution failed: both strategies returned null", fm);
        }
      }

      // --- Socket_CreateConnect → GetSockAddr (unchanged) ---
      const ptLoadRodataPMemsz = elf.ptLoadRodataPMemsz === null ? 0 : elf.ptLoadRodataPMemsz;
      const ptGnuRelroPVaddr = elf.ptGnuRelroPVaddr === null ? 0 : elf.ptGnuRelroPVaddr;
      const ptGnuRelroPMemsz = elf.ptGnuRelroPMemsz === null ? 0 : elf.ptGnuRelroPMemsz;
      resolveSocketCreateConnectAndroid(
        flutter_base,
        ptLoadRodataPMemsz,
        ptGnuRelroPVaddr,
        ptGnuRelroPMemsz,
        (getSockAddr: NativePointer) => {
          GetSockAddr_func_addr = getSockAddr;
        },
      );

      // Watchdogs — verbatim from JS lines 1378-1394
      setTimeout(() => {
        if (_A_diagState.socketOverwriteCount > 0 && _A_diagState.hookEnterCount === 0) {
          _A_writeAutoDiag(
            "watchdog A: TLS activity observed (" +
              _A_diagState.socketOverwriteCount +
              " socket overwrites) but " +
              "verify_cert_chain never entered — hook is on the wrong function",
            fm,
          );
        }
      }, 15000);
      setTimeout(() => {
        if (
          _A_diagState.hookEnterCount >= 5 &&
          _A_diagState.hookRetvalZeroCount === 0 &&
          _A_diagState.hookRetvalOneCount === _A_diagState.hookEnterCount
        ) {
          _A_writeAutoDiag(
            "watchdog B: hook fired " +
              _A_diagState.hookEnterCount +
              " times, all returned 1 — either wrong sibling or Dart-side pinning",
            fm,
          );
        }
      }, 20000);
    } else if (Process.platform === "darwin") {
      const macho = parseMachO(flutter_base);
      void macho; // iOS scan path uses the parsed offsets via scanMemoryIOSHandshake;
      // the iOS scan code in src/socket-redirect.ts is preserved verbatim and
      // explicitly untested on recent Flutter iOS builds.
      verify_cert_chain_strategy = "replace-return-0";
    }

    // 5. Hook polling — verbatim from JS lines 1396-1430.
    const getSockPoll = setInterval(() => {
      if (GetSockAddr_func_addr != null) {
        console.log("[*] Hook GetSockAddr function");
        hookGetSockAddr(GetSockAddr_func_addr, sockaddrSlot, params.proxyIp, params.proxyPort);
        clearInterval(getSockPoll);
      }
    }, 0);

    const verifyPoll = setInterval(() => {
      if (
        verify_cert_chain_strategy === "attach-replace-1" &&
        verify_cert_chain_func_addr != null
      ) {
        console.log("[*] Hook verify_cert_chain function (attach + retval.replace(1))");
        hookVerifyCertChainAttach(verify_cert_chain_func_addr);
        clearInterval(verifyPoll);
      } else if (
        verify_cert_chain_strategy === "replace-return-0" &&
        verify_peer_cert_func_addr != null
      ) {
        console.log("[*] Hook verify_peer_cert function (Interceptor.replace -> 0)");
        hookVerifyPeerCertReplace(verify_peer_cert_func_addr);
        clearInterval(verifyPoll);
      }
    }, 0);

    setTimeout(() => {
      clearInterval(verifyPoll);
    }, 10000);
  };

  awaitForCondition(init);
}
