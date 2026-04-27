/**
 * SSL hook installers.
 *
 * Strict-verbatim port from flutter-ssl-bypass.js:
 *   - hookVerifyCertChainAttach (lines 1177-1196)
 *   - hookVerifyPeerCertReplace (lines 1198-1205)
 *
 * Forced drift from JS form: JS reads `verify_cert_chain_func_addr` /
 * `verify_peer_cert_func_addr` from module globals. TS port accepts the
 * addresses as function arguments.
 *
 * Discipline: every `Interceptor.attach` callback uses `function (args) {}`
 * form, NOT arrow functions. The `Interceptor.replace` site uses a verbatim
 * `new NativeCallback(function () { ... }, "int", [...])` — preserved as JS.
 */

import "./types/globals";
import { _A_diagState } from "./log";

/**
 * Hook `ssl_crypto_x509_session_verify_cert_chain` (returns bool —
 * true=valid). Force retval 0 → 1 on return. Hook trace logs match the JS
 * source-of-truth byte-for-byte after parity-normalize so the JS-vs-TS
 * parity diff can confirm behavior.
 */
export function hookVerifyCertChainAttach(verifyCertChainAddr: NativePointer): void {
  Interceptor.attach(verifyCertChainAddr, {
    onEnter: function (args) {
      _A_diagState.hookEnterCount++;
      console.log(
        "[trace] verify_cert_chain ENTER  arg0=" +
          args[0] +
          "  arg1=" +
          args[1] +
          "  arg2=" +
          args[2],
      );
    },
    onLeave: function (retval) {
      const v = retval.toInt32();
      if (v === 0) _A_diagState.hookRetvalZeroCount++;
      else if (v === 1) _A_diagState.hookRetvalOneCount++;
      console.log("[trace] verify_cert_chain LEAVE  retval=" + v);
      if (v === 0) {
        console.log("[*] verify cert bypass (return 0 -> 1)");
        retval.replace(ptr(0x1));
      }
    },
  });
}

/**
 * Replace `ssl_verify_peer_cert` (enum — ssl_verify_ok = 0) with
 * `mov w0, #0; ret`. Verbatim port of JS lines 1198-1205.
 */
export function hookVerifyPeerCertReplace(verifyPeerCertAddr: NativePointer): void {
  Interceptor.replace(
    verifyPeerCertAddr,
    new NativeCallback(
      function () {
        console.log("[*] verify peer cert bypass (return 0 = ssl_verify_ok)");
        return 0;
      },
      "int",
      ["pointer", "int"],
    ),
  );
}
