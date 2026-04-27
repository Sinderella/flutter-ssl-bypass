/**
 * Resolve `verify_cert_chain` (primary) and `verify_peer_cert` (fallback)
 * for the Android arm64 path.
 *
 * Strict-verbatim port from flutter-ssl-bypass.js lines 836-1015.
 *
 * Forced drift from JS form: JS writes to module-level globals
 * (`verify_cert_chain_func_addr`, `verify_peer_cert_func_addr`,
 * `verify_cert_chain_strategy`). TS form returns an `AnchorResolution | null`
 * and lets `src/main.ts` decide which strategy to dispatch.
 *
 * Discipline: every critical resolve goes through `mustResolve`; pointer
 * arithmetic uses `.add` / `.sub` / `.equals` / `.compare` only.
 */

import "./types/globals";
import {
  _A_assertRange,
  _A_findAdrpAddXrefs,
  _A_findAllStringsInModule,
  _A_findBlCallers,
  _A_functionSize,
  _A_isStubAtAdrp,
  _A_scoreAsVerifyCertChain,
  _A_validateVerifyCertChainCandidate,
  _A_walkToPrologue,
  GROUND_TRUTH,
} from "./anchor-chain";
import { _A_diagState } from "./log";
import type { AnchorResolution } from "./types/anchor";

interface AnchorCandidateInternal {
  addr: NativePointer;
  size: number;
  via: string;
  score?: number;
  validation?: { ok: boolean; signals: number; reasons: string[] };
}

/**
 * Try to find ssl_crypto_x509_session_verify_cert_chain in libflutter.so.
 *
 * Strategy 1 (stub-caller): find the ssl_x509.cc __FILE__ string, find its
 *   ADRP+ADD xrefs. For each xref, walk back to the enclosing function. If
 *   the enclosing function is a tiny stub (<= 0x20 bytes), enumerate the
 *   BL callers of the stub and pick the largest one.
 *
 * Strategy 2 (direct ssl_client): register-agnostic ADRP+ADD scan for the
 *   ssl_client string, walk back to prologue, accept only if function size
 *   is > 0x100 bytes (skips the new-build string dispatcher).
 */
export function resolveVerifyCertChain(mod: Module): AnchorResolution | null {
  // --- Strategy 1: ssl_x509.cc path → stub → biggest caller ---
  const ssl_x509_paths = _A_findAllStringsInModule(
    mod,
    "../../../flutter/third_party/boringssl/src/ssl/ssl_x509.cc",
  );
  console.log("[anchor] ssl_x509.cc string hits: " + ssl_x509_paths.length);
  _A_assertRange(
    "ssl_x509.cc_string_hits",
    ssl_x509_paths.length,
    GROUND_TRUTH.ssl_x509_cc_string_hits,
  );

  const candidates: AnchorCandidateInternal[] = [];
  let sslX509StubAddr: NativePointer | null = null;
  let totalXrefs = 0;
  let totalStubCallers = 0;

  for (let i = 0; i < ssl_x509_paths.length; i++) {
    const strAddr = ssl_x509_paths[i];
    if (strAddr === undefined) continue;
    const xrefs = _A_findAdrpAddXrefs(mod, strAddr);
    totalXrefs += xrefs.length;
    console.log("[anchor]   " + strAddr + " -> " + xrefs.length + " ADRP+ADD xref(s)");
    for (let j = 0; j < xrefs.length; j++) {
      const xref = xrefs[j];
      if (xref === undefined) continue;
      const isStubHere = _A_isStubAtAdrp(xref);
      console.log("[anchor]     xref @ " + xref + "  isStub=" + isStubHere);

      if (isStubHere) {
        if (!sslX509StubAddr) sslX509StubAddr = xref;
        const blSites = _A_findBlCallers(mod, xref);
        totalStubCallers += blSites.length;
        console.log("[anchor]       stub -> " + blSites.length + " BL caller(s)");
        for (let k = 0; k < blSites.length; k++) {
          const bl = blSites[k];
          if (bl === undefined) continue;
          const callerPrologue = _A_walkToPrologue(bl);
          if (!callerPrologue) continue;
          const callerSize = _A_functionSize(callerPrologue);
          if (callerSize >= 0x80) {
            candidates.push({
              addr: callerPrologue,
              size: callerSize,
              via: "ssl_x509.cc-stub",
            });
          }
        }
        continue;
      }

      const prologue = _A_walkToPrologue(xref);
      if (!prologue) {
        console.log("[anchor]       (no prologue within 0x2000)");
        continue;
      }
      const size = _A_functionSize(prologue);
      if (size >= 0x100) {
        candidates.push({ addr: prologue, size, via: "ssl_x509.cc-direct" });
      }
    }
  }

  _A_assertRange("ssl_x509.cc_xrefs", totalXrefs, GROUND_TRUTH.ssl_x509_cc_xrefs);
  if (sslX509StubAddr) {
    _A_assertRange(
      "ssl_x509.cc_stub_callers",
      totalStubCallers,
      GROUND_TRUTH.ssl_x509_cc_stub_callers,
    );
  }

  // Dedupe by address
  const seen: Record<string, boolean> = {};
  const unique: AnchorCandidateInternal[] = [];
  for (let m = 0; m < candidates.length; m++) {
    const c = candidates[m];
    if (c === undefined) continue;
    const key = c.addr.toString();
    if (!seen[key]) {
      seen[key] = true;
      unique.push(c);
    }
  }

  for (let u = 0; u < unique.length; u++) {
    const c = unique[u];
    if (c === undefined) continue;
    c.score = _A_scoreAsVerifyCertChain(c.addr, c.size);
    c.validation = _A_validateVerifyCertChainCandidate(c.addr, c.size, sslX509StubAddr);
  }

  console.log("[anchor] ssl_x509.cc candidates:");
  const candidateLines: string[] = [];
  for (let u2 = 0; u2 < unique.length; u2++) {
    const c2 = unique[u2];
    if (c2 === undefined || c2.validation === undefined) continue;
    const line =
      "  " +
      c2.addr +
      "  size=0x" +
      c2.size.toString(16) +
      "  score=" +
      c2.score +
      "  signals=" +
      c2.validation.signals +
      "  via=" +
      c2.via +
      "  [" +
      c2.validation.reasons.join(" ") +
      "]";
    console.log(line);
    candidateLines.push(line);
  }
  _A_diagState.candidatesDump = candidateLines.join("\n");

  const qualified = unique.filter((c) => c.validation !== undefined && c.validation.ok);
  if (qualified.length) {
    qualified.sort((a, b) => {
      const sa = a.score ?? 0;
      const sb = b.score ?? 0;
      if (sb !== sa) return sb - sa;
      const va = a.validation?.signals ?? 0;
      const vb = b.validation?.signals ?? 0;
      if (vb !== va) return vb - va;
      return b.size - a.size;
    });
    const winner = qualified[0];
    if (winner !== undefined) {
      return { addr: winner.addr, size: winner.size, via: winner.via };
    }
  }

  console.warn(
    "[anchor] No ssl_x509.cc candidate passed validation — falling back to weaker strategies.",
  );
  console.warn(
    "[anchor] This usually means: (a) wrong binary; (b) new compiler codegen; (c) a decoder regression.",
  );

  // --- Strategy 2: ssl_client direct xref with function-size filter ---
  const ssl_client_addrs = _A_findAllStringsInModule(mod, "ssl_client");
  for (let n = 0; n < ssl_client_addrs.length; n++) {
    const ssl_client_addr = ssl_client_addrs[n];
    if (ssl_client_addr === undefined) continue;
    const xrefs2 = _A_findAdrpAddXrefs(mod, ssl_client_addr);
    for (let q = 0; q < xrefs2.length; q++) {
      const xref = xrefs2[q];
      if (xref === undefined) continue;
      const pro = _A_walkToPrologue(xref);
      if (!pro) continue;
      const sz = _A_functionSize(pro);
      if (sz >= 0x100) {
        return { addr: pro, size: sz, via: "ssl_client-direct" };
      }
    }
  }

  return null;
}

/**
 * Fallback: resolve ssl_verify_peer_cert via handshake.cc path xref.
 * Uses Interceptor.replace semantics (return 0 = ssl_verify_ok).
 *
 * Verbatim port from JS lines 972-1010.
 */
export function resolveVerifyPeerCert(mod: Module): AnchorResolution | null {
  const handshake_paths = _A_findAllStringsInModule(
    mod,
    "../../../flutter/third_party/boringssl/src/ssl/handshake.cc",
  );
  let best: AnchorResolution | null = null;
  for (let i = 0; i < handshake_paths.length; i++) {
    const path = handshake_paths[i];
    if (path === undefined) continue;
    const xrefs = _A_findAdrpAddXrefs(mod, path);
    for (let j = 0; j < xrefs.length; j++) {
      const xref = xrefs[j];
      if (xref === undefined) continue;

      if (_A_isStubAtAdrp(xref)) {
        const blSites = _A_findBlCallers(mod, xref);
        for (let k = 0; k < blSites.length; k++) {
          const bl = blSites[k];
          if (bl === undefined) continue;
          const cp = _A_walkToPrologue(bl);
          if (!cp) continue;
          const cs = _A_functionSize(cp);
          if (cs >= 0x80 && (!best || cs > best.size)) {
            best = { addr: cp, size: cs, via: "handshake.cc-stub" };
          }
        }
        continue;
      }

      const pro = _A_walkToPrologue(xref);
      if (!pro) continue;
      const sz = _A_functionSize(pro);
      if (sz >= 0x100) {
        if (!best || sz > best.size) best = { addr: pro, size: sz, via: "handshake.cc-direct" };
      }
    }
  }
  return best;
}
