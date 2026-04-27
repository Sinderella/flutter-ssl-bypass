/**
 * Anchor-resolution result types.
 *
 * `AnchorResolution` is the shape returned by `resolveVerifyCertChain` /
 * `resolveVerifyPeerCert` in src/dart-resolver.ts, mirroring the JS objects
 * `{ addr, size, via }` (flutter-ssl-bypass.js lines 887, 898, 964, 994, 1005).
 *
 * `GroundTruthRange` mirrors the GROUND_TRUTH table at JS line 558.
 */

export interface AnchorResolution {
  addr: NativePointer;
  size: number;
  via: string;
}

export interface AnchorCandidate extends AnchorResolution {
  score?: number;
  validation?: AnchorValidation;
}

export interface AnchorValidation {
  ok: boolean;
  signals: number;
  reasons: string[];
}

export interface GroundTruthRange {
  min: number;
}

export interface GroundTruthTable {
  ssl_x509_cc_string_hits: GroundTruthRange;
  ssl_x509_cc_xrefs: GroundTruthRange;
  ssl_x509_cc_stub_callers: GroundTruthRange;
}
