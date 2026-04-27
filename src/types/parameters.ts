/**
 * Parameters API surface.
 *
 * The `parameters` global is declared in src/types/globals.ts as `unknown`.
 * `validateParameters` is the runtime gate that converts the injected payload
 * into a typed `ProxyParameters` object — and throws BEFORE any hook is
 * installed. The error message format `[!] Parameters API rejected: <reason>`
 * is part of the documented user-facing contract.
 *
 * Leaf modules (`src/socket-redirect.ts`) receive `proxyIp` / `proxyPort` as
 * resolved function arguments — they never touch the global directly.
 */

export interface ProxyParameters {
  proxyIp: string;
  proxyPort: number;
}

/**
 * Validate the Frida-injected `parameters` global. Throws a descriptive Error
 * with the literal prefix `[!] Parameters API rejected:` on any defect —
 * validation runs BEFORE any hook installation.
 *
 * @param raw - the value of `globalThis.parameters` (typed as `unknown`).
 */
export function validateParameters(raw: unknown): ProxyParameters {
  if (raw === null || raw === undefined || typeof raw !== "object") {
    throw new Error(
      "[!] Parameters API rejected: expected object with {proxyIp, proxyPort} (-P '{...}')",
    );
  }
  const obj = raw as Record<string, unknown>;
  const ip = obj.proxyIp;
  const port = obj.proxyPort;
  if (typeof ip !== "string" || ip.length === 0) {
    throw new Error("[!] Parameters API rejected: proxyIp must be a non-empty string");
  }
  if (typeof port !== "number" || !Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("[!] Parameters API rejected: proxyPort must be an integer in [1, 65535]");
  }
  return { proxyIp: ip, proxyPort: port };
}
