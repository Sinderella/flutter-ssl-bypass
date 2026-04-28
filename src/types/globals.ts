/**
 * Frida runtime globals not declared by @types/frida-gum@19.0.2.
 *
 * Why this is a `.ts` file (not `.d.ts`): frida-compile's internal compiler
 * does not pick up ambient `.d.ts` files. Imported as a side effect from
 * src/main.ts and src/log.ts so the bundler emits the declarations.
 *
 * `parameters` is intentionally NOT declared here. Frida CLI does not populate
 * `globalThis.parameters` — `-P '{...}'` is delivered via the
 * `rpc.exports.init(stage, parameters)` RPC method (see src/main.ts and
 * frida-tools/repl.py:308). `rpc` itself is fully typed by @types/frida-gum.
 *
 * The `console` redeclaration is a workaround: Frida's embedded V8/QuickJS
 * provides `console.log` at runtime but neither @types/frida-gum nor our
 * locked-down `types: ["frida-gum"]` tsconfig surface declares it.
 */

/**
 * Minimal shape for Frida's `Java` bridge. Only the surface used by
 * flutter-ssl-bypass.js is captured (per the strict-verbatim rule we type
 * exactly what is called: `Java.available`, `Java.use`).
 */
interface FridaJavaUse {
  // biome-ignore lint/suspicious/noExplicitAny: untyped Java reflection surface
  currentApplication(): any;
}
interface FridaJavaBridge {
  available: boolean;
  use(className: string): FridaJavaUse;
}

/**
 * Minimal shape for Frida's `ObjC` bridge. Only `ObjC.available` and
 * `ObjC.classes.NSBundle` are touched by the JS source-of-truth.
 */
// biome-ignore lint/suspicious/noExplicitAny: untyped Objective-C class surface
type FridaObjCClassMember = any;
interface FridaObjCBridge {
  available: boolean;
  classes: Record<string, FridaObjCClassMember>;
}

declare global {
  // biome-ignore lint/suspicious/noVar: Frida runtime global, declared as `var` for hoisting consistency
  var console: {
    log: (...args: unknown[]) => void;
    warn: (...args: unknown[]) => void;
    error: (...args: unknown[]) => void;
  };

  // Frida bridge globals (frida-java-bridge / frida-objc-bridge are loaded by
  // the runtime but not part of @types/frida-gum). We declare the minimal
  // surface the agent uses. `noVar` doesn't fire on ambient `declare global`
  // bindings so no biome-ignore comment is required here.
  var Java: FridaJavaBridge;
  var ObjC: FridaObjCBridge;

  // setInterval / clearInterval / setTimeout are Frida-runtime-provided but
  // not declared by @types/frida-gum.
  function setInterval(fn: () => void, ms: number): number;
  function clearInterval(handle: number): void;
  function setTimeout(fn: () => void, ms: number): number;
}

export {};
