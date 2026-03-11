import { describe, expect, test } from "bun:test";

describe("package exports", () => {
  test("exports the public API from the root entrypoint", async () => {
    const mod = await import("tanstack-utils");

    expect(mod.Honeypot).toBeDefined();
    expect(mod.SpamError).toBeDefined();
    expect(mod.HoneypotInputs).toBeDefined();
    expect(mod.HoneypotProvider).toBeDefined();
  });

  test("exports the server API from the server entrypoint", async () => {
    const mod = await import("tanstack-utils/server");

    expect(mod.Honeypot).toBeDefined();
    expect(mod.SpamError).toBeDefined();
  });

  test("exports the React API from the React entrypoint", async () => {
    const mod = await import("tanstack-utils/react");

    expect(mod.HoneypotInputs).toBeDefined();
    expect(mod.HoneypotProvider).toBeDefined();
  });

  test("exposes built entrypoints in dist", async () => {
    const [root, server, react] = await Promise.all([
      import("../dist/honeypot.js"),
      import("../dist/server.js"),
      import("../dist/react.js"),
    ]);

    expect(root.Honeypot).toBeDefined();
    expect(server.SpamError).toBeDefined();
    expect(react.HoneypotInputs).toBeDefined();
  });
});
