import { describe, it, expect } from "vitest";
import { createInProcessTransport } from "../transport.js";
import { apiSuccess, apiError } from "../result.js";
import type { ApiRoute, ApiHandler } from "../transport.js";

function createTestHandlers(): Record<ApiRoute, ApiHandler> {
  return {
    "ingress.evaluate": () => apiSuccess({ result: "ingress" }),
    "tool.authorize": () => apiSuccess({ result: "tool" }),
    "memory.write": () => apiSuccess({ result: "memory" }),
    "decision.explain": () => apiSuccess({ result: "explain" }),
  };
}

describe("createInProcessTransport", () => {
  it("returns a frozen router", () => {
    const router = createInProcessTransport(createTestHandlers());
    expect(Object.isFrozen(router)).toBe(true);
  });

  it("routes to ingress.evaluate handler", () => {
    const router = createInProcessTransport(createTestHandlers());
    const result = router.handle("ingress.evaluate", {});
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.data).toEqual({ result: "ingress" });
    }
  });

  it("routes to tool.authorize handler", () => {
    const router = createInProcessTransport(createTestHandlers());
    const result = router.handle("tool.authorize", {});
    expect(result.ok).toBe(true);
  });

  it("routes to memory.write handler", () => {
    const router = createInProcessTransport(createTestHandlers());
    const result = router.handle("memory.write", {});
    expect(result.ok).toBe(true);
  });

  it("routes to decision.explain handler", () => {
    const router = createInProcessTransport(createTestHandlers());
    const result = router.handle("decision.explain", {});
    expect(result.ok).toBe(true);
  });

  it("returns error for unknown route", () => {
    const router = createInProcessTransport(createTestHandlers());
    const result = router.handle("unknown" as ApiRoute, {});
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("UNKNOWN_ROUTE");
    }
  });

  it("catches unhandled exceptions and returns error (fail-closed)", () => {
    const handlers = createTestHandlers();
    handlers["ingress.evaluate"] = () => {
      throw new Error("unexpected");
    };
    const router = createInProcessTransport(handlers);
    const result = router.handle("ingress.evaluate", {});
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("INTERNAL_ERROR");
      expect(result.error.message).toContain("failing closed");
    }
  });

  it("passes request data to handler", () => {
    const handlers = createTestHandlers();
    handlers["ingress.evaluate"] = (req) => apiSuccess({ received: req });
    const router = createInProcessTransport(handlers);
    const result = router.handle("ingress.evaluate", { test: true });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.data).toEqual({ received: { test: true } });
    }
  });

  it("propagates apiError results from handlers", () => {
    const handlers = createTestHandlers();
    handlers["tool.authorize"] = () => apiError("CUSTOM_ERROR", "Something went wrong");
    const router = createInProcessTransport(handlers);
    const result = router.handle("tool.authorize", {});
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("CUSTOM_ERROR");
    }
  });
});
