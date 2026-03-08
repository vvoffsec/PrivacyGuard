import { describe, it, expect } from "vitest";
import { apiSuccess, apiError } from "../result.js";

describe("apiSuccess", () => {
  it("returns ok: true", () => {
    const result = apiSuccess("data");
    expect(result.ok).toBe(true);
  });

  it("includes data", () => {
    const result = apiSuccess({ foo: "bar" });
    expect(result.data).toEqual({ foo: "bar" });
  });

  it("returns a frozen object", () => {
    const result = apiSuccess("data");
    expect(Object.isFrozen(result)).toBe(true);
  });

  it("works with null data", () => {
    const result = apiSuccess(null);
    expect(result.ok).toBe(true);
    expect(result.data).toBeNull();
  });

  it("works with complex data", () => {
    const result = apiSuccess({ nested: { value: 42 } });
    expect(result.data).toEqual({ nested: { value: 42 } });
  });
});

describe("apiError", () => {
  it("returns ok: false", () => {
    const result = apiError("ERR", "message");
    expect(result.ok).toBe(false);
  });

  it("includes error code and message", () => {
    const result = apiError("NOT_FOUND", "Not found");
    expect(result.error.code).toBe("NOT_FOUND");
    expect(result.error.message).toBe("Not found");
  });

  it("returns a frozen object", () => {
    const result = apiError("ERR", "msg");
    expect(Object.isFrozen(result)).toBe(true);
  });

  it("returns a frozen error body", () => {
    const result = apiError("ERR", "msg");
    expect(Object.isFrozen(result.error)).toBe(true);
  });

  it("includes details when provided", () => {
    const details = { field: "test" };
    const result = apiError("ERR", "msg", details);
    expect(result.error.details).toEqual({ field: "test" });
  });

  it("omits details when not provided", () => {
    const result = apiError("ERR", "msg");
    expect(result.error.details).toBeUndefined();
  });

  it("discriminates from success via ok field", () => {
    const success = apiSuccess("data");
    const error = apiError("ERR", "msg");
    expect(success.ok).not.toBe(error.ok);
  });
});
