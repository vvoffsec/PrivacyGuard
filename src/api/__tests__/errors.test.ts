import { describe, it, expect } from "vitest";
import { ApiValidationError, ApiHandlerError } from "../errors.js";

describe("ApiValidationError", () => {
  it("has name ApiValidationError", () => {
    const error = new ApiValidationError([]);
    expect(error.name).toBe("ApiValidationError");
  });

  it("stores issues array", () => {
    const issues = [
      { path: ["field"], message: "Required", code: "invalid_type" },
    ] as never[];
    const error = new ApiValidationError(issues);
    expect(error.issues).toBe(issues);
  });

  it("includes issue count in message", () => {
    const issues = [
      { path: ["a"], message: "bad", code: "invalid_type" },
      { path: ["b"], message: "bad", code: "invalid_type" },
    ] as never[];
    const error = new ApiValidationError(issues);
    expect(error.message).toContain("2 issue(s)");
  });

  it("is an instance of Error", () => {
    const error = new ApiValidationError([]);
    expect(error).toBeInstanceOf(Error);
  });

  it("toExplanation formats issues with path and message", () => {
    const issues = [
      { path: ["input", "content"], message: "Required" },
      { path: ["agent_id"], message: "Too short" },
    ] as never[];
    const error = new ApiValidationError(issues);
    const explanation = error.toExplanation();
    expect(explanation).toContain("1. [input.content] Required");
    expect(explanation).toContain("2. [agent_id] Too short");
  });

  it("toExplanation handles empty path", () => {
    const issues = [{ path: [], message: "Invalid" }] as never[];
    const error = new ApiValidationError(issues);
    expect(error.toExplanation()).toContain("1. [] Invalid");
  });

  it("toExplanation returns empty string for no issues", () => {
    const error = new ApiValidationError([]);
    expect(error.toExplanation()).toBe("");
  });
});

describe("ApiHandlerError", () => {
  it("has name ApiHandlerError", () => {
    const error = new ApiHandlerError("NOT_FOUND", "Resource not found");
    expect(error.name).toBe("ApiHandlerError");
  });

  it("stores code", () => {
    const error = new ApiHandlerError("VALIDATION_ERROR", "Bad input");
    expect(error.code).toBe("VALIDATION_ERROR");
  });

  it("stores message", () => {
    const error = new ApiHandlerError("ERR", "Something broke");
    expect(error.message).toBe("Something broke");
  });

  it("is an instance of Error", () => {
    const error = new ApiHandlerError("ERR", "msg");
    expect(error).toBeInstanceOf(Error);
  });

  it("toExplanation returns [CODE] message format", () => {
    const error = new ApiHandlerError("NOT_FOUND", "Decision not found");
    expect(error.toExplanation()).toBe("[NOT_FOUND] Decision not found");
  });
});
