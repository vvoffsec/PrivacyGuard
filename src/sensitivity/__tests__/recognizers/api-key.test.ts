import { describe, it, expect } from "vitest";
import { createApiKeyRecognizer } from "../../recognizers/api-key.js";

describe("createApiKeyRecognizer", () => {
  const r = createApiKeyRecognizer();

  it("has correct metadata", () => {
    expect(r.name).toBe("api_key");
    expect(r.data_class).toBe("secret");
    expect(r.default_confidence).toBe(0.8);
  });

  it("detects api_key=value", () => {
    const matches = r.detect("api_key=sk_test_1234567890abcdef");
    expect(matches).toHaveLength(1);
  });

  it("detects token=value", () => {
    const matches = r.detect('token="ghp_1234567890abcdefghij"');
    expect(matches).toHaveLength(1);
  });

  it("detects secret: value", () => {
    const matches = r.detect("secret: super_secret_value_1234");
    expect(matches).toHaveLength(1);
  });

  it("detects api-key=value", () => {
    const matches = r.detect("api-key=abcdefgh12345678");
    expect(matches).toHaveLength(1);
  });

  it("does not match password=value", () => {
    const matches = r.detect("password=mysecretpass123");
    expect(matches).toHaveLength(0);
  });

  it("does not match passwd=value", () => {
    const matches = r.detect("passwd=mysecretpass123");
    expect(matches).toHaveLength(0);
  });

  it("provides format_validated and context_validated signals", () => {
    const matches = r.detect("api_key=sk_test_1234567890abcdef");
    expect(matches[0].signals?.format_validated).toBe(true);
    expect(matches[0].signals?.context_validated).toBe(true);
  });

  it("returns empty for no matches", () => {
    expect(r.detect("just some text")).toHaveLength(0);
  });
});
