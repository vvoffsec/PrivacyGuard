import { describe, it, expect } from "vitest";
import { createAwsKeyRecognizer } from "../../recognizers/aws-key.js";

describe("createAwsKeyRecognizer", () => {
  const r = createAwsKeyRecognizer();

  it("has correct metadata", () => {
    expect(r.name).toBe("aws_access_key");
    expect(r.data_class).toBe("credential");
    expect(r.default_confidence).toBe(0.95);
  });

  it("detects AWS access key", () => {
    const matches = r.detect("AKIAIOSFODNN7EXAMPLE");
    expect(matches).toHaveLength(1);
    expect(matches[0].value).toBe("AKIAIOSFODNN7EXAMPLE");
  });

  it("detects key in context", () => {
    const matches = r.detect("aws_access_key_id = AKIAIOSFODNN7EXAMPLE");
    expect(matches).toHaveLength(1);
  });

  it("does not match non-AKIA prefix", () => {
    expect(r.detect("ASIAISAMPLEKEYID1234")).toHaveLength(0);
  });

  it("does not match too-short key", () => {
    expect(r.detect("AKIAIOSFODNN7EXA")).toHaveLength(0);
  });

  it("provides format_validated signal", () => {
    const matches = r.detect("AKIAIOSFODNN7EXAMPLE");
    expect(matches[0].signals?.format_validated).toBe(true);
  });
});
