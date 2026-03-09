import { describe, it, expect } from "vitest";
import { createPhoneRecognizer } from "../../recognizers/phone.js";

describe("createPhoneRecognizer", () => {
  const r = createPhoneRecognizer();

  it("has correct metadata", () => {
    expect(r.name).toBe("phone");
    expect(r.data_class).toBe("pii");
    expect(r.default_confidence).toBe(0.7);
  });

  it("detects phone with parentheses", () => {
    const matches = r.detect("Call (555) 123-4567");
    expect(matches).toHaveLength(1);
  });

  it("detects phone with dashes", () => {
    const matches = r.detect("555-123-4567");
    expect(matches).toHaveLength(1);
  });

  it("detects phone with +1 prefix", () => {
    const matches = r.detect("+1-555-123-4567");
    expect(matches).toHaveLength(1);
  });

  it("detects phone with dots", () => {
    const matches = r.detect("555.123.4567");
    expect(matches).toHaveLength(1);
  });

  it("rejects too few digits", () => {
    expect(r.detect("555-1234")).toHaveLength(0);
  });

  it("provides format_validated signal", () => {
    const matches = r.detect("555-123-4567");
    expect(matches[0].signals?.format_validated).toBe(true);
  });
});
