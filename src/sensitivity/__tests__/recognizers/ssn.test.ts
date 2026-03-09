import { describe, it, expect } from "vitest";
import { createSSNRecognizer } from "../../recognizers/ssn.js";

describe("createSSNRecognizer", () => {
  const r = createSSNRecognizer();

  it("has correct metadata", () => {
    expect(r.name).toBe("ssn");
    expect(r.data_class).toBe("pii");
    expect(r.default_confidence).toBe(0.85);
  });

  it("detects valid SSN", () => {
    const matches = r.detect("SSN: 123-45-6789");
    expect(matches).toHaveLength(1);
    expect(matches[0].value).toBe("123-45-6789");
  });

  it("rejects area 000", () => {
    expect(r.detect("000-12-3456")).toHaveLength(0);
  });

  it("rejects area 666", () => {
    expect(r.detect("666-12-3456")).toHaveLength(0);
  });

  it("rejects area 900+", () => {
    expect(r.detect("901-12-3456")).toHaveLength(0);
    expect(r.detect("999-12-3456")).toHaveLength(0);
  });

  it("accepts area 899", () => {
    const matches = r.detect("899-12-3456");
    expect(matches).toHaveLength(1);
  });

  it("provides format_validated signal", () => {
    const matches = r.detect("123-45-6789");
    expect(matches[0].signals?.format_validated).toBe(true);
  });

  it("does not match without dashes", () => {
    expect(r.detect("123456789")).toHaveLength(0);
  });
});
