import { describe, it, expect } from "vitest";
import { createEmailRecognizer } from "../../recognizers/email.js";

describe("createEmailRecognizer", () => {
  const r = createEmailRecognizer();

  it("has correct metadata", () => {
    expect(r.name).toBe("email");
    expect(r.data_class).toBe("pii");
    expect(r.default_confidence).toBe(0.9);
  });

  it("detects a simple email", () => {
    const matches = r.detect("user@example.com");
    expect(matches).toHaveLength(1);
    expect(matches[0].value).toBe("user@example.com");
    expect(matches[0].span).toEqual({ start: 0, end: 16 });
  });

  it("detects emails with subdomains", () => {
    const matches = r.detect("user@mail.example.co.uk");
    expect(matches).toHaveLength(1);
  });

  it("detects multiple emails", () => {
    const matches = r.detect("a@b.com and c@d.org");
    expect(matches).toHaveLength(2);
  });

  it("detects emails with plus addressing", () => {
    const matches = r.detect("user+tag@example.com");
    expect(matches).toHaveLength(1);
    expect(matches[0].value).toBe("user+tag@example.com");
  });

  it("provides format_validated signal", () => {
    const matches = r.detect("user@example.com");
    expect(matches[0].signals?.format_validated).toBe(true);
  });

  it("returns empty for no emails", () => {
    expect(r.detect("no email here")).toHaveLength(0);
  });

  it("does not match incomplete emails", () => {
    expect(r.detect("user@")).toHaveLength(0);
    expect(r.detect("@example.com")).toHaveLength(0);
  });
});
