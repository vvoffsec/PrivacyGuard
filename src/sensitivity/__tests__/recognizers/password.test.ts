import { describe, it, expect } from "vitest";
import { createPasswordRecognizer } from "../../recognizers/password.js";

describe("createPasswordRecognizer", () => {
  const r = createPasswordRecognizer();

  it("has correct metadata", () => {
    expect(r.name).toBe("password");
    expect(r.data_class).toBe("credential");
    expect(r.default_confidence).toBe(0.75);
  });

  it("detects password=value", () => {
    const matches = r.detect("password=mysecretpass123");
    expect(matches).toHaveLength(1);
  });

  it("detects passwd: value", () => {
    const matches = r.detect("passwd: s3cretValue!");
    expect(matches).toHaveLength(1);
  });

  it("detects pwd=value", () => {
    const matches = r.detect('pwd="hunter2"');
    expect(matches).toHaveLength(1);
  });

  it("detects pass=value", () => {
    const matches = r.detect("pass=abc123xyz");
    expect(matches).toHaveLength(1);
  });

  it("is case insensitive", () => {
    const matches = r.detect("PASSWORD=MySecret");
    expect(matches).toHaveLength(1);
  });

  it("provides context_validated signal", () => {
    const matches = r.detect("password=test123");
    expect(matches[0].signals?.context_validated).toBe(true);
  });

  it("returns empty for no passwords", () => {
    expect(r.detect("no password here")).toHaveLength(0);
  });

  it("returns empty for password without assignment", () => {
    expect(r.detect("change your password regularly")).toHaveLength(0);
  });
});
