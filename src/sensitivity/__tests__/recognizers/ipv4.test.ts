import { describe, it, expect } from "vitest";
import { createIPv4Recognizer } from "../../recognizers/ipv4.js";

describe("createIPv4Recognizer", () => {
  const r = createIPv4Recognizer();

  it("has correct metadata", () => {
    expect(r.name).toBe("ipv4");
    expect(r.data_class).toBe("internal");
    expect(r.default_confidence).toBe(0.5);
  });

  it("detects standard IPv4", () => {
    const matches = r.detect("Server at 192.168.1.100");
    expect(matches).toHaveLength(1);
    expect(matches[0].value).toBe("192.168.1.100");
  });

  it("detects loopback", () => {
    const matches = r.detect("localhost 127.0.0.1");
    expect(matches).toHaveLength(1);
  });

  it("detects boundary values", () => {
    const matches = r.detect("0.0.0.0 and 255.255.255.255");
    expect(matches).toHaveLength(2);
  });

  it("rejects invalid octets", () => {
    expect(r.detect("999.999.999.999")).toHaveLength(0);
    expect(r.detect("256.1.1.1")).toHaveLength(0);
  });

  it("provides pattern_matched signal", () => {
    const matches = r.detect("10.0.0.1");
    expect(matches[0].signals?.pattern_matched).toBe(true);
  });
});
