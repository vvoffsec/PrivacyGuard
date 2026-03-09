import { describe, it, expect } from "vitest";
import { createHighEntropyRecognizer } from "../../recognizers/high-entropy.js";

describe("createHighEntropyRecognizer", () => {
  const r = createHighEntropyRecognizer();

  it("has correct metadata", () => {
    expect(r.name).toBe("high_entropy_string");
    expect(r.data_class).toBe("secret");
    expect(r.default_confidence).toBe(0.6);
  });

  it("detects high-entropy key value", () => {
    const matches = r.detect("key=aB3dE6gH9jK2mN5pQ8rS1uV4wX7yZ0a");
    expect(matches).toHaveLength(1);
  });

  it("detects high-entropy token value", () => {
    const matches = r.detect("token=xY9bC2dE5fG8hI1jK4lM7nO0pQ3rS6tU");
    expect(matches).toHaveLength(1);
  });

  it("ignores low-entropy values", () => {
    const matches = r.detect("key=aaaaaaaaaaaaaaaaaaaaaaaaa");
    expect(matches).toHaveLength(0);
  });

  it("provides entropy_score signal", () => {
    const matches = r.detect("secret=aB3dE6gH9jK2mN5pQ8rS1uV4wX7yZ0a");
    expect(matches).toHaveLength(1);
    expect(matches[0].signals?.entropy_score).toBeGreaterThan(4.5);
  });

  it("respects custom threshold", () => {
    const strict = createHighEntropyRecognizer(5.0);
    const lenient = createHighEntropyRecognizer(3.0);
    const content = "secret=aB3dE6gH9jK2mN5pQ8rS1uV";
    // Lenient should find more or equal matches than strict
    expect(lenient.detect(content).length).toBeGreaterThanOrEqual(
      strict.detect(content).length,
    );
  });

  it("returns empty for no key-value patterns", () => {
    expect(r.detect("just regular text")).toHaveLength(0);
  });
});
