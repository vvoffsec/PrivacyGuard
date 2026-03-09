import { describe, it, expect } from "vitest";
import { computeConfidence } from "../confidence.js";

describe("computeConfidence", () => {
  it("caps at 0.7 when no signals", () => {
    expect(computeConfidence(0.9)).toBe(0.7);
    expect(computeConfidence(0.5)).toBe(0.5);
  });

  it("caps at 0.7 when signals have no validations", () => {
    expect(computeConfidence(0.9, { pattern_matched: true })).toBe(0.7);
  });

  it("boosts to max(base, 0.95) for checksum_validated", () => {
    expect(
      computeConfidence(0.9, { pattern_matched: true, checksum_validated: true }),
    ).toBe(0.95);
    expect(
      computeConfidence(0.98, { pattern_matched: true, checksum_validated: true }),
    ).toBe(0.98);
  });

  it("boosts to max(base, 0.9) for format_validated", () => {
    expect(
      computeConfidence(0.7, { pattern_matched: true, format_validated: true }),
    ).toBe(0.9);
    expect(
      computeConfidence(0.95, { pattern_matched: true, format_validated: true }),
    ).toBe(0.95);
  });

  it("boosts by +0.05 for context_validated", () => {
    expect(
      computeConfidence(0.8, { pattern_matched: true, context_validated: true }),
    ).toBe(0.85);
  });

  it("boosts by +0.05 for high entropy (>5.0)", () => {
    expect(computeConfidence(0.6, { pattern_matched: true, entropy_score: 5.5 })).toBe(
      0.65,
    );
  });

  it("does not boost for low entropy (<=5.0)", () => {
    expect(computeConfidence(0.9, { pattern_matched: true, entropy_score: 4.0 })).toBe(
      0.7,
    );
  });

  it("combines multiple boosts", () => {
    const result = computeConfidence(0.8, {
      pattern_matched: true,
      checksum_validated: true,
      context_validated: true,
      entropy_score: 5.5,
    });
    // checksum -> max(0.8, 0.95) = 0.95, +0.05 context = 1.0, +0.05 entropy -> capped at 1.0
    expect(result).toBe(1.0);
  });

  it("never exceeds 1.0", () => {
    const result = computeConfidence(0.95, {
      pattern_matched: true,
      checksum_validated: true,
      context_validated: true,
      entropy_score: 6.0,
    });
    expect(result).toBeLessThanOrEqual(1.0);
  });

  it("handles format_validated + context_validated", () => {
    const result = computeConfidence(0.7, {
      pattern_matched: true,
      format_validated: true,
      context_validated: true,
    });
    // format -> max(0.7, 0.9) = 0.9, context -> 0.9 + 0.05 = 0.95
    expect(result).toBe(0.95);
  });

  it("returns base when base < 0.7 and no signals", () => {
    expect(computeConfidence(0.3)).toBe(0.3);
  });
});
