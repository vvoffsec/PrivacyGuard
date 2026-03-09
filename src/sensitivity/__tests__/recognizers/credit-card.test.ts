import { describe, it, expect } from "vitest";
import { createCreditCardRecognizer, luhnCheck } from "../../recognizers/credit-card.js";

describe("luhnCheck", () => {
  it("validates known Visa number", () => {
    expect(luhnCheck("4111111111111111")).toBe(true);
  });

  it("validates known Mastercard number", () => {
    expect(luhnCheck("5500000000000004")).toBe(true);
  });

  it("rejects invalid number", () => {
    expect(luhnCheck("4111111111111112")).toBe(false);
  });

  it("validates known Amex number", () => {
    expect(luhnCheck("378282246310005")).toBe(true);
  });
});

describe("createCreditCardRecognizer", () => {
  const r = createCreditCardRecognizer();

  it("has correct metadata", () => {
    expect(r.name).toBe("credit_card");
    expect(r.data_class).toBe("pii");
    expect(r.default_confidence).toBe(0.9);
  });

  it("detects valid Visa", () => {
    const matches = r.detect("Card: 4111111111111111");
    expect(matches).toHaveLength(1);
  });

  it("detects card with spaces", () => {
    const matches = r.detect("4111 1111 1111 1111");
    expect(matches).toHaveLength(1);
  });

  it("detects card with dashes", () => {
    const matches = r.detect("4111-1111-1111-1111");
    expect(matches).toHaveLength(1);
  });

  it("rejects numbers failing Luhn", () => {
    expect(r.detect("4111111111111112")).toHaveLength(0);
  });

  it("provides checksum_validated signal", () => {
    const matches = r.detect("4111111111111111");
    expect(matches[0].signals?.checksum_validated).toBe(true);
  });
});
