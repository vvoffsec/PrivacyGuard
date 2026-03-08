import { describe, it, expect } from "vitest";
import { DataClassSchema, highestDataClass, isAtLeast } from "../data-class.js";

describe("DataClassSchema", () => {
  it("accepts valid data classes", () => {
    const valid = ["public", "internal", "confidential", "restricted", "pii", "secret", "credential"];
    for (const dc of valid) {
      expect(DataClassSchema.parse(dc)).toBe(dc);
    }
  });

  it("rejects invalid data class", () => {
    expect(() => DataClassSchema.parse("top_secret")).toThrow();
  });
});

describe("highestDataClass", () => {
  it("returns public for empty array", () => {
    expect(highestDataClass([])).toBe("public");
  });

  it("returns the single element for a singleton", () => {
    expect(highestDataClass(["pii"])).toBe("pii");
  });

  it("returns the highest from a mixed array", () => {
    expect(highestDataClass(["public", "confidential", "pii", "internal"])).toBe("pii");
  });

  it("treats secret and credential as equal (both ordinal 5)", () => {
    // When both are present, whichever appears first at ordinal 5 wins
    const result = highestDataClass(["secret", "credential"]);
    expect(["secret", "credential"]).toContain(result);
  });

  it("secret outranks pii", () => {
    expect(highestDataClass(["pii", "secret"])).toBe("secret");
  });

  it("credential outranks restricted", () => {
    expect(highestDataClass(["restricted", "credential"])).toBe("credential");
  });
});

describe("isAtLeast", () => {
  it("public is at least public", () => {
    expect(isAtLeast("public", "public")).toBe(true);
  });

  it("secret is at least pii", () => {
    expect(isAtLeast("secret", "pii")).toBe(true);
  });

  it("public is not at least internal", () => {
    expect(isAtLeast("public", "internal")).toBe(false);
  });

  it("credential is at least secret (same ordinal)", () => {
    expect(isAtLeast("credential", "secret")).toBe(true);
  });

  it("secret is at least credential (same ordinal)", () => {
    expect(isAtLeast("secret", "credential")).toBe(true);
  });

  it("pii is not at least secret", () => {
    expect(isAtLeast("pii", "secret")).toBe(false);
  });
});
