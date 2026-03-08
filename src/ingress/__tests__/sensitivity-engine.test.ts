import { describe, it, expect } from "vitest";
import { createPatternSensitivityEngine } from "../sensitivity-engine.js";

describe("createPatternSensitivityEngine", () => {
  const engine = createPatternSensitivityEngine();

  describe("email detection", () => {
    it("detects email addresses", () => {
      const result = engine.scan("Contact us at user@example.com for info");
      expect(result.entities).toHaveLength(1);
      expect(result.entities[0].type).toBe("email");
      expect(result.entities[0].confidence).toBe(0.9);
    });

    it("detects multiple email addresses", () => {
      const result = engine.scan("Email alice@test.com or bob@test.org");
      expect(result.entities).toHaveLength(2);
    });

    it("sets pii data class for emails", () => {
      const result = engine.scan("user@example.com");
      expect(result.data_classes).toContain("pii");
    });

    it("adds contains_pii taint flag", () => {
      const result = engine.scan("user@example.com");
      expect(result.taint_flags).toContain("contains_pii");
    });
  });

  describe("phone number detection", () => {
    it("detects US phone with parentheses", () => {
      const result = engine.scan("Call (555) 123-4567");
      expect(result.entities.some((e) => e.type === "phone")).toBe(true);
    });

    it("detects US phone with dashes", () => {
      const result = engine.scan("Call 555-123-4567");
      expect(result.entities.some((e) => e.type === "phone")).toBe(true);
    });

    it("detects US phone with +1 prefix", () => {
      const result = engine.scan("Call +1-555-123-4567");
      expect(result.entities.some((e) => e.type === "phone")).toBe(true);
    });
  });

  describe("SSN detection", () => {
    it("detects SSN pattern", () => {
      const result = engine.scan("SSN: 123-45-6789");
      expect(result.entities.some((e) => e.type === "ssn")).toBe(true);
    });

    it("rejects invalid SSN area 000", () => {
      const result = engine.scan("Number: 000-12-3456");
      expect(result.entities.some((e) => e.type === "ssn")).toBe(false);
    });

    it("rejects invalid SSN area 666", () => {
      const result = engine.scan("Number: 666-12-3456");
      expect(result.entities.some((e) => e.type === "ssn")).toBe(false);
    });

    it("rejects invalid SSN area 900+", () => {
      const result = engine.scan("Number: 901-12-3456");
      expect(result.entities.some((e) => e.type === "ssn")).toBe(false);
    });
  });

  describe("credit card detection", () => {
    it("detects valid Visa card number", () => {
      // 4111111111111111 passes Luhn
      const result = engine.scan("Card: 4111111111111111");
      expect(result.entities.some((e) => e.type === "credit_card")).toBe(true);
    });

    it("detects card with spaces", () => {
      const result = engine.scan("Card: 4111 1111 1111 1111");
      expect(result.entities.some((e) => e.type === "credit_card")).toBe(true);
    });

    it("rejects numbers failing Luhn check", () => {
      const result = engine.scan("Card: 4111111111111112");
      expect(result.entities.some((e) => e.type === "credit_card")).toBe(false);
    });
  });

  describe("API key detection", () => {
    it("detects api_key=value pattern", () => {
      const result = engine.scan("api_key=sk_test_1234567890abcdef");
      expect(result.entities.some((e) => e.type === "api_key")).toBe(true);
      expect(result.data_classes).toContain("secret");
    });

    it("detects token=value pattern", () => {
      const result = engine.scan('token="ghp_1234567890abcdefghij"');
      expect(result.entities.some((e) => e.type === "api_key")).toBe(true);
    });

    it("detects secret=value pattern", () => {
      const result = engine.scan("secret: super_secret_value_1234");
      expect(result.entities.some((e) => e.type === "api_key")).toBe(true);
    });

    it("adds contains_secret taint flag", () => {
      const result = engine.scan("api_key=sk_test_1234567890abcdef");
      expect(result.taint_flags).toContain("contains_secret");
    });
  });

  describe("AWS key detection", () => {
    it("detects AWS access key ID", () => {
      const result = engine.scan("Key: AKIAIOSFODNN7EXAMPLE");
      expect(result.entities.some((e) => e.type === "aws_access_key")).toBe(true);
    });

    it("sets credential data class for AWS keys", () => {
      const result = engine.scan("AKIAIOSFODNN7EXAMPLE");
      expect(result.data_classes).toContain("credential");
    });

    it("adds contains_secret taint for credentials", () => {
      const result = engine.scan("AKIAIOSFODNN7EXAMPLE");
      expect(result.taint_flags).toContain("contains_secret");
    });
  });

  describe("IPv4 detection", () => {
    it("detects IPv4 addresses", () => {
      const result = engine.scan("Server at 192.168.1.100");
      expect(result.entities.some((e) => e.type === "ipv4")).toBe(true);
    });

    it("sets internal data class for IPs", () => {
      const result = engine.scan("IP: 10.0.0.1");
      expect(result.data_classes).toContain("internal");
    });

    it("rejects invalid octets >255", () => {
      const result = engine.scan("Not IP: 999.999.999.999");
      expect(result.entities.some((e) => e.type === "ipv4")).toBe(false);
    });
  });

  describe("value hashing", () => {
    it("hashes detected values with sha256", () => {
      const result = engine.scan("user@example.com");
      expect(result.entities[0].value_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
    });
  });

  describe("clean content", () => {
    it("returns empty results for clean content", () => {
      const result = engine.scan("This is just regular text with no PII.");
      expect(result.entities).toHaveLength(0);
      expect(result.data_classes).toHaveLength(0);
      expect(result.taint_flags).toHaveLength(0);
    });
  });

  describe("entity spans", () => {
    it("records correct span for detected entities", () => {
      const content = "Email: user@example.com here";
      const result = engine.scan(content);
      const email = result.entities.find((e) => e.type === "email");
      expect(email).toBeDefined();
      expect(email?.span.start).toBe(7);
      expect(email?.span.end).toBe(23);
      expect(content.slice(email?.span.start, email?.span.end)).toBe("user@example.com");
    });
  });

  describe("de-duplication", () => {
    it("de-duplicates overlapping spans keeping higher confidence", () => {
      // Custom recognizers that match overlapping spans
      const engine2 = createPatternSensitivityEngine({
        recognizers: [
          {
            name: "low_conf",
            data_class: "internal",
            default_confidence: 0.3,
            detect: (content) =>
              content.includes("overlap")
                ? [{ value: "overlap", span: { start: 0, end: 7 } }]
                : [],
          },
          {
            name: "high_conf",
            data_class: "pii",
            default_confidence: 0.9,
            detect: (content) =>
              content.includes("overlap")
                ? [{ value: "overlap", span: { start: 0, end: 7 } }]
                : [],
          },
        ],
      });
      const result = engine2.scan("overlap");
      expect(result.entities).toHaveLength(1);
      expect(result.entities[0].confidence).toBe(0.9);
    });
  });

  describe("immutability", () => {
    it("returns frozen result", () => {
      const result = engine.scan("user@example.com");
      expect(Object.isFrozen(result)).toBe(true);
    });
  });
});
