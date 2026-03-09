import { describe, it, expect } from "vitest";
import { createSensitivityEngine } from "../engine.js";

/**
 * Golden corpus: structured test cases covering all entity types.
 * Each case specifies input, expected entity type(s), and key properties.
 */
describe("golden corpus", () => {
  const engine = createSensitivityEngine();

  // --- Email ---
  describe("email", () => {
    const cases = [
      { input: "user@example.com", desc: "simple email" },
      {
        input: "john.doe+work@company.co.uk",
        desc: "complex email with plus and subdomain",
      },
      { input: "admin@localhost.test", desc: "admin email" },
      { input: "first.last@sub.domain.org", desc: "email with subdomain" },
      { input: "user123@example.museum", desc: "email with long TLD" },
    ];
    for (const { input, desc } of cases) {
      it(`detects ${desc}: ${input}`, () => {
        const result = engine.scan(input);
        expect(result.entities.some((e) => e.type === "email")).toBe(true);
        expect(result.data_classes).toContain("pii");
      });
    }
  });

  // --- Phone ---
  describe("phone", () => {
    const cases = [
      { input: "Call (212) 555-1234", desc: "parenthesized area code" },
      { input: "Phone: 415-555-6789", desc: "dashed" },
      { input: "+1-800-555-0199", desc: "with country code" },
      { input: "Tel: 555.123.4567", desc: "dotted" },
    ];
    for (const { input, desc } of cases) {
      it(`detects ${desc}: ${input}`, () => {
        const result = engine.scan(input);
        expect(result.entities.some((e) => e.type === "phone")).toBe(true);
      });
    }
  });

  // --- SSN ---
  describe("SSN", () => {
    const cases = [
      { input: "SSN: 123-45-6789", desc: "standard SSN" },
      { input: "Social: 456-78-9012", desc: "mid-range area" },
      { input: "Number: 001-01-0001", desc: "low area" },
    ];
    for (const { input, desc } of cases) {
      it(`detects ${desc}: ${input}`, () => {
        const result = engine.scan(input);
        expect(result.entities.some((e) => e.type === "ssn")).toBe(true);
      });
    }
  });

  // --- Credit Card ---
  describe("credit card", () => {
    const cases = [
      { input: "4111111111111111", desc: "Visa" },
      { input: "5500000000000004", desc: "Mastercard" },
      { input: "378282246310005", desc: "Amex" },
      { input: "4111 1111 1111 1111", desc: "Visa with spaces" },
      { input: "4111-1111-1111-1111", desc: "Visa with dashes" },
    ];
    for (const { input, desc } of cases) {
      it(`detects ${desc}: ${input}`, () => {
        const result = engine.scan(input);
        expect(result.entities.some((e) => e.type === "credit_card")).toBe(true);
      });
    }
  });

  // --- API Key ---
  describe("API key", () => {
    const cases = [
      { input: "api_key=sk_live_abcdef1234567890", desc: "api_key equals" },
      { input: 'token: "ghp_1234567890abcdefghij"', desc: "token colon quoted" },
      { input: "secret=super_secret_value_1234", desc: "secret equals" },
      { input: "api-secret: mySecretValue12345", desc: "api-secret colon" },
    ];
    for (const { input, desc } of cases) {
      it(`detects ${desc}: ${input}`, () => {
        const result = engine.scan(input);
        expect(result.entities.some((e) => e.type === "api_key")).toBe(true);
        expect(result.taint_flags).toContain("contains_secret");
      });
    }
  });

  // --- AWS Key ---
  describe("AWS access key", () => {
    it("detects AKIA prefix key", () => {
      const result = engine.scan("AKIAIOSFODNN7EXAMPLE");
      expect(result.entities.some((e) => e.type === "aws_access_key")).toBe(true);
      expect(result.taint_flags).toContain("contains_secret");
    });

    it("detects key in config context", () => {
      const result = engine.scan("aws_access_key_id = AKIAIOSFODNN7EXAMPLE");
      expect(result.entities.some((e) => e.type === "aws_access_key")).toBe(true);
    });
  });

  // --- OAuth Token ---
  describe("OAuth/JWT token", () => {
    it("detects well-formed JWT", () => {
      const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }))
        .replace(/=/g, "")
        .replace(/\+/g, "-")
        .replace(/\//g, "_");
      const payload = btoa(JSON.stringify({ sub: "1234567890", iat: 1516239022 }))
        .replace(/=/g, "")
        .replace(/\+/g, "-")
        .replace(/\//g, "_");
      const sig = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
      const result = engine.scan(`${header}.${payload}.${sig}`);
      expect(result.entities.some((e) => e.type === "oauth_token")).toBe(true);
    });

    it("detects Bearer token", () => {
      const result = engine.scan(
        "Authorization: Bearer test-token-abc123def456ghi789jkl",
      );
      expect(result.entities.some((e) => e.type === "oauth_token")).toBe(true);
    });
  });

  // --- Password ---
  describe("password", () => {
    const cases = [
      { input: "password=hunter2", desc: "password equals" },
      { input: "passwd: s3cretValue!", desc: "passwd colon" },
      { input: "pwd=abc123", desc: "pwd equals" },
      { input: "pass=my_pass_123", desc: "pass equals" },
    ];
    for (const { input, desc } of cases) {
      it(`detects ${desc}: ${input}`, () => {
        const result = engine.scan(input);
        expect(result.entities.some((e) => e.type === "password")).toBe(true);
        expect(result.taint_flags).toContain("contains_secret");
      });
    }
  });

  // --- IPv4 ---
  describe("IPv4", () => {
    const cases = [
      { input: "192.168.1.1", desc: "private class C" },
      { input: "10.0.0.1", desc: "private class A" },
      { input: "8.8.8.8", desc: "public DNS" },
      { input: "255.255.255.255", desc: "broadcast" },
      { input: "0.0.0.0", desc: "unspecified" },
    ];
    for (const { input, desc } of cases) {
      it(`detects ${desc}: ${input}`, () => {
        const result = engine.scan(input);
        expect(result.entities.some((e) => e.type === "ipv4")).toBe(true);
      });
    }
  });

  // --- Mixed content ---
  describe("mixed content", () => {
    it("detects multiple entity types in single content", () => {
      const result = engine.scan(
        "Contact user@example.com or call (555) 123-4567. SSN: 123-45-6789",
      );
      const types = result.entities.map((e) => e.type);
      expect(types).toContain("email");
      expect(types).toContain("phone");
      expect(types).toContain("ssn");
    });

    it("detects secrets and PII together", () => {
      const result = engine.scan(
        "Email: admin@corp.com, API: api_key=sk_live_1234567890abc",
      );
      expect(result.taint_flags).toContain("contains_pii");
      expect(result.taint_flags).toContain("contains_secret");
    });
  });
});
