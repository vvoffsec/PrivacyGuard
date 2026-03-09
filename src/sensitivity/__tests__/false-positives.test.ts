import { describe, it, expect } from "vitest";
import { createSensitivityEngine } from "../engine.js";

/**
 * False positive test suite: content that should NOT trigger detection.
 */
describe("false positives", () => {
  const engine = createSensitivityEngine();

  describe("not emails", () => {
    const cases = [
      "user@",
      "@example.com",
      "not-an-email",
      "user at example dot com",
      "CSS selector a@b {}",
    ];
    for (const input of cases) {
      it(`does not detect email in: "${input}"`, () => {
        const result = engine.scan(input);
        expect(result.entities.filter((e) => e.type === "email")).toHaveLength(0);
      });
    }
  });

  describe("not phone numbers", () => {
    const cases = ["555-1234", "Version 1.2.3.4567", "ISBN 978-0-123456-47-2"];
    for (const input of cases) {
      it(`does not detect phone in: "${input}"`, () => {
        const result = engine.scan(input);
        expect(result.entities.filter((e) => e.type === "phone")).toHaveLength(0);
      });
    }
  });

  describe("not SSNs", () => {
    const cases = [
      "000-12-3456",
      "666-12-3456",
      "900-12-3456",
      "999-99-9999",
      "123456789",
      "12-345-6789",
    ];
    for (const input of cases) {
      it(`does not detect SSN in: "${input}"`, () => {
        const result = engine.scan(input);
        expect(result.entities.filter((e) => e.type === "ssn")).toHaveLength(0);
      });
    }
  });

  describe("not credit cards", () => {
    const cases = ["4111111111111112", "1234567890", "12345"];
    for (const input of cases) {
      it(`does not detect credit card in: "${input}"`, () => {
        const result = engine.scan(input);
        expect(result.entities.filter((e) => e.type === "credit_card")).toHaveLength(0);
      });
    }
  });

  describe("not API keys", () => {
    const cases = [
      "just some regular text",
      "the key to success is perseverance",
      "token of appreciation",
      "x = 42",
    ];
    for (const input of cases) {
      it(`does not detect api_key in: "${input}"`, () => {
        const result = engine.scan(input);
        expect(result.entities.filter((e) => e.type === "api_key")).toHaveLength(0);
      });
    }
  });

  describe("not AWS keys", () => {
    const cases = ["AKIATOOSHORT", "ASIAISAMPLEKEYID1234", "NOTAKIAIOSFODNN7EXAM"];
    for (const input of cases) {
      it(`does not detect AWS key in: "${input}"`, () => {
        const result = engine.scan(input);
        expect(result.entities.filter((e) => e.type === "aws_access_key")).toHaveLength(
          0,
        );
      });
    }
  });

  describe("not IPv4", () => {
    const cases = ["999.999.999.999", "256.1.1.1", "1.2.3"];
    for (const input of cases) {
      it(`does not detect IPv4 in: "${input}"`, () => {
        const result = engine.scan(input);
        expect(result.entities.filter((e) => e.type === "ipv4")).toHaveLength(0);
      });
    }
  });

  describe("not passwords", () => {
    const cases = [
      "change your password regularly",
      "the password must be at least 8 characters",
      "password strength meter",
      "forgot password link",
    ];
    for (const input of cases) {
      it(`does not detect password in: "${input}"`, () => {
        const result = engine.scan(input);
        expect(result.entities.filter((e) => e.type === "password")).toHaveLength(0);
      });
    }
  });

  describe("not OAuth tokens", () => {
    const cases = ["just regular text", "Bearer ", "eyJ incomplete token"];
    for (const input of cases) {
      it(`does not detect oauth_token in: "${input}"`, () => {
        const result = engine.scan(input);
        expect(result.entities.filter((e) => e.type === "oauth_token")).toHaveLength(0);
      });
    }
  });

  describe("clean content", () => {
    const cases = [
      "The quick brown fox jumps over the lazy dog.",
      "Hello, World!",
      "function add(a, b) { return a + b; }",
      "SELECT * FROM users WHERE id = 1",
      "npm install express --save",
      '{ "name": "John", "age": 30 }',
      "https://example.com/path?q=search",
    ];
    for (const input of cases) {
      it(`detects nothing in: "${input.substring(0, 40)}..."`, () => {
        const result = engine.scan(input);
        expect(result.entities).toHaveLength(0);
      });
    }
  });
});
