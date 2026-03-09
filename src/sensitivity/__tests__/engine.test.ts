import { describe, it, expect } from "vitest";
import { createSensitivityEngine } from "../engine.js";
import type { PatternRecognizer } from "../types.js";

describe("createSensitivityEngine", () => {
  it("creates engine with default config", () => {
    const engine = createSensitivityEngine();
    const result = engine.scan("no sensitive data");
    expect(result.entities).toHaveLength(0);
    expect(result.data_classes).toHaveLength(0);
    expect(result.taint_flags).toHaveLength(0);
  });

  it("detects email", () => {
    const engine = createSensitivityEngine();
    const result = engine.scan("user@example.com");
    expect(result.entities.some((e) => e.type === "email")).toBe(true);
    expect(result.data_classes).toContain("pii");
    expect(result.taint_flags).toContain("contains_pii");
  });

  it("detects phone", () => {
    const engine = createSensitivityEngine();
    const result = engine.scan("Call (555) 123-4567");
    expect(result.entities.some((e) => e.type === "phone")).toBe(true);
  });

  it("detects SSN", () => {
    const engine = createSensitivityEngine();
    const result = engine.scan("SSN: 123-45-6789");
    expect(result.entities.some((e) => e.type === "ssn")).toBe(true);
  });

  it("detects credit card", () => {
    const engine = createSensitivityEngine();
    const result = engine.scan("Card: 4111111111111111");
    expect(result.entities.some((e) => e.type === "credit_card")).toBe(true);
  });

  it("detects API key", () => {
    const engine = createSensitivityEngine();
    const result = engine.scan("api_key=sk_test_1234567890abcdef");
    expect(result.entities.some((e) => e.type === "api_key")).toBe(true);
    expect(result.taint_flags).toContain("contains_secret");
  });

  it("detects AWS key", () => {
    const engine = createSensitivityEngine();
    const result = engine.scan("AKIAIOSFODNN7EXAMPLE");
    expect(result.entities.some((e) => e.type === "aws_access_key")).toBe(true);
  });

  it("detects OAuth token (JWT)", () => {
    const engine = createSensitivityEngine();
    const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }))
      .replace(/=/g, "")
      .replace(/\+/g, "-")
      .replace(/\//g, "_");
    const payload = btoa(JSON.stringify({ sub: "1234567890" }))
      .replace(/=/g, "")
      .replace(/\+/g, "-")
      .replace(/\//g, "_");
    const jwt = `${header}.${payload}.abcdefghijklmnop`;
    const result = engine.scan(jwt);
    expect(result.entities.some((e) => e.type === "oauth_token")).toBe(true);
  });

  it("detects password", () => {
    const engine = createSensitivityEngine();
    const result = engine.scan("password=hunter2");
    expect(result.entities.some((e) => e.type === "password")).toBe(true);
  });

  it("detects IPv4", () => {
    const engine = createSensitivityEngine();
    const result = engine.scan("Server 192.168.1.1");
    expect(result.entities.some((e) => e.type === "ipv4")).toBe(true);
  });

  it("generates secret handles for secret/credential entities", () => {
    const engine = createSensitivityEngine();
    const result = engine.scan("AKIAIOSFODNN7EXAMPLE");
    expect(result.secret_handles).toBeDefined();
    expect(result.secret_handles?.length).toBeGreaterThan(0);
    expect(result.secret_handles?.[0].handle_id).toMatch(/^secretref:\/\//);
  });

  it("does not generate secret handles for pii entities", () => {
    const engine = createSensitivityEngine();
    const result = engine.scan("user@example.com");
    expect(result.secret_handles).toBeUndefined();
  });

  it("skips secret handle generation when disabled", () => {
    const engine = createSensitivityEngine({ generate_secret_handles: false });
    const result = engine.scan("AKIAIOSFODNN7EXAMPLE");
    expect(result.secret_handles).toBeUndefined();
  });

  it("returns frozen result", () => {
    const engine = createSensitivityEngine();
    const result = engine.scan("user@example.com");
    expect(Object.isFrozen(result)).toBe(true);
  });

  it("hashes values with sha256", () => {
    const engine = createSensitivityEngine();
    const result = engine.scan("user@example.com");
    expect(result.entities[0].value_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it("accepts custom recognizers", () => {
    const custom: PatternRecognizer = {
      name: "custom",
      data_class: "confidential",
      default_confidence: 0.8,
      detect: (content) =>
        content.includes("CUSTOM")
          ? [
              {
                value: "CUSTOM",
                span: {
                  start: content.indexOf("CUSTOM"),
                  end: content.indexOf("CUSTOM") + 6,
                },
                signals: { pattern_matched: true, format_validated: true },
              },
            ]
          : [],
    };
    const engine = createSensitivityEngine({ recognizers: [custom] });
    const result = engine.scan("found CUSTOM here");
    expect(result.entities).toHaveLength(1);
    expect(result.entities[0].type).toBe("custom");
  });

  it("appends additional_recognizers to defaults", () => {
    const custom: PatternRecognizer = {
      name: "custom",
      data_class: "confidential",
      default_confidence: 0.8,
      detect: (content) =>
        content.includes("CUSTOM")
          ? [
              {
                value: "CUSTOM",
                span: {
                  start: content.indexOf("CUSTOM"),
                  end: content.indexOf("CUSTOM") + 6,
                },
                signals: { pattern_matched: true, format_validated: true },
              },
            ]
          : [],
    };
    const engine = createSensitivityEngine({ additional_recognizers: [custom] });
    // Should still detect built-in types
    const emailResult = engine.scan("user@example.com");
    expect(emailResult.entities.some((e) => e.type === "email")).toBe(true);
    // And the custom type
    const customResult = engine.scan("found CUSTOM here");
    expect(customResult.entities.some((e) => e.type === "custom")).toBe(true);
  });

  it("respects custom entropy threshold", () => {
    const strictEngine = createSensitivityEngine({ entropy_threshold: 6.0 });
    const lenientEngine = createSensitivityEngine({ entropy_threshold: 3.0 });
    const content = "secret=aB3dE6gH9jK2mN5pQ8rS1uV4wX7yZ0a";
    const strict = strictEngine.scan(content);
    const lenient = lenientEngine.scan(content);
    // Both may detect api_key pattern. Focus on high_entropy_string
    const strictHE = strict.entities.filter((e) => e.type === "high_entropy_string");
    const lenientHE = lenient.entities.filter((e) => e.type === "high_entropy_string");
    expect(lenientHE.length).toBeGreaterThanOrEqual(strictHE.length);
  });

  it("deduplicates overlapping entities", () => {
    const r1: PatternRecognizer = {
      name: "a",
      data_class: "pii",
      default_confidence: 0.5,
      detect: () => [
        {
          value: "test",
          span: { start: 0, end: 4 },
          signals: { pattern_matched: true, format_validated: true },
        },
      ],
    };
    const r2: PatternRecognizer = {
      name: "b",
      data_class: "secret",
      default_confidence: 0.9,
      detect: () => [
        {
          value: "test",
          span: { start: 0, end: 4 },
          signals: { pattern_matched: true, format_validated: true },
        },
      ],
    };
    const engine = createSensitivityEngine({ recognizers: [r1, r2] });
    const result = engine.scan("test");
    expect(result.entities).toHaveLength(1);
    expect(result.entities[0].confidence).toBe(0.9);
  });

  it("wraps recognizer errors in SensitivityDetectionError", () => {
    const failing: PatternRecognizer = {
      name: "broken",
      data_class: "pii",
      default_confidence: 0.5,
      detect: () => {
        throw new Error("boom");
      },
    };
    const engine = createSensitivityEngine({ recognizers: [failing] });
    expect(() => engine.scan("test")).toThrow('Recognizer "broken" failed');
  });
});
