import { describe, it, expect } from "vitest";
import { createTrustClassifier } from "../trust-classifier.js";

describe("createTrustClassifier", () => {
  const classifier = createTrustClassifier();

  describe("default mappings", () => {
    it("classifies user_input as trusted_user with session retention", () => {
      const result = classifier.classify("user_input");
      expect(result.source_trust).toBe("trusted_user");
      expect(result.default_taint_flags).toEqual([]);
      expect(result.retention_class).toBe("session");
    });

    it("classifies local_file as trusted_local", () => {
      const result = classifier.classify("local_file");
      expect(result.source_trust).toBe("trusted_local");
      expect(result.default_taint_flags).toEqual([]);
      expect(result.retention_class).toBe("session");
    });

    it("classifies web_content as untrusted_external with untrusted_instruction taint", () => {
      const result = classifier.classify("web_content");
      expect(result.source_trust).toBe("untrusted_external");
      expect(result.default_taint_flags).toEqual(["untrusted_instruction"]);
      expect(result.retention_class).toBe("ephemeral");
    });

    it("classifies email_content as untrusted_external with untrusted_instruction taint", () => {
      const result = classifier.classify("email_content");
      expect(result.source_trust).toBe("untrusted_external");
      expect(result.default_taint_flags).toEqual(["untrusted_instruction"]);
      expect(result.retention_class).toBe("ephemeral");
    });

    it("classifies tool_output as untrusted_external with no taint", () => {
      const result = classifier.classify("tool_output");
      expect(result.source_trust).toBe("untrusted_external");
      expect(result.default_taint_flags).toEqual([]);
      expect(result.retention_class).toBe("ephemeral");
    });

    it("classifies generated as generated_unverified", () => {
      const result = classifier.classify("generated");
      expect(result.source_trust).toBe("generated_unverified");
      expect(result.default_taint_flags).toEqual([]);
      expect(result.retention_class).toBe("ephemeral");
    });
  });

  describe("memory_content pass-through", () => {
    it("uses provided trust for memory_content", () => {
      const result = classifier.classify("memory_content", "trusted_user");
      expect(result.source_trust).toBe("trusted_user");
    });

    it("defaults to trusted_local when no trust provided for memory_content", () => {
      const result = classifier.classify("memory_content");
      expect(result.source_trust).toBe("trusted_local");
    });

    it("accepts untrusted_external for memory_content", () => {
      const result = classifier.classify(
        "memory_content",
        "untrusted_external",
      );
      expect(result.source_trust).toBe("untrusted_external");
    });
  });

  describe("trust escalation prevention", () => {
    it("accepts equal trust level", () => {
      const result = classifier.classify("web_content", "untrusted_external");
      expect(result.source_trust).toBe("untrusted_external");
    });

    it("accepts more restrictive trust level", () => {
      const result = classifier.classify("user_input", "untrusted_external");
      expect(result.source_trust).toBe("untrusted_external");
    });

    it("rejects trust escalation (trusted_user for web_content)", () => {
      const result = classifier.classify("web_content", "trusted_user");
      expect(result.source_trust).toBe("untrusted_external");
    });

    it("rejects trust escalation (trusted_local for tool_output)", () => {
      const result = classifier.classify("tool_output", "trusted_local");
      expect(result.source_trust).toBe("untrusted_external");
    });

    it("accepts downgrade from trusted_user to generated_unverified", () => {
      const result = classifier.classify("user_input", "generated_unverified");
      expect(result.source_trust).toBe("generated_unverified");
    });

    it("rejects upgrade from generated to trusted_user", () => {
      const result = classifier.classify("generated", "trusted_user");
      expect(result.source_trust).toBe("generated_unverified");
    });
  });

  describe("immutability", () => {
    it("returns frozen result", () => {
      const result = classifier.classify("user_input");
      expect(Object.isFrozen(result)).toBe(true);
    });
  });
});
