import { describe, it, expect } from "vitest";
import { createEnvelopeAssembler } from "../envelope-assembler.js";
import type { EnvelopeAssemblerInput } from "../types.js";

function validInput(overrides?: Partial<EnvelopeAssemblerInput>): EnvelopeAssemblerInput {
  return {
    content: "Hello, world!",
    source_type: "user_input",
    parsed: {
      format: "text/plain",
      normalized_text: "Hello, world!",
      content_hash: "sha256:" + "a".repeat(64),
      byte_length: 13,
    },
    trust: {
      source_trust: "trusted_user",
      default_taint_flags: [],
      retention_class: "session",
    },
    sensitivity: {
      entities: [],
      data_classes: [],
      taint_flags: [],
    },
    injection: {
      detected: false,
      confidence: 0,
      matched_patterns: [],
      taint_flags: [],
    },
    ...overrides,
  };
}

describe("createEnvelopeAssembler", () => {
  const assembler = createEnvelopeAssembler();

  describe("basic assembly", () => {
    it("assembles a valid envelope from clean input", () => {
      const { envelope } = assembler.assemble(validInput());
      expect(envelope.source_type).toBe("user_input");
      expect(envelope.source_trust).toBe("trusted_user");
      expect(envelope.retention_class).toBe("session");
      expect(envelope.sensitivity).toEqual(["public"]);
    });

    it("returns frozen envelope", () => {
      const { envelope } = assembler.assemble(validInput());
      expect(Object.isFrozen(envelope)).toBe(true);
    });

    it("returns frozen policy_input", () => {
      const { policy_input } = assembler.assemble(validInput());
      expect(Object.isFrozen(policy_input)).toBe(true);
    });

    it("generates valid content_id (UUID)", () => {
      const { envelope } = assembler.assemble(validInput());
      expect(envelope.content_id).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
      );
    });
  });

  describe("sensitivity handling", () => {
    it("defaults to ['public'] when no data classes detected", () => {
      const { envelope } = assembler.assemble(validInput());
      expect(envelope.sensitivity).toEqual(["public"]);
    });

    it("uses detected data classes", () => {
      const { envelope } = assembler.assemble(
        validInput({
          sensitivity: {
            entities: [
              {
                type: "email",
                value_hash: "sha256:" + "b".repeat(64),
                confidence: 0.9,
                span: { start: 0, end: 5 },
              },
            ],
            data_classes: ["pii"],
            taint_flags: ["contains_pii"],
          },
        }),
      );
      expect(envelope.sensitivity).toContain("pii");
    });
  });

  describe("taint flag union", () => {
    it("unions trust + sensitivity + injection taint flags", () => {
      const { envelope } = assembler.assemble(
        validInput({
          trust: {
            source_trust: "untrusted_external",
            default_taint_flags: ["untrusted_instruction"],
            retention_class: "ephemeral",
          },
          sensitivity: {
            entities: [
              {
                type: "email",
                value_hash: "sha256:" + "b".repeat(64),
                confidence: 0.9,
                span: { start: 0, end: 5 },
              },
            ],
            data_classes: ["pii"],
            taint_flags: ["contains_pii"],
          },
          injection: {
            detected: true,
            confidence: 0.9,
            matched_patterns: ["role_assumption"],
            taint_flags: ["prompt_injection_suspected"],
          },
        }),
      );
      expect(envelope.taint_flags).toContain("untrusted_instruction");
      expect(envelope.taint_flags).toContain("contains_pii");
      expect(envelope.taint_flags).toContain("prompt_injection_suspected");
    });

    it("de-duplicates taint flags", () => {
      const { envelope } = assembler.assemble(
        validInput({
          trust: {
            source_trust: "untrusted_external",
            default_taint_flags: ["untrusted_instruction"],
            retention_class: "ephemeral",
          },
          injection: {
            detected: true,
            confidence: 0.9,
            matched_patterns: ["role_assumption"],
            taint_flags: ["prompt_injection_suspected", "untrusted_instruction"],
          },
        }),
      );
      const count = envelope.taint_flags.filter(
        (f) => f === "untrusted_instruction",
      ).length;
      expect(count).toBe(1);
    });
  });

  describe("allowed destinations", () => {
    it("restricts untrusted_external to local_only", () => {
      const { envelope } = assembler.assemble(
        validInput({
          trust: {
            source_trust: "untrusted_external",
            default_taint_flags: [],
            retention_class: "ephemeral",
          },
        }),
      );
      expect(envelope.allowed_destinations).toEqual(["local_only"]);
    });

    it("allows local_only and approved_remote for trusted sources", () => {
      const { envelope } = assembler.assemble(validInput());
      expect(envelope.allowed_destinations).toContain("local_only");
      expect(envelope.allowed_destinations).toContain("approved_remote");
    });
  });

  describe("policy input", () => {
    it("builds policy_input with correct structure", () => {
      const { policy_input } = assembler.assemble(validInput());
      expect(policy_input.principal.type).toBe("agent");
      expect(policy_input.request.action).toBe("ingress.evaluate");
      expect(policy_input.resource.type).toBe("content");
      expect(policy_input.resource.name).toBe("user_input");
    });

    it("includes sensitivity data in policy_input", () => {
      const { policy_input } = assembler.assemble(
        validInput({
          sensitivity: {
            entities: [],
            data_classes: ["pii"],
            taint_flags: ["contains_pii"],
          },
        }),
      );
      expect(policy_input.data.sensitivity).toContain("pii");
      expect(policy_input.data.taint_flags).toContain("contains_pii");
    });

    it("includes source trust in policy_input", () => {
      const { policy_input } = assembler.assemble(validInput());
      expect(policy_input.data.source_trust).toContain("trusted_user");
    });
  });

  describe("retention_class", () => {
    it("uses trust classification retention_class", () => {
      const { envelope } = assembler.assemble(
        validInput({
          trust: {
            source_trust: "untrusted_external",
            default_taint_flags: [],
            retention_class: "ephemeral",
          },
        }),
      );
      expect(envelope.retention_class).toBe("ephemeral");
    });
  });
});
