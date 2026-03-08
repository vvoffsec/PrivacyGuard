import { describe, it, expect } from "vitest";
import { v4 as uuidv4 } from "uuid";
import { parseEnvelope, updateEnvelope } from "../envelope.js";
import { EnvelopeValidationError, EnvelopeConsistencyError } from "../errors.js";

function validEnvelopeData(overrides: Record<string, unknown> = {}) {
  return {
    content_id: uuidv4(),
    source_type: "user_input",
    source_trust: "trusted_user",
    retention_class: "session",
    sensitivity: ["public"],
    entities: [],
    allowed_destinations: ["local_only"],
    purpose_tags: [],
    taint_flags: [],
    created_at: new Date().toISOString(),
    ...overrides,
  };
}

describe("parseEnvelope", () => {
  it("parses a valid envelope", () => {
    const data = validEnvelopeData();
    const envelope = parseEnvelope(data);
    expect(envelope.content_id).toBe(data.content_id);
    expect(envelope.source_type).toBe("user_input");
  });

  it("returns a frozen (immutable) object", () => {
    const envelope = parseEnvelope(validEnvelopeData());
    expect(Object.isFrozen(envelope)).toBe(true);
  });

  it("rejects missing required fields", () => {
    expect(() => parseEnvelope({})).toThrow(EnvelopeValidationError);
  });

  it("rejects invalid source_type", () => {
    expect(() =>
      parseEnvelope(validEnvelopeData({ source_type: "fax" })),
    ).toThrow(EnvelopeValidationError);
  });

  it("rejects invalid source_trust", () => {
    expect(() =>
      parseEnvelope(validEnvelopeData({ source_trust: "super_trusted" })),
    ).toThrow(EnvelopeValidationError);
  });

  it("rejects empty sensitivity array", () => {
    expect(() =>
      parseEnvelope(validEnvelopeData({ sensitivity: [] })),
    ).toThrow(EnvelopeValidationError);
  });

  it("rejects invalid content_id (not UUID)", () => {
    expect(() =>
      parseEnvelope(validEnvelopeData({ content_id: "not-a-uuid" })),
    ).toThrow(EnvelopeValidationError);
  });

  it("rejects invalid created_at (not ISO 8601)", () => {
    expect(() =>
      parseEnvelope(validEnvelopeData({ created_at: "yesterday" })),
    ).toThrow(EnvelopeValidationError);
  });
});

describe("cross-field refinements", () => {
  it("rejects secret sensitivity without contains_secret taint flag", () => {
    expect(() =>
      parseEnvelope(
        validEnvelopeData({ sensitivity: ["secret"], taint_flags: [] }),
      ),
    ).toThrow(EnvelopeConsistencyError);
  });

  it("rejects credential sensitivity without contains_secret taint flag", () => {
    expect(() =>
      parseEnvelope(
        validEnvelopeData({ sensitivity: ["credential"], taint_flags: [] }),
      ),
    ).toThrow(EnvelopeConsistencyError);
  });

  it("accepts secret sensitivity with contains_secret taint flag", () => {
    const envelope = parseEnvelope(
      validEnvelopeData({
        sensitivity: ["secret"],
        taint_flags: ["contains_secret"],
      }),
    );
    expect(envelope.sensitivity).toContain("secret");
  });

  it("rejects pii sensitivity without contains_pii taint flag", () => {
    expect(() =>
      parseEnvelope(
        validEnvelopeData({ sensitivity: ["pii"], taint_flags: [] }),
      ),
    ).toThrow(EnvelopeConsistencyError);
  });

  it("accepts pii sensitivity with contains_pii taint flag", () => {
    const envelope = parseEnvelope(
      validEnvelopeData({
        sensitivity: ["pii"],
        taint_flags: ["contains_pii"],
      }),
    );
    expect(envelope.sensitivity).toContain("pii");
  });

  it("rejects untrusted_external with durable retention", () => {
    expect(() =>
      parseEnvelope(
        validEnvelopeData({
          source_trust: "untrusted_external",
          retention_class: "durable",
        }),
      ),
    ).toThrow(EnvelopeConsistencyError);
  });

  it("allows untrusted_external with ephemeral retention", () => {
    const envelope = parseEnvelope(
      validEnvelopeData({
        source_trust: "untrusted_external",
        retention_class: "ephemeral",
      }),
    );
    expect(envelope.retention_class).toBe("ephemeral");
  });

  it("allows untrusted_external with quarantined retention", () => {
    const envelope = parseEnvelope(
      validEnvelopeData({
        source_trust: "untrusted_external",
        retention_class: "quarantined",
      }),
    );
    expect(envelope.retention_class).toBe("quarantined");
  });
});

describe("EnvelopeValidationError", () => {
  it("provides human-readable explanation", () => {
    try {
      parseEnvelope({});
    } catch (e) {
      expect(e).toBeInstanceOf(EnvelopeValidationError);
      const explanation = (e as EnvelopeValidationError).toExplanation();
      expect(explanation).toContain("1.");
      expect(typeof explanation).toBe("string");
    }
  });
});

describe("updateEnvelope", () => {
  it("returns a new envelope with patched fields", () => {
    const original = parseEnvelope(validEnvelopeData());
    const updated = updateEnvelope(original, { retention_class: "ephemeral" });
    expect(updated.retention_class).toBe("ephemeral");
    expect(updated.content_id).toBe(original.content_id);
  });

  it("preserves content_id even if patch tries to change it", () => {
    const original = parseEnvelope(validEnvelopeData());
    const updated = updateEnvelope(original, {
      retention_class: "ephemeral",
    } as never);
    expect(updated.content_id).toBe(original.content_id);
  });

  it("validates the patched result", () => {
    const original = parseEnvelope(validEnvelopeData());
    expect(() =>
      updateEnvelope(original, { source_trust: "invalid" as never }),
    ).toThrow(EnvelopeValidationError);
  });
});
