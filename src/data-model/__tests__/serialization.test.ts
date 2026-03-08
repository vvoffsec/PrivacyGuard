import { describe, it, expect } from "vitest";
import { createUserEnvelope } from "../factories.js";
import {
  serializeEnvelope,
  deserializeEnvelope,
  stripForEgress,
} from "../serialization.js";
import { EnvelopeValidationError } from "../errors.js";
import { sha256Hash } from "../../shared/crypto.js";

describe("serializeEnvelope / deserializeEnvelope", () => {
  it("round-trips a valid envelope", () => {
    const original = createUserEnvelope();
    const json = serializeEnvelope(original);
    const restored = deserializeEnvelope(json);

    expect(restored.content_id).toBe(original.content_id);
    expect(restored.source_type).toBe(original.source_type);
    expect(restored.source_trust).toBe(original.source_trust);
    expect(restored.retention_class).toBe(original.retention_class);
    expect(restored.sensitivity).toEqual(original.sensitivity);
    expect(restored.taint_flags).toEqual(original.taint_flags);
    expect(restored.created_at).toBe(original.created_at);
  });

  it("produces valid JSON", () => {
    const json = serializeEnvelope(createUserEnvelope());
    expect(() => JSON.parse(json) as unknown).not.toThrow();
  });

  it("rejects malformed JSON", () => {
    expect(() => deserializeEnvelope("{not valid json")).toThrow();
  });

  it("rejects valid JSON that isn't a valid envelope", () => {
    expect(() => deserializeEnvelope('{"foo": "bar"}')).toThrow(EnvelopeValidationError);
  });
});

describe("stripForEgress", () => {
  it("preserves only allowlisted fields", () => {
    const envelope = createUserEnvelope({ purpose_tags: ["audit"] });
    const stripped = stripForEgress(envelope);

    // Preserved
    expect(stripped.content_id).toBe(envelope.content_id);
    expect(stripped.source_type).toBe(envelope.source_type);
    expect(stripped.sensitivity).toEqual(envelope.sensitivity);
    expect(stripped.purpose_tags).toEqual(envelope.purpose_tags);
    expect(stripped.created_at).toBe(envelope.created_at);

    // Stripped
    expect(stripped.taint_flags).toBeUndefined();
    expect(stripped.source_trust).toBeUndefined();
    expect(stripped.retention_class).toBeUndefined();
    expect(stripped.provenance_ref).toBeUndefined();
    expect(stripped.entities).toBeUndefined();
    expect(stripped.allowed_destinations).toBeUndefined();
  });

  it("strips entities with sensitive data from egress", () => {
    const envelope = createUserEnvelope({
      sensitivity: ["pii"],
      taint_flags: ["contains_pii"],
      entities: [
        {
          type: "email",
          value_hash: sha256Hash("test@example.com"),
          confidence: 0.95,
          span: { start: 0, end: 16 },
        },
      ],
    });
    const stripped = stripForEgress(envelope);
    expect(stripped.entities).toBeUndefined();
  });
});
