import type { ContentEnvelope } from "./envelope.js";
import { parseEnvelope } from "./envelope.js";

/**
 * Serialize an envelope to deterministic key-sorted JSON.
 */
export function serializeEnvelope(envelope: ContentEnvelope): string {
  return JSON.stringify(envelope, Object.keys(envelope).sort());
}

/**
 * Deserialize JSON into a validated ContentEnvelope.
 * Throws EnvelopeValidationError on invalid input.
 */
export function deserializeEnvelope(json: string): ContentEnvelope {
  const parsed: unknown = JSON.parse(json);
  return parseEnvelope(parsed);
}

/** Fields preserved through egress (allowlist). */
const EGRESS_ALLOWED_FIELDS = new Set([
  "content_id",
  "source_type",
  "sensitivity",
  "purpose_tags",
  "created_at",
]);

/**
 * Strip an envelope to only egress-safe fields (allowlist approach).
 * New fields default to stripped — safer at trust boundaries.
 */
export function stripForEgress(
  envelope: ContentEnvelope,
): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const key of Object.keys(envelope)) {
    if (EGRESS_ALLOWED_FIELDS.has(key)) {
      result[key] = envelope[key as keyof ContentEnvelope];
    }
  }
  return result;
}
