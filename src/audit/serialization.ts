import { sha256Hash } from "../shared/crypto.js";
import type { AuditEvent } from "./types.js";
import { parseAuditEvent } from "./types.js";

// Patterns that indicate sensitive content
const EMAIL_PATTERN = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
const JWT_PATTERN = /eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]+/g;
const LONG_SECRET_PATTERN = /(?<![a-zA-Z0-9:])([a-zA-Z0-9/+=]{33,})(?![a-zA-Z0-9])/g;

// Fields that contain free-text and need scrubbing
const SCRUBBABLE_FIELDS = new Set([
  "explanation",
  "reason",
  "tool_name",
  "destination",
  "artifact_id",
  "bundle_version",
]);

function scrubString(value: string): string {
  let result = value;
  result = result.replace(JWT_PATTERN, (match) => sha256Hash(match));
  result = result.replace(EMAIL_PATTERN, (match) => sha256Hash(match));
  result = result.replace(LONG_SECRET_PATTERN, (match) => {
    if (match.startsWith("sha256:")) return match;
    return sha256Hash(match);
  });
  return result;
}

/**
 * Defense-in-depth scrubbing of an audit event.
 * Scans free-text fields for sensitive patterns and replaces them with hashes.
 */
export function scrubEvent(event: AuditEvent): AuditEvent {
  const scrubbed: Record<string, unknown> = { ...event };

  for (const field of Array.from(SCRUBBABLE_FIELDS)) {
    if (field in scrubbed && typeof scrubbed[field] === "string") {
      scrubbed[field] = scrubString(scrubbed[field]);
    }
  }

  return parseAuditEvent(scrubbed);
}

/**
 * Serialize an audit event to deterministic key-sorted JSON.
 * Scrubs sensitive patterns before serialization.
 */
export function serializeAuditEvent(event: AuditEvent): string {
  const scrubbed = scrubEvent(event);
  return JSON.stringify(scrubbed, Object.keys(scrubbed).sort());
}

/**
 * Deserialize JSON into a validated AuditEvent.
 * Throws AuditValidationError on invalid input.
 */
export function deserializeAuditEvent(json: string): AuditEvent {
  const parsed: unknown = JSON.parse(json);
  return parseAuditEvent(parsed);
}
