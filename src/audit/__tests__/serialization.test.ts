import { describe, it, expect } from "vitest";
import { v4 as uuidv4 } from "uuid";
import { sha256Hash } from "../../shared/crypto.js";
import { parseAuditEvent } from "../types.js";
import {
  serializeAuditEvent,
  deserializeAuditEvent,
  scrubEvent,
} from "../serialization.js";
import { AuditValidationError } from "../errors.js";

const HASH = sha256Hash("test");

function validDecisionEventData(overrides: Record<string, unknown> = {}) {
  return {
    event_id: uuidv4(),
    event_type: "decision",
    timestamp: new Date().toISOString(),
    decision_id: uuidv4(),
    actor_id: "user-1",
    agent_id: "agent-1",
    policy_id: "policy-1",
    action: "read",
    result: "allow",
    explanation: "Allowed by default policy",
    matched_rules: ["rule-1"],
    input_hashes: [HASH],
    ...overrides,
  };
}

describe("serializeAuditEvent / deserializeAuditEvent", () => {
  it("round-trips a valid event", () => {
    const original = parseAuditEvent(validDecisionEventData());
    const json = serializeAuditEvent(original);
    const restored = deserializeAuditEvent(json);
    expect(restored.event_id).toBe(original.event_id);
    expect(restored.event_type).toBe(original.event_type);
    expect(restored.timestamp).toBe(original.timestamp);
  });

  it("produces valid JSON", () => {
    const event = parseAuditEvent(validDecisionEventData());
    const json = serializeAuditEvent(event);
    expect(() => JSON.parse(json) as unknown).not.toThrow();
  });

  it("rejects malformed JSON", () => {
    expect(() => deserializeAuditEvent("{not valid json")).toThrow();
  });

  it("rejects valid JSON that isn't a valid event", () => {
    expect(() => deserializeAuditEvent('{"foo": "bar"}')).toThrow(AuditValidationError);
  });

  it("produces deterministic output (sorted keys)", () => {
    const event = parseAuditEvent(validDecisionEventData());
    const json1 = serializeAuditEvent(event);
    const json2 = serializeAuditEvent(event);
    expect(json1).toBe(json2);
  });
});

describe("scrubEvent", () => {
  it("replaces email addresses in free-text fields", () => {
    const event = parseAuditEvent(
      validDecisionEventData({ explanation: "Action by user@example.com" }),
    );
    const scrubbed = scrubEvent(event);
    expect(scrubbed.event_type).toBe("decision");
    if (scrubbed.event_type === "decision") {
      expect(scrubbed.explanation).not.toContain("user@example.com");
      expect(scrubbed.explanation).toContain("sha256:");
    }
  });

  it("replaces JWT tokens in free-text fields", () => {
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123signature";
    const event = parseAuditEvent(
      validDecisionEventData({ explanation: `Token: ${jwt}` }),
    );
    const scrubbed = scrubEvent(event);
    if (scrubbed.event_type === "decision") {
      expect(scrubbed.explanation).not.toContain("eyJ");
    }
  });

  it("replaces long secret-like strings", () => {
    const secret = "A".repeat(40);
    const event = parseAuditEvent(
      validDecisionEventData({
        explanation: `Secret: ${secret}`,
      }),
    );
    const scrubbed = scrubEvent(event);
    if (scrubbed.event_type === "decision") {
      expect(scrubbed.explanation).not.toContain(secret);
      expect(scrubbed.explanation).toContain("sha256:");
    }
  });

  it("preserves sha256: prefixed hashes", () => {
    const event = parseAuditEvent(
      validDecisionEventData({ explanation: `Hash: ${HASH}` }),
    );
    const scrubbed = scrubEvent(event);
    if (scrubbed.event_type === "decision") {
      expect(scrubbed.explanation).toContain(HASH);
    }
  });

  it("preserves safe fields (UUIDs, enums, timestamps)", () => {
    const event = parseAuditEvent(validDecisionEventData());
    const scrubbed = scrubEvent(event);
    expect(scrubbed.event_id).toBe(event.event_id);
    expect(scrubbed.event_type).toBe(event.event_type);
    expect(scrubbed.timestamp).toBe(event.timestamp);
  });

  it("returns a frozen event", () => {
    const event = parseAuditEvent(validDecisionEventData());
    const scrubbed = scrubEvent(event);
    expect(Object.isFrozen(scrubbed)).toBe(true);
  });

  it("scrubs tool_name field", () => {
    const toolData = {
      event_id: uuidv4(),
      event_type: "tool",
      timestamp: new Date().toISOString(),
      request_id: uuidv4(),
      tool_name: "exec user@example.com",
      args_hash: HASH,
      destination: "local",
      result: "allowed",
      capability_id: uuidv4(),
    };
    const event = parseAuditEvent(toolData);
    const scrubbed = scrubEvent(event);
    if (scrubbed.event_type === "tool") {
      expect(scrubbed.tool_name).not.toContain("user@example.com");
    }
  });

  it("scrubs destination field", () => {
    const toolData = {
      event_id: uuidv4(),
      event_type: "tool",
      timestamp: new Date().toISOString(),
      request_id: uuidv4(),
      tool_name: "http.post",
      args_hash: HASH,
      destination: "admin@secret.corp",
      result: "allowed",
      capability_id: uuidv4(),
    };
    const event = parseAuditEvent(toolData);
    const scrubbed = scrubEvent(event);
    if (scrubbed.event_type === "tool") {
      expect(scrubbed.destination).not.toContain("admin@secret.corp");
    }
  });

  it("scrubs reason field in approval events", () => {
    const approvalData = {
      event_id: uuidv4(),
      event_type: "approval",
      timestamp: new Date().toISOString(),
      approval_id: uuidv4(),
      actor_id: "user-1",
      decision_id: uuidv4(),
      scope_hash: HASH,
      reason: "Approved for user@example.com",
      status: "granted",
    };
    const event = parseAuditEvent(approvalData);
    const scrubbed = scrubEvent(event);
    if (scrubbed.event_type === "approval") {
      expect(scrubbed.reason).not.toContain("user@example.com");
    }
  });
});
