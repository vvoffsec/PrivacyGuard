import { describe, it, expect } from "vitest";
import { validate as uuidValidate, version as uuidVersion } from "uuid";
import { sha256Hash } from "../../shared/crypto.js";
import {
  createDecisionEvent,
  createApprovalEvent,
  createToolEvent,
  createMemoryEvent,
  createEgressEvent,
  createIntegrityEvent,
} from "../factories.js";
import { v4 as uuidv4 } from "uuid";

const HASH = sha256Hash("test");

function expectValidUUIDv4(id: string) {
  expect(uuidValidate(id)).toBe(true);
  expect(uuidVersion(id)).toBe(4);
}

describe("createDecisionEvent", () => {
  it("creates a valid decision event with auto-generated fields", () => {
    const event = createDecisionEvent({
      decision_id: uuidv4(),
      actor_id: "user-1",
      agent_id: "agent-1",
      policy_id: "policy-1",
      action: "read",
      result: "allow",
      explanation: "Allowed",
      matched_rules: ["rule-1"],
      input_hashes: [HASH],
    });
    expectValidUUIDv4(event.event_id);
    expect(event.event_type).toBe("decision");
    expect(event.timestamp).toBeTruthy();
    expect(event.result).toBe("allow");
    expect(Object.isFrozen(event)).toBe(true);
  });

  it("generates unique IDs per call", () => {
    const args = {
      decision_id: uuidv4(),
      actor_id: "user-1",
      agent_id: "agent-1",
      policy_id: "policy-1",
      action: "read",
      result: "allow" as const,
      explanation: "Allowed",
      matched_rules: ["rule-1"],
    };
    const e1 = createDecisionEvent(args);
    const e2 = createDecisionEvent(args);
    expect(e1.event_id).not.toBe(e2.event_id);
  });

  it("propagates correlation_id", () => {
    const cid = uuidv4();
    const event = createDecisionEvent({
      decision_id: uuidv4(),
      actor_id: "user-1",
      agent_id: "agent-1",
      policy_id: "policy-1",
      action: "read",
      result: "allow",
      explanation: "Allowed",
      matched_rules: ["rule-1"],
      correlation_id: cid,
    });
    expect(event.correlation_id).toBe(cid);
  });
});

describe("createApprovalEvent", () => {
  it("creates a valid approval event", () => {
    const event = createApprovalEvent({
      approval_id: uuidv4(),
      actor_id: "user-1",
      decision_id: uuidv4(),
      scope_hash: HASH,
      reason: "Approved by admin",
      status: "granted",
    });
    expectValidUUIDv4(event.event_id);
    expect(event.event_type).toBe("approval");
    expect(event.status).toBe("granted");
  });

  it("generates unique IDs per call", () => {
    const args = {
      approval_id: uuidv4(),
      actor_id: "user-1",
      decision_id: uuidv4(),
      scope_hash: HASH,
      reason: "Reason",
      status: "granted" as const,
    };
    const e1 = createApprovalEvent(args);
    const e2 = createApprovalEvent(args);
    expect(e1.event_id).not.toBe(e2.event_id);
  });
});

describe("createToolEvent", () => {
  it("creates a valid tool event", () => {
    const event = createToolEvent({
      request_id: uuidv4(),
      tool_name: "fs.read",
      args_hash: HASH,
      destination: "local",
      result: "allowed",
      capability_id: uuidv4(),
    });
    expectValidUUIDv4(event.event_id);
    expect(event.event_type).toBe("tool");
    expect(event.result).toBe("allowed");
  });

  it("propagates correlation_id", () => {
    const cid = uuidv4();
    const event = createToolEvent({
      request_id: uuidv4(),
      tool_name: "fs.read",
      args_hash: HASH,
      destination: "local",
      result: "allowed",
      capability_id: uuidv4(),
      correlation_id: cid,
    });
    expect(event.correlation_id).toBe(cid);
  });
});

describe("createMemoryEvent", () => {
  it("creates a valid memory event", () => {
    const event = createMemoryEvent({
      entry_id: uuidv4(),
      tier: "ephemeral",
      source_trust: "trusted_user",
      sensitivity: ["public"],
      action: "write",
    });
    expectValidUUIDv4(event.event_id);
    expect(event.event_type).toBe("memory");
    expect(event.action).toBe("write");
  });

  it("generates unique IDs per call", () => {
    const args = {
      entry_id: uuidv4(),
      tier: "ephemeral" as const,
      source_trust: "trusted_user" as const,
      sensitivity: ["public" as const],
      action: "write" as const,
    };
    const e1 = createMemoryEvent(args);
    const e2 = createMemoryEvent(args);
    expect(e1.event_id).not.toBe(e2.event_id);
  });
});

describe("createEgressEvent", () => {
  it("creates a valid egress event", () => {
    const event = createEgressEvent({
      egress_id: uuidv4(),
      destination: "https://api.example.com",
      classes_detected: ["pii"],
      transform_applied: "redact",
      bytes_sent: 512,
      blocked: false,
    });
    expectValidUUIDv4(event.event_id);
    expect(event.event_type).toBe("egress");
    expect(event.blocked).toBe(false);
  });

  it("propagates correlation_id", () => {
    const cid = uuidv4();
    const event = createEgressEvent({
      egress_id: uuidv4(),
      destination: "remote",
      classes_detected: [],
      transform_applied: "none",
      bytes_sent: 0,
      blocked: false,
      correlation_id: cid,
    });
    expect(event.correlation_id).toBe(cid);
  });
});

describe("createIntegrityEvent", () => {
  it("creates a valid integrity event", () => {
    const event = createIntegrityEvent({
      artifact_id: "bundle-v1",
      signature_status: "valid",
      bundle_version: "1.0.0",
    });
    expectValidUUIDv4(event.event_id);
    expect(event.event_type).toBe("integrity");
    expect(event.signature_status).toBe("valid");
  });

  it("generates unique IDs per call", () => {
    const args = {
      artifact_id: "bundle-v1",
      signature_status: "valid" as const,
      bundle_version: "1.0.0",
    };
    const e1 = createIntegrityEvent(args);
    const e2 = createIntegrityEvent(args);
    expect(e1.event_id).not.toBe(e2.event_id);
  });

  it("accepts optional provenance_ref", () => {
    const event = createIntegrityEvent({
      artifact_id: "bundle-v1",
      signature_status: "valid",
      bundle_version: "1.0.0",
      provenance_ref: "https://example.com/provenance",
    });
    expect(event.provenance_ref).toBe("https://example.com/provenance");
  });
});
