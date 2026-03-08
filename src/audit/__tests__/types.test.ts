import { describe, it, expect } from "vitest";
import { v4 as uuidv4 } from "uuid";
import { sha256Hash } from "../../shared/crypto.js";
import {
  parseAuditEvent,
  DecisionEventSchema,
  ApprovalEventSchema,
  ToolEventSchema,
  MemoryEventSchema,
  EgressEventSchema,
  IntegrityEventSchema,
  AuditEventSchema,
} from "../types.js";
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

function validApprovalEventData(overrides: Record<string, unknown> = {}) {
  return {
    event_id: uuidv4(),
    event_type: "approval",
    timestamp: new Date().toISOString(),
    approval_id: uuidv4(),
    actor_id: "user-1",
    decision_id: uuidv4(),
    scope_hash: HASH,
    reason: "User approved",
    status: "granted",
    ...overrides,
  };
}

function validToolEventData(overrides: Record<string, unknown> = {}) {
  return {
    event_id: uuidv4(),
    event_type: "tool",
    timestamp: new Date().toISOString(),
    request_id: uuidv4(),
    tool_name: "fs.read",
    args_hash: HASH,
    destination: "local",
    result: "allowed",
    capability_id: uuidv4(),
    ...overrides,
  };
}

function validMemoryEventData(overrides: Record<string, unknown> = {}) {
  return {
    event_id: uuidv4(),
    event_type: "memory",
    timestamp: new Date().toISOString(),
    entry_id: uuidv4(),
    tier: "ephemeral",
    source_trust: "trusted_user",
    sensitivity: ["public"],
    action: "write",
    ...overrides,
  };
}

function validEgressEventData(overrides: Record<string, unknown> = {}) {
  return {
    event_id: uuidv4(),
    event_type: "egress",
    timestamp: new Date().toISOString(),
    egress_id: uuidv4(),
    destination: "https://api.example.com",
    classes_detected: ["pii"],
    transform_applied: "redact",
    bytes_sent: 1024,
    blocked: false,
    ...overrides,
  };
}

function validIntegrityEventData(overrides: Record<string, unknown> = {}) {
  return {
    event_id: uuidv4(),
    event_type: "integrity",
    timestamp: new Date().toISOString(),
    artifact_id: "bundle-v1.0",
    signature_status: "valid",
    bundle_version: "1.0.0",
    ...overrides,
  };
}

// --- Schema validation ---

describe("DecisionEventSchema", () => {
  it("accepts valid decision event", () => {
    const result = DecisionEventSchema.safeParse(validDecisionEventData());
    expect(result.success).toBe(true);
  });

  it("rejects missing decision_id", () => {
    const data = validDecisionEventData();
    delete (data as Record<string, unknown>).decision_id;
    const result = DecisionEventSchema.safeParse(data);
    expect(result.success).toBe(false);
  });

  it("rejects invalid result (not a PolicyEffect)", () => {
    const result = DecisionEventSchema.safeParse(
      validDecisionEventData({ result: "maybe" }),
    );
    expect(result.success).toBe(false);
  });

  it("rejects empty matched_rules", () => {
    const result = DecisionEventSchema.safeParse(
      validDecisionEventData({ matched_rules: [] }),
    );
    expect(result.success).toBe(false);
  });

  it("accepts all PolicyEffect values", () => {
    for (const effect of [
      "allow",
      "allow_with_minimization",
      "require_approval",
      "quarantine",
      "deny",
    ]) {
      const result = DecisionEventSchema.safeParse(
        validDecisionEventData({ result: effect }),
      );
      expect(result.success).toBe(true);
    }
  });

  it("validates input_hashes format", () => {
    const result = DecisionEventSchema.safeParse(
      validDecisionEventData({ input_hashes: ["not-a-hash"] }),
    );
    expect(result.success).toBe(false);
  });
});

describe("ApprovalEventSchema", () => {
  it("accepts valid approval event", () => {
    const result = ApprovalEventSchema.safeParse(validApprovalEventData());
    expect(result.success).toBe(true);
  });

  it("rejects invalid status", () => {
    const result = ApprovalEventSchema.safeParse(
      validApprovalEventData({ status: "pending" }),
    );
    expect(result.success).toBe(false);
  });

  it("accepts all valid statuses", () => {
    for (const status of ["granted", "denied", "expired", "revoked"]) {
      const result = ApprovalEventSchema.safeParse(validApprovalEventData({ status }));
      expect(result.success).toBe(true);
    }
  });

  it("validates scope_hash format", () => {
    const result = ApprovalEventSchema.safeParse(
      validApprovalEventData({ scope_hash: "bad-hash" }),
    );
    expect(result.success).toBe(false);
  });

  it("accepts optional expires_at", () => {
    const result = ApprovalEventSchema.safeParse(
      validApprovalEventData({ expires_at: new Date().toISOString() }),
    );
    expect(result.success).toBe(true);
  });
});

describe("ToolEventSchema", () => {
  it("accepts valid tool event", () => {
    const result = ToolEventSchema.safeParse(validToolEventData());
    expect(result.success).toBe(true);
  });

  it("rejects invalid result", () => {
    const result = ToolEventSchema.safeParse(validToolEventData({ result: "pending" }));
    expect(result.success).toBe(false);
  });

  it("accepts all valid results", () => {
    for (const r of ["allowed", "denied", "error"]) {
      const result = ToolEventSchema.safeParse(validToolEventData({ result: r }));
      expect(result.success).toBe(true);
    }
  });
});

describe("MemoryEventSchema", () => {
  it("accepts valid memory event", () => {
    const result = MemoryEventSchema.safeParse(validMemoryEventData());
    expect(result.success).toBe(true);
  });

  it("rejects invalid tier", () => {
    const result = MemoryEventSchema.safeParse(
      validMemoryEventData({ tier: "permanent" }),
    );
    expect(result.success).toBe(false);
  });

  it("accepts all valid tiers", () => {
    for (const tier of ["ephemeral", "quarantined", "trusted"]) {
      const result = MemoryEventSchema.safeParse(validMemoryEventData({ tier }));
      expect(result.success).toBe(true);
    }
  });

  it("accepts all valid actions", () => {
    for (const action of ["write", "promote", "quarantine", "delete", "expire"]) {
      const result = MemoryEventSchema.safeParse(validMemoryEventData({ action }));
      expect(result.success).toBe(true);
    }
  });

  it("accepts optional ttl", () => {
    const result = MemoryEventSchema.safeParse(validMemoryEventData({ ttl: 3600 }));
    expect(result.success).toBe(true);
  });

  it("rejects non-positive ttl", () => {
    const result = MemoryEventSchema.safeParse(validMemoryEventData({ ttl: 0 }));
    expect(result.success).toBe(false);
  });
});

describe("EgressEventSchema", () => {
  it("accepts valid egress event", () => {
    const result = EgressEventSchema.safeParse(validEgressEventData());
    expect(result.success).toBe(true);
  });

  it("rejects invalid transform", () => {
    const result = EgressEventSchema.safeParse(
      validEgressEventData({ transform_applied: "encrypt" }),
    );
    expect(result.success).toBe(false);
  });

  it("accepts all valid transforms", () => {
    for (const t of ["none", "mask", "tokenize", "redact", "hash"]) {
      const result = EgressEventSchema.safeParse(
        validEgressEventData({ transform_applied: t }),
      );
      expect(result.success).toBe(true);
    }
  });

  it("rejects negative bytes_sent", () => {
    const result = EgressEventSchema.safeParse(validEgressEventData({ bytes_sent: -1 }));
    expect(result.success).toBe(false);
  });
});

describe("IntegrityEventSchema", () => {
  it("accepts valid integrity event", () => {
    const result = IntegrityEventSchema.safeParse(validIntegrityEventData());
    expect(result.success).toBe(true);
  });

  it("rejects invalid signature_status", () => {
    const result = IntegrityEventSchema.safeParse(
      validIntegrityEventData({ signature_status: "unknown" }),
    );
    expect(result.success).toBe(false);
  });

  it("accepts all valid signature statuses", () => {
    for (const s of ["valid", "invalid", "missing", "expired"]) {
      const result = IntegrityEventSchema.safeParse(
        validIntegrityEventData({ signature_status: s }),
      );
      expect(result.success).toBe(true);
    }
  });

  it("accepts optional provenance_ref", () => {
    const result = IntegrityEventSchema.safeParse(
      validIntegrityEventData({ provenance_ref: "https://example.com/provenance" }),
    );
    expect(result.success).toBe(true);
  });
});

// --- Discriminated union ---

describe("AuditEventSchema (discriminated union)", () => {
  it("discriminates decision events", () => {
    const result = AuditEventSchema.safeParse(validDecisionEventData());
    expect(result.success).toBe(true);
    if (result.success) expect(result.data.event_type).toBe("decision");
  });

  it("discriminates approval events", () => {
    const result = AuditEventSchema.safeParse(validApprovalEventData());
    expect(result.success).toBe(true);
    if (result.success) expect(result.data.event_type).toBe("approval");
  });

  it("discriminates tool events", () => {
    const result = AuditEventSchema.safeParse(validToolEventData());
    expect(result.success).toBe(true);
    if (result.success) expect(result.data.event_type).toBe("tool");
  });

  it("discriminates memory events", () => {
    const result = AuditEventSchema.safeParse(validMemoryEventData());
    expect(result.success).toBe(true);
    if (result.success) expect(result.data.event_type).toBe("memory");
  });

  it("discriminates egress events", () => {
    const result = AuditEventSchema.safeParse(validEgressEventData());
    expect(result.success).toBe(true);
    if (result.success) expect(result.data.event_type).toBe("egress");
  });

  it("discriminates integrity events", () => {
    const result = AuditEventSchema.safeParse(validIntegrityEventData());
    expect(result.success).toBe(true);
    if (result.success) expect(result.data.event_type).toBe("integrity");
  });

  it("rejects unknown event_type", () => {
    const result = AuditEventSchema.safeParse({
      ...validDecisionEventData(),
      event_type: "unknown",
    });
    expect(result.success).toBe(false);
  });
});

// --- parseAuditEvent ---

describe("parseAuditEvent", () => {
  it("returns a frozen object", () => {
    const event = parseAuditEvent(validDecisionEventData());
    expect(Object.isFrozen(event)).toBe(true);
  });

  it("throws AuditValidationError on invalid data", () => {
    expect(() => parseAuditEvent({ event_type: "decision" })).toThrow(
      AuditValidationError,
    );
  });

  it("error has toExplanation method", () => {
    try {
      parseAuditEvent({ event_type: "decision" });
    } catch (e) {
      expect(e).toBeInstanceOf(AuditValidationError);
      expect((e as AuditValidationError).toExplanation()).toBeTruthy();
    }
  });

  it("accepts optional correlation_id", () => {
    const event = parseAuditEvent(validDecisionEventData({ correlation_id: uuidv4() }));
    expect(event.correlation_id).toBeTruthy();
  });

  it("works without correlation_id", () => {
    const data = validDecisionEventData();
    delete (data as Record<string, unknown>).correlation_id;
    const event = parseAuditEvent(data);
    expect(event.correlation_id).toBeUndefined();
  });
});
