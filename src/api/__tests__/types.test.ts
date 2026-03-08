import { describe, it, expect } from "vitest";
import {
  ConfidenceLevelSchema,
  MemoryTierSchema,
  IngressInputSchema,
  IngressEvaluateRequestSchema,
  DetectedClassSummarySchema,
  IngressEvaluateResponseSchema,
  ToolDescriptorSchema,
  ToolAuthorizeRequestSchema,
  ToolAuthorizeResponseSchema,
  MemoryEntrySchema,
  MemoryWriteRequestSchema,
  MemoryWriteResponseSchema,
  DecisionExplainRequestSchema,
  DecisionExplainResponseSchema,
  parseIngressEvaluateRequest,
  parseToolAuthorizeRequest,
  parseMemoryWriteRequest,
  parseDecisionExplainRequest,
} from "../types.js";
import { ApiValidationError } from "../errors.js";

const UUID = "12345678-1234-4234-8234-123456789012";

describe("ConfidenceLevelSchema", () => {
  it("accepts valid levels", () => {
    expect(ConfidenceLevelSchema.parse("low")).toBe("low");
    expect(ConfidenceLevelSchema.parse("medium")).toBe("medium");
    expect(ConfidenceLevelSchema.parse("high")).toBe("high");
  });

  it("rejects invalid values", () => {
    expect(() => ConfidenceLevelSchema.parse("extreme")).toThrow();
  });
});

describe("MemoryTierSchema", () => {
  it("accepts valid tiers", () => {
    expect(MemoryTierSchema.parse("ephemeral")).toBe("ephemeral");
    expect(MemoryTierSchema.parse("session")).toBe("session");
    expect(MemoryTierSchema.parse("durable")).toBe("durable");
  });

  it("rejects quarantined (not a valid request tier)", () => {
    expect(() => MemoryTierSchema.parse("quarantined")).toThrow();
  });
});

describe("IngressInputSchema", () => {
  it("accepts valid input", () => {
    const result = IngressInputSchema.parse({
      content: "Hello",
      source_type: "user_input",
      source_trust: "trusted_user",
    });
    expect(result.content).toBe("Hello");
  });

  it("rejects empty content", () => {
    expect(() =>
      IngressInputSchema.parse({
        content: "",
        source_type: "user_input",
        source_trust: "trusted_user",
      }),
    ).toThrow();
  });

  it("accepts optional metadata", () => {
    const result = IngressInputSchema.parse({
      content: "Hello",
      source_type: "user_input",
      source_trust: "trusted_user",
      metadata: { key: "value" },
    });
    expect(result.metadata).toEqual({ key: "value" });
  });
});

describe("IngressEvaluateRequestSchema", () => {
  it("accepts valid request", () => {
    const result = IngressEvaluateRequestSchema.parse({
      input: {
        content: "Hello",
        source_type: "user_input",
        source_trust: "trusted_user",
      },
      actor_id: "user-1",
      agent_id: "agent-1",
      purpose: "user_request",
      task_id: "task-1",
    });
    expect(result.actor_id).toBe("user-1");
  });

  it("rejects missing fields", () => {
    expect(() => IngressEvaluateRequestSchema.parse({})).toThrow();
  });

  it("rejects empty agent_id", () => {
    expect(() =>
      IngressEvaluateRequestSchema.parse({
        input: {
          content: "Hello",
          source_type: "user_input",
          source_trust: "trusted_user",
        },
        actor_id: "user-1",
        agent_id: "",
        purpose: "user_request",
        task_id: "task-1",
      }),
    ).toThrow();
  });
});

describe("DetectedClassSummarySchema", () => {
  it("accepts valid summary", () => {
    const result = DetectedClassSummarySchema.parse({
      data_class: "pii",
      confidence: "high",
      entity_count: 5,
    });
    expect(result.data_class).toBe("pii");
    expect(result.entity_count).toBe(5);
  });

  it("rejects negative entity_count", () => {
    expect(() =>
      DetectedClassSummarySchema.parse({
        data_class: "pii",
        confidence: "high",
        entity_count: -1,
      }),
    ).toThrow();
  });
});

describe("IngressEvaluateResponseSchema", () => {
  it("accepts valid response", () => {
    const result = IngressEvaluateResponseSchema.parse({
      decision_id: UUID,
      effect: "allow",
      policy_id: "pg.default",
      explanation: "Allowed",
      detected: [],
      working_set_ref: "ws_123",
    });
    expect(result.effect).toBe("allow");
  });
});

describe("ToolDescriptorSchema", () => {
  it("accepts valid descriptor", () => {
    const result = ToolDescriptorSchema.parse({
      name: "file_read",
      action: "read",
    });
    expect(result.name).toBe("file_read");
  });

  it("accepts optional parameters", () => {
    const result = ToolDescriptorSchema.parse({
      name: "file_read",
      action: "read",
      parameters: { path: "/etc/passwd" },
    });
    expect(result.parameters).toEqual({ path: "/etc/passwd" });
  });

  it("rejects empty name", () => {
    expect(() => ToolDescriptorSchema.parse({ name: "", action: "read" })).toThrow();
  });
});

describe("ToolAuthorizeRequestSchema", () => {
  it("accepts valid request", () => {
    const result = ToolAuthorizeRequestSchema.parse({
      tool: { name: "file_read", action: "read" },
      capability_token: "token-123",
      agent_id: "agent-1",
      task_id: "task-1",
    });
    expect(result.capability_token).toBe("token-123");
  });

  it("accepts optional destination and sensitivity", () => {
    const result = ToolAuthorizeRequestSchema.parse({
      tool: { name: "http", action: "send" },
      capability_token: "token-123",
      agent_id: "agent-1",
      task_id: "task-1",
      requested_destination: "api.example.com",
      data_sensitivity: ["pii", "internal"],
    });
    expect(result.requested_destination).toBe("api.example.com");
    expect(result.data_sensitivity).toEqual(["pii", "internal"]);
  });

  it("rejects missing tool", () => {
    expect(() =>
      ToolAuthorizeRequestSchema.parse({
        capability_token: "token-123",
        agent_id: "agent-1",
        task_id: "task-1",
      }),
    ).toThrow();
  });
});

describe("ToolAuthorizeResponseSchema", () => {
  it("accepts valid response", () => {
    const result = ToolAuthorizeResponseSchema.parse({
      decision_id: UUID,
      effect: "allow",
      policy_id: "pg.default",
      explanation: "Allowed",
      reasons: [],
    });
    expect(result.effect).toBe("allow");
  });

  it("accepts optional approval_prompt_ref", () => {
    const result = ToolAuthorizeResponseSchema.parse({
      decision_id: UUID,
      effect: "require_approval",
      policy_id: "pg.exec",
      explanation: "Needs approval",
      reasons: ["pg.exec"],
      approval_prompt_ref: "approval_123",
    });
    expect(result.approval_prompt_ref).toBe("approval_123");
  });
});

describe("MemoryEntrySchema", () => {
  it("accepts valid entry", () => {
    const result = MemoryEntrySchema.parse({
      key: "test-key",
      value: "test-value",
      source_trust: "trusted_user",
    });
    expect(result.key).toBe("test-key");
  });

  it("defaults sensitivity to empty array", () => {
    const result = MemoryEntrySchema.parse({
      key: "k",
      value: "v",
      source_trust: "trusted_user",
    });
    expect(result.sensitivity).toEqual([]);
  });

  it("accepts sensitivity labels", () => {
    const result = MemoryEntrySchema.parse({
      key: "k",
      value: "v",
      source_trust: "trusted_user",
      sensitivity: ["pii", "confidential"],
    });
    expect(result.sensitivity).toEqual(["pii", "confidential"]);
  });
});

describe("MemoryWriteRequestSchema", () => {
  it("accepts valid request", () => {
    const result = MemoryWriteRequestSchema.parse({
      entry: { key: "k", value: "v", source_trust: "trusted_user" },
      memory_tier: "session",
      agent_id: "agent-1",
      task_id: "task-1",
    });
    expect(result.memory_tier).toBe("session");
  });

  it("accepts optional ttl_seconds", () => {
    const result = MemoryWriteRequestSchema.parse({
      entry: { key: "k", value: "v", source_trust: "trusted_user" },
      memory_tier: "ephemeral",
      agent_id: "agent-1",
      task_id: "task-1",
      ttl_seconds: 300,
    });
    expect(result.ttl_seconds).toBe(300);
  });

  it("rejects non-positive ttl_seconds", () => {
    expect(() =>
      MemoryWriteRequestSchema.parse({
        entry: { key: "k", value: "v", source_trust: "trusted_user" },
        memory_tier: "session",
        agent_id: "agent-1",
        task_id: "task-1",
        ttl_seconds: 0,
      }),
    ).toThrow();
  });
});

describe("MemoryWriteResponseSchema", () => {
  it("accepts valid response with quarantined tier", () => {
    const result = MemoryWriteResponseSchema.parse({
      decision_id: UUID,
      effect: "quarantine",
      policy_id: "pg.memory",
      explanation: "Quarantined",
      entry_id: UUID,
      effective_tier: "quarantined",
    });
    expect(result.effective_tier).toBe("quarantined");
  });
});

describe("DecisionExplainRequestSchema", () => {
  it("accepts valid UUID", () => {
    const result = DecisionExplainRequestSchema.parse({
      decision_id: UUID,
    });
    expect(result.decision_id).toBe(UUID);
  });

  it("rejects non-UUID", () => {
    expect(() =>
      DecisionExplainRequestSchema.parse({ decision_id: "not-a-uuid" }),
    ).toThrow();
  });
});

describe("DecisionExplainResponseSchema", () => {
  it("accepts valid response", () => {
    const result = DecisionExplainResponseSchema.parse({
      decision_id: UUID,
      decision: "deny",
      policy_id: "pg.egress",
      matched_rules: ["pg.egress.secret"],
      explanation: "Blocked secret egress",
    });
    expect(result.decision).toBe("deny");
  });

  it("rejects empty matched_rules", () => {
    expect(() =>
      DecisionExplainResponseSchema.parse({
        decision_id: UUID,
        decision: "allow",
        policy_id: "pg.default",
        matched_rules: [],
        explanation: "Allowed",
      }),
    ).toThrow();
  });
});

describe("parseIngressEvaluateRequest", () => {
  it("returns frozen object for valid input", () => {
    const result = parseIngressEvaluateRequest({
      input: {
        content: "Hello",
        source_type: "user_input",
        source_trust: "trusted_user",
      },
      actor_id: "user-1",
      agent_id: "agent-1",
      purpose: "user_request",
      task_id: "task-1",
    });
    expect(Object.isFrozen(result)).toBe(true);
  });

  it("throws ApiValidationError for invalid input", () => {
    expect(() => parseIngressEvaluateRequest({})).toThrow(ApiValidationError);
  });
});

describe("parseToolAuthorizeRequest", () => {
  it("returns frozen object for valid input", () => {
    const result = parseToolAuthorizeRequest({
      tool: { name: "file_read", action: "read" },
      capability_token: "token-123",
      agent_id: "agent-1",
      task_id: "task-1",
    });
    expect(Object.isFrozen(result)).toBe(true);
  });

  it("throws ApiValidationError for invalid input", () => {
    expect(() => parseToolAuthorizeRequest({})).toThrow(ApiValidationError);
  });
});

describe("parseMemoryWriteRequest", () => {
  it("returns frozen object for valid input", () => {
    const result = parseMemoryWriteRequest({
      entry: { key: "k", value: "v", source_trust: "trusted_user" },
      memory_tier: "session",
      agent_id: "agent-1",
      task_id: "task-1",
    });
    expect(Object.isFrozen(result)).toBe(true);
  });

  it("throws ApiValidationError for invalid input", () => {
    expect(() => parseMemoryWriteRequest({})).toThrow(ApiValidationError);
  });
});

describe("parseDecisionExplainRequest", () => {
  it("returns frozen object for valid input", () => {
    const result = parseDecisionExplainRequest({ decision_id: UUID });
    expect(Object.isFrozen(result)).toBe(true);
  });

  it("throws ApiValidationError for invalid input", () => {
    expect(() => parseDecisionExplainRequest({})).toThrow(ApiValidationError);
  });
});
