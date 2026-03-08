import { describe, it, expect } from "vitest";
import { v4 as uuidv4 } from "uuid";
import {
  parseCapabilityToken,
  parseMintTokenRequest,
  MemoryTierSchema,
  ApprovalStateSchema,
  CapabilityTokenSchema,
  MintTokenRequestSchema,
} from "../types.js";
import { TokenValidationError } from "../errors.js";

function validTokenData(overrides: Record<string, unknown> = {}) {
  const now = new Date();
  const expires = new Date(now.getTime() + 300_000);
  return {
    token_id: uuidv4(),
    agent_id: "agent-1",
    task_id: "task-1",
    purpose_tags: ["summarize"],
    working_set_hash: "sha256:abc123",
    allowed_tools: ["tool.read"],
    max_data_class: "internal",
    allowed_destinations: ["local_only"],
    memory_tier: "ephemeral",
    approval_state: "not_required",
    ttl: 300,
    issued_at: now.toISOString(),
    expires_at: expires.toISOString(),
    signature: "hmac-sha256:deadbeef",
    revoked: false,
    source_decision_id: uuidv4(),
    ...overrides,
  };
}

function validMintRequestData(overrides: Record<string, unknown> = {}) {
  return {
    agent_id: "agent-1",
    task_id: "task-1",
    purpose_tags: ["summarize"],
    working_set_hash: "sha256:abc123",
    max_data_class: "internal",
    ...overrides,
  };
}

describe("parseCapabilityToken", () => {
  it("parses a valid token", () => {
    const data = validTokenData();
    const token = parseCapabilityToken(data);
    expect(token.agent_id).toBe("agent-1");
    expect(token.task_id).toBe("task-1");
    expect(token.purpose_tags).toEqual(["summarize"]);
  });

  it("returns a frozen object", () => {
    const token = parseCapabilityToken(validTokenData());
    expect(Object.isFrozen(token)).toBe(true);
  });

  it("rejects missing required fields", () => {
    expect(() => parseCapabilityToken({})).toThrow(TokenValidationError);
  });

  it("rejects invalid token_id (non-uuid)", () => {
    expect(() =>
      parseCapabilityToken(validTokenData({ token_id: "not-a-uuid" })),
    ).toThrow(TokenValidationError);
  });

  it("rejects empty agent_id", () => {
    expect(() => parseCapabilityToken(validTokenData({ agent_id: "" }))).toThrow(
      TokenValidationError,
    );
  });

  it("rejects empty task_id", () => {
    expect(() => parseCapabilityToken(validTokenData({ task_id: "" }))).toThrow(
      TokenValidationError,
    );
  });

  it("rejects empty purpose_tags", () => {
    expect(() => parseCapabilityToken(validTokenData({ purpose_tags: [] }))).toThrow(
      TokenValidationError,
    );
  });

  it("rejects non-positive TTL", () => {
    expect(() => parseCapabilityToken(validTokenData({ ttl: 0 }))).toThrow(
      TokenValidationError,
    );
    expect(() => parseCapabilityToken(validTokenData({ ttl: -1 }))).toThrow(
      TokenValidationError,
    );
  });

  it("rejects invalid max_data_class", () => {
    expect(() =>
      parseCapabilityToken(validTokenData({ max_data_class: "top_secret" })),
    ).toThrow(TokenValidationError);
  });

  it("rejects invalid memory_tier", () => {
    expect(() =>
      parseCapabilityToken(validTokenData({ memory_tier: "permanent" })),
    ).toThrow(TokenValidationError);
  });

  it("rejects invalid source_decision_id", () => {
    expect(() =>
      parseCapabilityToken(validTokenData({ source_decision_id: "not-uuid" })),
    ).toThrow(TokenValidationError);
  });

  it("rejects null input", () => {
    expect(() => parseCapabilityToken(null)).toThrow(TokenValidationError);
  });

  it("rejects non-object input", () => {
    expect(() => parseCapabilityToken("string")).toThrow(TokenValidationError);
  });

  it("provides explanation with path info", () => {
    try {
      parseCapabilityToken({});
      expect.fail("should have thrown");
    } catch (error) {
      expect(error).toBeInstanceOf(TokenValidationError);
      const explanation = (error as TokenValidationError).toExplanation();
      expect(explanation.length).toBeGreaterThan(0);
    }
  });
});

describe("parseMintTokenRequest", () => {
  it("parses a valid request with defaults", () => {
    const request = parseMintTokenRequest(validMintRequestData());
    expect(request.agent_id).toBe("agent-1");
    expect(request.ttl).toBe(300);
    expect(request.memory_tier).toBe("ephemeral");
    expect(request.allowed_tools).toEqual([]);
    expect(request.allowed_destinations).toEqual([]);
    expect(request.approval_state).toBe("not_required");
  });

  it("returns a frozen object", () => {
    const request = parseMintTokenRequest(validMintRequestData());
    expect(Object.isFrozen(request)).toBe(true);
  });

  it("accepts custom TTL", () => {
    const request = parseMintTokenRequest(validMintRequestData({ ttl: 600 }));
    expect(request.ttl).toBe(600);
  });

  it("accepts custom memory_tier", () => {
    const request = parseMintTokenRequest(
      validMintRequestData({ memory_tier: "session" }),
    );
    expect(request.memory_tier).toBe("session");
  });

  it("rejects empty purpose_tags", () => {
    expect(() =>
      parseMintTokenRequest(validMintRequestData({ purpose_tags: [] })),
    ).toThrow(TokenValidationError);
  });

  it("rejects missing required fields", () => {
    expect(() => parseMintTokenRequest({})).toThrow(TokenValidationError);
  });

  it("rejects non-positive TTL", () => {
    expect(() => parseMintTokenRequest(validMintRequestData({ ttl: 0 }))).toThrow(
      TokenValidationError,
    );
  });
});

describe("MemoryTierSchema", () => {
  it("accepts valid memory tiers", () => {
    for (const tier of ["ephemeral", "session", "durable"]) {
      expect(MemoryTierSchema.safeParse(tier).success).toBe(true);
    }
  });

  it("rejects invalid memory tier", () => {
    expect(MemoryTierSchema.safeParse("permanent").success).toBe(false);
  });
});

describe("ApprovalStateSchema", () => {
  it("accepts valid approval states", () => {
    for (const state of ["not_required", "pending", "approved", "denied"]) {
      expect(ApprovalStateSchema.safeParse(state).success).toBe(true);
    }
  });

  it("rejects invalid approval state", () => {
    expect(ApprovalStateSchema.safeParse("maybe").success).toBe(false);
  });
});

describe("CapabilityTokenSchema", () => {
  it("accepts all valid data classes for max_data_class", () => {
    for (const cls of [
      "public",
      "internal",
      "confidential",
      "restricted",
      "pii",
      "secret",
      "credential",
    ]) {
      const result = CapabilityTokenSchema.safeParse(
        validTokenData({ max_data_class: cls }),
      );
      expect(result.success).toBe(true);
    }
  });
});

describe("MintTokenRequestSchema", () => {
  it("applies all defaults", () => {
    const result = MintTokenRequestSchema.safeParse(validMintRequestData());
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.ttl).toBe(300);
      expect(result.data.memory_tier).toBe("ephemeral");
      expect(result.data.allowed_tools).toEqual([]);
      expect(result.data.allowed_destinations).toEqual([]);
    }
  });
});
