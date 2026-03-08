import { describe, it, expect } from "vitest";
import { v4 as uuidv4 } from "uuid";
import { checkScope } from "../scope.js";
import type { CapabilityToken, ScopeCheckRequest } from "../types.js";

function makeToken(overrides: Partial<CapabilityToken> = {}): CapabilityToken {
  const now = new Date();
  const expires = new Date(now.getTime() + 300_000);
  return Object.freeze({
    token_id: uuidv4(),
    agent_id: "agent-1",
    task_id: "task-1",
    purpose_tags: ["summarize"],
    working_set_hash: "sha256:abc123",
    allowed_tools: ["tool.read", "tool.write"],
    max_data_class: "confidential",
    allowed_destinations: ["local_only", "approved_remote"],
    memory_tier: "session",
    approval_state: "not_required",
    ttl: 300,
    issued_at: now.toISOString(),
    expires_at: expires.toISOString(),
    signature: "hmac-sha256:fake",
    revoked: false,
    source_decision_id: uuidv4(),
    ...overrides,
  }) as CapabilityToken;
}

describe("checkScope", () => {
  // --- Tool checks ---
  it("allows a tool that is in allowed_tools", () => {
    const token = makeToken();
    const result = checkScope(token, { tool: "tool.read" });
    expect(result.allowed).toBe(true);
    expect(result.denial_reasons).toEqual([]);
  });

  it("denies a tool that is not in allowed_tools", () => {
    const token = makeToken();
    const result = checkScope(token, { tool: "tool.delete" });
    expect(result.allowed).toBe(false);
    expect(result.denial_reasons).toHaveLength(1);
    expect(result.denial_reasons[0]).toContain("tool.delete");
  });

  it("allows any tool when allowed_tools is empty (unconstrained)", () => {
    const token = makeToken({ allowed_tools: [] });
    const result = checkScope(token, { tool: "anything" });
    expect(result.allowed).toBe(true);
  });

  // --- Destination checks ---
  it("allows a destination that is in allowed_destinations", () => {
    const token = makeToken();
    const result = checkScope(token, { destination: "local_only" });
    expect(result.allowed).toBe(true);
  });

  it("denies a destination not in allowed_destinations", () => {
    const token = makeToken();
    const result = checkScope(token, { destination: "evil_server" });
    expect(result.allowed).toBe(false);
    expect(result.denial_reasons[0]).toContain("evil_server");
  });

  it("allows any destination when allowed_destinations is empty (unconstrained)", () => {
    const token = makeToken({ allowed_destinations: [] });
    const result = checkScope(token, { destination: "anywhere" });
    expect(result.allowed).toBe(true);
  });

  // --- Data class checks ---
  it("allows data_class at max_data_class", () => {
    const token = makeToken({ max_data_class: "confidential" });
    const result = checkScope(token, { data_class: "confidential" });
    expect(result.allowed).toBe(true);
  });

  it("allows data_class below max_data_class", () => {
    const token = makeToken({ max_data_class: "confidential" });
    const result = checkScope(token, { data_class: "public" });
    expect(result.allowed).toBe(true);
  });

  it("denies data_class above max_data_class", () => {
    const token = makeToken({ max_data_class: "confidential" });
    const result = checkScope(token, { data_class: "secret" });
    expect(result.allowed).toBe(false);
    expect(result.denial_reasons[0]).toContain("secret");
  });

  it("handles secret/credential equivalence", () => {
    const tokenSecret = makeToken({ max_data_class: "secret" });
    const resultCred = checkScope(tokenSecret, { data_class: "credential" });
    expect(resultCred.allowed).toBe(true);

    const tokenCred = makeToken({ max_data_class: "credential" });
    const resultSecret = checkScope(tokenCred, { data_class: "secret" });
    expect(resultSecret.allowed).toBe(true);
  });

  // --- Memory tier checks ---
  it("allows memory_tier at token tier", () => {
    const token = makeToken({ memory_tier: "session" });
    const result = checkScope(token, { memory_tier: "session" });
    expect(result.allowed).toBe(true);
  });

  it("allows memory_tier below token tier", () => {
    const token = makeToken({ memory_tier: "session" });
    const result = checkScope(token, { memory_tier: "ephemeral" });
    expect(result.allowed).toBe(true);
  });

  it("denies memory_tier above token tier", () => {
    const token = makeToken({ memory_tier: "ephemeral" });
    const result = checkScope(token, { memory_tier: "durable" });
    expect(result.allowed).toBe(false);
    expect(result.denial_reasons[0]).toContain("durable");
  });

  // --- Multiple violations ---
  it("collects multiple denial reasons", () => {
    const token = makeToken({
      allowed_tools: ["tool.read"],
      allowed_destinations: ["local_only"],
      max_data_class: "public",
      memory_tier: "ephemeral",
    });

    const request: ScopeCheckRequest = {
      tool: "tool.delete",
      destination: "evil_server",
      data_class: "secret",
      memory_tier: "durable",
    };

    const result = checkScope(token, request);
    expect(result.allowed).toBe(false);
    expect(result.denial_reasons).toHaveLength(4);
  });

  // --- Empty request ---
  it("empty request is always allowed", () => {
    const token = makeToken();
    const result = checkScope(token, {});
    expect(result.allowed).toBe(true);
    expect(result.denial_reasons).toEqual([]);
  });
});
