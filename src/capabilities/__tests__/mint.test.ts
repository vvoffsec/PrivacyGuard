import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { v4 as uuidv4 } from "uuid";
import { createTokenMinter } from "../mint.js";
import { createStaticKeyProvider, verifyTokenSignature } from "../signing.js";
import { TokenMintError } from "../errors.js";
import { TokenValidationError } from "../errors.js";
import type { PolicyDecision } from "../../pdp/index.js";

const KEY = createStaticKeyProvider("test-mint-key");

function makeDecision(overrides: Partial<PolicyDecision> = {}): PolicyDecision {
  return Object.freeze({
    decision: "allow",
    decision_id: uuidv4(),
    policy_id: "pg.default.allow",
    matched_rules: ["rule-1"],
    explanation: "Allowed by default",
    policy_bundle_version: "0.1.0",
    ...overrides,
  }) as PolicyDecision;
}

function validMintRequest(overrides: Record<string, unknown> = {}) {
  return {
    agent_id: "agent-1",
    task_id: "task-1",
    purpose_tags: ["summarize"],
    working_set_hash: "sha256:abc123",
    max_data_class: "internal",
    allowed_tools: ["tool.read"],
    allowed_destinations: ["local_only"],
    ...overrides,
  };
}

describe("createTokenMinter", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-03-08T12:00:00.000Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("mints a token from an allow decision", () => {
    const minter = createTokenMinter(KEY);
    const decision = makeDecision({ decision: "allow" });
    const token = minter.mint(validMintRequest(), decision);

    expect(token.agent_id).toBe("agent-1");
    expect(token.task_id).toBe("task-1");
    expect(token.purpose_tags).toEqual(["summarize"]);
    expect(token.revoked).toBe(false);
  });

  it("mints a token from an allow_with_minimization decision", () => {
    const minter = createTokenMinter(KEY);
    const decision = makeDecision({ decision: "allow_with_minimization" });
    const token = minter.mint(validMintRequest(), decision);
    expect(token.agent_id).toBe("agent-1");
  });

  it("throws TokenMintError for deny decision", () => {
    const minter = createTokenMinter(KEY);
    const decision = makeDecision({ decision: "deny" });
    expect(() => minter.mint(validMintRequest(), decision)).toThrow(TokenMintError);
  });

  it("throws TokenMintError for require_approval decision", () => {
    const minter = createTokenMinter(KEY);
    const decision = makeDecision({ decision: "require_approval" });
    expect(() => minter.mint(validMintRequest(), decision)).toThrow(TokenMintError);
  });

  it("throws TokenMintError for quarantine decision", () => {
    const minter = createTokenMinter(KEY);
    const decision = makeDecision({ decision: "quarantine" });
    expect(() => minter.mint(validMintRequest(), decision)).toThrow(TokenMintError);
  });

  it("sets source_decision_id from decision", () => {
    const minter = createTokenMinter(KEY);
    const decision = makeDecision();
    const token = minter.mint(validMintRequest(), decision);
    expect(token.source_decision_id).toBe(decision.decision_id);
  });

  it("computes expires_at = issued_at + TTL", () => {
    const minter = createTokenMinter(KEY);
    const decision = makeDecision();
    const token = minter.mint(validMintRequest({ ttl: 600 }), decision);

    const issued = new Date(token.issued_at).getTime();
    const expires = new Date(token.expires_at).getTime();
    expect(expires - issued).toBe(600_000);
  });

  it("uses default TTL of 300 when not specified", () => {
    const minter = createTokenMinter(KEY);
    const decision = makeDecision();
    const token = minter.mint(validMintRequest(), decision);

    const issued = new Date(token.issued_at).getTime();
    const expires = new Date(token.expires_at).getTime();
    expect(expires - issued).toBe(300_000);
  });

  it("minted token has a valid verifiable signature", () => {
    const minter = createTokenMinter(KEY);
    const decision = makeDecision();
    const token = minter.mint(validMintRequest(), decision);
    expect(verifyTokenSignature(token, KEY)).toBe(true);
  });

  it("minted token is frozen", () => {
    const minter = createTokenMinter(KEY);
    const decision = makeDecision();
    const token = minter.mint(validMintRequest(), decision);
    expect(Object.isFrozen(token)).toBe(true);
  });

  it("generates unique token_id for each mint", () => {
    const minter = createTokenMinter(KEY);
    const decision = makeDecision();
    const token1 = minter.mint(validMintRequest(), decision);
    const token2 = minter.mint(validMintRequest(), decision);
    expect(token1.token_id).not.toBe(token2.token_id);
  });

  it("uses deterministic issued_at based on current time", () => {
    const minter = createTokenMinter(KEY);
    const decision = makeDecision();
    const token = minter.mint(validMintRequest(), decision);
    expect(token.issued_at).toBe("2026-03-08T12:00:00.000Z");
  });

  it("throws TokenValidationError for invalid mint request", () => {
    const minter = createTokenMinter(KEY);
    const decision = makeDecision();
    expect(() => minter.mint({}, decision)).toThrow(TokenValidationError);
  });

  it("applies default memory_tier of ephemeral", () => {
    const minter = createTokenMinter(KEY);
    const decision = makeDecision();
    const token = minter.mint(validMintRequest(), decision);
    expect(token.memory_tier).toBe("ephemeral");
  });
});
