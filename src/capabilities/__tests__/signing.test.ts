import { describe, it, expect } from "vitest";
import { v4 as uuidv4 } from "uuid";
import {
  createStaticKeyProvider,
  computeTokenSignature,
  verifyTokenSignature,
} from "../signing.js";
import type { CapabilityToken } from "../types.js";

function makeUnsignedToken(overrides: Record<string, unknown> = {}) {
  const now = new Date();
  const expires = new Date(now.getTime() + 300_000);
  return {
    token_id: uuidv4(),
    agent_id: "agent-1",
    task_id: "task-1",
    purpose_tags: ["summarize"],
    working_set_hash: "sha256:abc123",
    allowed_tools: ["tool.read"],
    max_data_class: "internal" as const,
    allowed_destinations: ["local_only"],
    memory_tier: "ephemeral" as const,
    approval_state: "not_required" as const,
    ttl: 300,
    issued_at: now.toISOString(),
    expires_at: expires.toISOString(),
    revoked: false,
    source_decision_id: uuidv4(),
    ...overrides,
  };
}

describe("createStaticKeyProvider", () => {
  it("returns key via getKey()", () => {
    const provider = createStaticKeyProvider("my-secret");
    expect(provider.getKey()).toBe("my-secret");
  });

  it("rejects empty key", () => {
    expect(() => createStaticKeyProvider("")).toThrow();
  });
});

describe("computeTokenSignature", () => {
  it("returns hmac-sha256 prefixed string", () => {
    const key = createStaticKeyProvider("test-key");
    const token = makeUnsignedToken();
    const sig = computeTokenSignature(token, key);
    expect(sig).toMatch(/^hmac-sha256:[0-9a-f]{64}$/);
  });

  it("is deterministic — same token + key = same signature", () => {
    const key = createStaticKeyProvider("test-key");
    const token = makeUnsignedToken();
    const sig1 = computeTokenSignature(token, key);
    const sig2 = computeTokenSignature(token, key);
    expect(sig1).toBe(sig2);
  });

  it("different key produces different signature", () => {
    const key1 = createStaticKeyProvider("key-1");
    const key2 = createStaticKeyProvider("key-2");
    const token = makeUnsignedToken();
    expect(computeTokenSignature(token, key1)).not.toBe(
      computeTokenSignature(token, key2),
    );
  });

  it("any field change produces different signature", () => {
    const key = createStaticKeyProvider("test-key");
    const base = makeUnsignedToken();
    const baseSig = computeTokenSignature(base, key);

    const modified = makeUnsignedToken({ agent_id: "agent-2" });
    expect(computeTokenSignature(modified, key)).not.toBe(baseSig);
  });

  it("canonicalization is stable regardless of property insertion order", () => {
    const key = createStaticKeyProvider("test-key");
    const tokenId = uuidv4();
    const decisionId = uuidv4();
    const now = new Date().toISOString();
    const later = new Date(Date.now() + 300_000).toISOString();

    // Two objects with same data but different insertion order
    const tokenA = {
      token_id: tokenId,
      agent_id: "agent-1",
      task_id: "task-1",
      purpose_tags: ["summarize"],
      working_set_hash: "sha256:abc",
      allowed_tools: ["tool.read"],
      max_data_class: "internal" as const,
      allowed_destinations: ["local_only"],
      memory_tier: "ephemeral" as const,
      approval_state: "not_required" as const,
      ttl: 300,
      issued_at: now,
      expires_at: later,
      revoked: false,
      source_decision_id: decisionId,
    };

    // Reverse insertion order
    const tokenB = {
      source_decision_id: decisionId,
      revoked: false,
      expires_at: later,
      issued_at: now,
      ttl: 300,
      approval_state: "not_required" as const,
      memory_tier: "ephemeral" as const,
      allowed_destinations: ["local_only"],
      max_data_class: "internal" as const,
      allowed_tools: ["tool.read"],
      working_set_hash: "sha256:abc",
      purpose_tags: ["summarize"],
      task_id: "task-1",
      agent_id: "agent-1",
      token_id: tokenId,
    };

    expect(computeTokenSignature(tokenA, key)).toBe(computeTokenSignature(tokenB, key));
  });
});

describe("verifyTokenSignature", () => {
  it("returns true for correctly signed token", () => {
    const key = createStaticKeyProvider("test-key");
    const unsigned = makeUnsignedToken();
    const signature = computeTokenSignature(unsigned, key);
    const signed = { ...unsigned, signature } as CapabilityToken;
    expect(verifyTokenSignature(signed, key)).toBe(true);
  });

  it("returns false for tampered token", () => {
    const key = createStaticKeyProvider("test-key");
    const unsigned = makeUnsignedToken();
    const signature = computeTokenSignature(unsigned, key);
    const tampered = {
      ...unsigned,
      signature,
      agent_id: "evil-agent",
    } as CapabilityToken;
    expect(verifyTokenSignature(tampered, key)).toBe(false);
  });

  it("returns false for wrong key", () => {
    const key1 = createStaticKeyProvider("key-1");
    const key2 = createStaticKeyProvider("key-2");
    const unsigned = makeUnsignedToken();
    const signature = computeTokenSignature(unsigned, key1);
    const signed = { ...unsigned, signature } as CapabilityToken;
    expect(verifyTokenSignature(signed, key2)).toBe(false);
  });

  it("returns false for corrupted signature", () => {
    const key = createStaticKeyProvider("test-key");
    const unsigned = makeUnsignedToken();
    const signed = {
      ...unsigned,
      signature:
        "hmac-sha256:0000000000000000000000000000000000000000000000000000000000000000",
    } as CapabilityToken;
    expect(verifyTokenSignature(signed, key)).toBe(false);
  });
});
