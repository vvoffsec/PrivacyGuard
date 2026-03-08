import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { v4 as uuidv4 } from "uuid";
import { createTokenValidator } from "../validate.js";
import { createTokenMinter } from "../mint.js";
import { createStaticKeyProvider } from "../signing.js";
import { createRevocationRegistry } from "../revocation.js";
import type { PolicyDecision } from "../../pdp/index.js";

const KEY = createStaticKeyProvider("test-validate-key");

function makeDecision(): PolicyDecision {
  return Object.freeze({
    decision: "allow",
    decision_id: uuidv4(),
    policy_id: "pg.default.allow",
    matched_rules: ["rule-1"],
    explanation: "Allowed",
    policy_bundle_version: "0.1.0",
  }) as PolicyDecision;
}

function validMintRequest() {
  return {
    agent_id: "agent-1",
    task_id: "task-1",
    purpose_tags: ["summarize"],
    working_set_hash: "sha256:abc123",
    max_data_class: "internal",
    ttl: 300,
  };
}

describe("createTokenValidator", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-03-08T12:00:00.000Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("validates a valid token", () => {
    const registry = createRevocationRegistry();
    const validator = createTokenValidator(KEY, registry);
    const minter = createTokenMinter(KEY);
    const token = minter.mint(validMintRequest(), makeDecision());

    const result = validator.validate(token);
    expect(result.valid).toBe(true);
    expect(result.token_id).toBe(token.token_id);
    expect(result.failure_reason).toBeUndefined();
  });

  it("returns validation_error for malformed token", () => {
    const registry = createRevocationRegistry();
    const validator = createTokenValidator(KEY, registry);

    const result = validator.validate({ not: "a token" });
    expect(result.valid).toBe(false);
    expect(result.failure_reason).toBe("validation_error");
  });

  it("returns invalid_signature for tampered token", () => {
    const registry = createRevocationRegistry();
    const validator = createTokenValidator(KEY, registry);
    const minter = createTokenMinter(KEY);
    const token = minter.mint(validMintRequest(), makeDecision());

    // Tamper with agent_id
    const tampered = { ...token, agent_id: "evil-agent" };
    const result = validator.validate(tampered);
    expect(result.valid).toBe(false);
    expect(result.failure_reason).toBe("invalid_signature");
    expect(result.token_id).toBe(token.token_id);
  });

  it("returns revoked for revoked token", () => {
    const registry = createRevocationRegistry();
    const validator = createTokenValidator(KEY, registry);
    const minter = createTokenMinter(KEY);
    const token = minter.mint(validMintRequest(), makeDecision());

    registry.revoke(token.token_id);
    const result = validator.validate(token);
    expect(result.valid).toBe(false);
    expect(result.failure_reason).toBe("revoked");
  });

  it("returns expired for expired token", () => {
    const registry = createRevocationRegistry();
    const validator = createTokenValidator(KEY, registry);
    const minter = createTokenMinter(KEY);
    const token = minter.mint(validMintRequest(), makeDecision());

    // Advance time past expiry
    vi.setSystemTime(new Date("2026-03-08T12:10:00.000Z"));
    const result = validator.validate(token);
    expect(result.valid).toBe(false);
    expect(result.failure_reason).toBe("expired");
  });

  it("checks signature before revocation (prevents probing)", () => {
    const registry = createRevocationRegistry();
    const validator = createTokenValidator(KEY, registry);
    const minter = createTokenMinter(KEY);
    const token = minter.mint(validMintRequest(), makeDecision());

    // Both tamper AND revoke
    registry.revoke(token.token_id);
    const tampered = { ...token, agent_id: "evil-agent" };

    const result = validator.validate(tampered);
    // Should fail on signature, not revocation
    expect(result.failure_reason).toBe("invalid_signature");
  });

  it("checks revocation before expiry", () => {
    const registry = createRevocationRegistry();
    const validator = createTokenValidator(KEY, registry);
    const minter = createTokenMinter(KEY);
    const token = minter.mint(validMintRequest(), makeDecision());

    // Both revoke AND expire
    registry.revoke(token.token_id);
    vi.setSystemTime(new Date("2026-03-08T12:10:00.000Z"));

    const result = validator.validate(token);
    // Should fail on revocation, not expiry
    expect(result.failure_reason).toBe("revoked");
  });

  it("returns validation_error for null input", () => {
    const registry = createRevocationRegistry();
    const validator = createTokenValidator(KEY, registry);
    const result = validator.validate(null);
    expect(result.valid).toBe(false);
    expect(result.failure_reason).toBe("validation_error");
  });

  it("returns validation_error for string input", () => {
    const registry = createRevocationRegistry();
    const validator = createTokenValidator(KEY, registry);
    const result = validator.validate("not-a-token");
    expect(result.valid).toBe(false);
    expect(result.failure_reason).toBe("validation_error");
  });

  it("token signed with different key fails signature check", () => {
    const otherKey = createStaticKeyProvider("other-key");
    const registry = createRevocationRegistry();
    const validator = createTokenValidator(KEY, registry);
    const minter = createTokenMinter(otherKey);
    const token = minter.mint(validMintRequest(), makeDecision());

    const result = validator.validate(token);
    expect(result.valid).toBe(false);
    expect(result.failure_reason).toBe("invalid_signature");
  });
});
