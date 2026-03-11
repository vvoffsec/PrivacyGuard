import { describe, it, expect } from "vitest";
import { generateApprovalPrompt } from "../prompt-generator.js";
import type { PolicyDecision, PolicyInput } from "../../pdp/types.js";

// --- Test helpers ---

function makeDecision(overrides: Partial<PolicyDecision> = {}): PolicyDecision {
  return {
    decision: "require_approval",
    decision_id: "550e8400-e29b-41d4-a716-446655440000",
    policy_id: "pg.test.policy",
    matched_rules: ["rule-sensitive-data", "rule-external-dest"],
    explanation: "Requires approval due to sensitive data",
    policy_bundle_version: "1.0.0",
    ...overrides,
  } as PolicyDecision;
}

function makeInput(overrides: Partial<Record<string, unknown>> = {}): PolicyInput {
  return {
    principal: { type: "agent", id: "agent-1" },
    request: { action: "file.write", purpose: ["backup"], task_id: "task-1" },
    resource: { type: "file", name: "config.json" },
    data: { source_trust: [], sensitivity: ["confidential", "pii"], taint_flags: [] },
    destination: { kind: "cloud-storage", name: "s3-bucket" },
    environment: { host_class: "production", policy_bundle: "v1" },
    ...overrides,
  } as PolicyInput;
}

describe("generateApprovalPrompt", () => {
  it("returns a frozen prompt object", () => {
    const prompt = generateApprovalPrompt(makeDecision(), makeInput());
    expect(Object.isFrozen(prompt)).toBe(true);
  });

  it("uses approval_<decision_id> format for prompt_id", () => {
    const prompt = generateApprovalPrompt(makeDecision(), makeInput());
    expect(prompt.prompt_id).toBe("approval_550e8400-e29b-41d4-a716-446655440000");
  });

  it("carries decision_id from the decision", () => {
    const prompt = generateApprovalPrompt(makeDecision(), makeInput());
    expect(prompt.decision_id).toBe("550e8400-e29b-41d4-a716-446655440000");
  });

  it("extracts action from input", () => {
    const prompt = generateApprovalPrompt(makeDecision(), makeInput());
    expect(prompt.action).toBe("file.write");
  });

  it("extracts destination from input", () => {
    const prompt = generateApprovalPrompt(makeDecision(), makeInput());
    expect(prompt.destination).toBe("s3-bucket");
  });

  it("extracts destination_kind from input", () => {
    const prompt = generateApprovalPrompt(makeDecision(), makeInput());
    expect(prompt.destination_kind).toBe("cloud-storage");
  });

  it("includes valid data classes", () => {
    const prompt = generateApprovalPrompt(makeDecision(), makeInput());
    expect(prompt.data_classes).toContain("confidential");
    expect(prompt.data_classes).toContain("pii");
  });

  it("ignores invalid sensitivity strings in data_classes", () => {
    const input = makeInput({
      data: { source_trust: [], sensitivity: ["invalid", "pii"], taint_flags: [] },
    });
    const prompt = generateApprovalPrompt(makeDecision(), input);
    expect(prompt.data_classes).toEqual(["pii"]);
  });

  it("copies matched_rules to reasons", () => {
    const prompt = generateApprovalPrompt(makeDecision(), makeInput());
    expect(prompt.reasons).toEqual(["rule-sensitive-data", "rule-external-dest"]);
  });

  it("carries policy_id", () => {
    const prompt = generateApprovalPrompt(makeDecision(), makeInput());
    expect(prompt.policy_id).toBe("pg.test.policy");
  });

  it("includes scope_hash in sha256 format", () => {
    const prompt = generateApprovalPrompt(makeDecision(), makeInput());
    expect(prompt.scope_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it("builds explanation with action", () => {
    const prompt = generateApprovalPrompt(makeDecision(), makeInput());
    expect(prompt.explanation).toContain("file.write");
  });

  it("builds explanation with destination", () => {
    const prompt = generateApprovalPrompt(makeDecision(), makeInput());
    expect(prompt.explanation).toContain("s3-bucket");
  });

  it("builds explanation with data classes", () => {
    const prompt = generateApprovalPrompt(makeDecision(), makeInput());
    expect(prompt.explanation).toContain("confidential");
    expect(prompt.explanation).toContain("pii");
  });

  it("builds explanation with matched rules", () => {
    const prompt = generateApprovalPrompt(makeDecision(), makeInput());
    expect(prompt.explanation).toContain("rule-sensitive-data");
  });

  it("builds explanation with policy_id", () => {
    const prompt = generateApprovalPrompt(makeDecision(), makeInput());
    expect(prompt.explanation).toContain("pg.test.policy");
  });

  it("handles empty sensitivity", () => {
    const input = makeInput({
      data: { source_trust: [], sensitivity: [], taint_flags: [] },
    });
    const prompt = generateApprovalPrompt(makeDecision(), input);
    expect(prompt.data_classes).toEqual([]);
  });

  it("handles empty matched_rules (min 1 in schema, but reasons can be passed)", () => {
    // matched_rules requires min(1) in schema, so we test with at least one rule
    const decision = makeDecision({ matched_rules: ["single-rule"] });
    const prompt = generateApprovalPrompt(decision, makeInput());
    expect(prompt.reasons).toEqual(["single-rule"]);
  });

  it("produces deterministic scope_hash for same input", () => {
    const decision = makeDecision();
    const input = makeInput();
    const hash1 = generateApprovalPrompt(decision, input).scope_hash;
    const hash2 = generateApprovalPrompt(decision, input).scope_hash;
    expect(hash1).toBe(hash2);
  });
});
