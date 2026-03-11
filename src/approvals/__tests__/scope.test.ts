import { describe, it, expect } from "vitest";
import { computeScopeHash, scopeCoversRequest, buildScopeFromInput } from "../scope.js";
import type { ApprovalScope } from "../types.js";
import type { PolicyDecision, PolicyInput } from "../../pdp/types.js";
import { ApprovalValidationError } from "../errors.js";

// --- Test helpers ---

function makeScope(overrides: Partial<ApprovalScope> = {}): ApprovalScope {
  return {
    action: "file.write",
    purpose: ["backup"],
    destination: "s3-bucket",
    data_class: "confidential",
    ...overrides,
  };
}

function makeDecision(overrides: Partial<PolicyDecision> = {}): PolicyDecision {
  return {
    decision: "require_approval",
    decision_id: "550e8400-e29b-41d4-a716-446655440000",
    policy_id: "pg.test.policy",
    matched_rules: ["rule-1"],
    explanation: "Requires approval",
    policy_bundle_version: "1.0.0",
    ...overrides,
  } as PolicyDecision;
}

function makeInput(overrides: Partial<Record<string, unknown>> = {}): PolicyInput {
  return {
    principal: { type: "agent", id: "agent-1" },
    request: { action: "file.write", purpose: ["backup"], task_id: "task-1" },
    resource: { type: "file", name: "config.json" },
    data: { source_trust: [], sensitivity: ["confidential"], taint_flags: [] },
    destination: { kind: "cloud-storage", name: "s3-bucket" },
    environment: { host_class: "production", policy_bundle: "v1" },
    ...overrides,
  } as PolicyInput;
}

// --- computeScopeHash ---

describe("computeScopeHash", () => {
  it("returns a sha256-prefixed hash", () => {
    const hash = computeScopeHash(makeScope());
    expect(hash).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it("is deterministic for the same scope", () => {
    const scope = makeScope();
    expect(computeScopeHash(scope)).toBe(computeScopeHash(scope));
  });

  it("is order-independent for purposes", () => {
    const scope1 = makeScope({ purpose: ["alpha", "beta", "gamma"] });
    const scope2 = makeScope({ purpose: ["gamma", "alpha", "beta"] });
    expect(computeScopeHash(scope1)).toBe(computeScopeHash(scope2));
  });

  it("produces different hashes for different actions", () => {
    const scope1 = makeScope({ action: "file.read" });
    const scope2 = makeScope({ action: "file.write" });
    expect(computeScopeHash(scope1)).not.toBe(computeScopeHash(scope2));
  });

  it("produces different hashes for different destinations", () => {
    const scope1 = makeScope({ destination: "bucket-a" });
    const scope2 = makeScope({ destination: "bucket-b" });
    expect(computeScopeHash(scope1)).not.toBe(computeScopeHash(scope2));
  });

  it("produces different hashes for different data classes", () => {
    const scope1 = makeScope({ data_class: "public" });
    const scope2 = makeScope({ data_class: "secret" });
    expect(computeScopeHash(scope1)).not.toBe(computeScopeHash(scope2));
  });

  it("produces different hashes for different purposes", () => {
    const scope1 = makeScope({ purpose: ["read"] });
    const scope2 = makeScope({ purpose: ["write"] });
    expect(computeScopeHash(scope1)).not.toBe(computeScopeHash(scope2));
  });

  it("handles empty purpose array", () => {
    const hash = computeScopeHash(makeScope({ purpose: [] }));
    expect(hash).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it("throws ApprovalValidationError for invalid scope", () => {
    expect(() =>
      computeScopeHash({
        action: "",
        purpose: [],
        destination: "x",
        data_class: "public",
      }),
    ).toThrow(ApprovalValidationError);
  });

  it("throws for invalid data_class", () => {
    expect(() =>
      computeScopeHash({
        action: "read",
        purpose: [],
        destination: "x",
        data_class: "invalid" as "public",
      }),
    ).toThrow(ApprovalValidationError);
  });
});

// --- scopeCoversRequest ---

describe("scopeCoversRequest", () => {
  it("returns true for identical scopes", () => {
    const scope = makeScope();
    expect(scopeCoversRequest(scope, scope)).toBe(true);
  });

  it("returns false for different actions", () => {
    const existing = makeScope({ action: "file.write" });
    const request = makeScope({ action: "file.read" });
    expect(scopeCoversRequest(existing, request)).toBe(false);
  });

  it("returns false for different destinations", () => {
    const existing = makeScope({ destination: "bucket-a" });
    const request = makeScope({ destination: "bucket-b" });
    expect(scopeCoversRequest(existing, request)).toBe(false);
  });

  it("returns true when existing purpose is superset", () => {
    const existing = makeScope({ purpose: ["backup", "analytics"] });
    const request = makeScope({ purpose: ["backup"] });
    expect(scopeCoversRequest(existing, request)).toBe(true);
  });

  it("returns false when existing purpose is subset", () => {
    const existing = makeScope({ purpose: ["backup"] });
    const request = makeScope({ purpose: ["backup", "analytics"] });
    expect(scopeCoversRequest(existing, request)).toBe(false);
  });

  it("returns true when existing data_class is more sensitive", () => {
    const existing = makeScope({ data_class: "secret" });
    const request = makeScope({ data_class: "confidential" });
    expect(scopeCoversRequest(existing, request)).toBe(true);
  });

  it("returns false when existing data_class is less sensitive", () => {
    const existing = makeScope({ data_class: "public" });
    const request = makeScope({ data_class: "confidential" });
    expect(scopeCoversRequest(existing, request)).toBe(false);
  });

  it("returns true for equal data_class", () => {
    const existing = makeScope({ data_class: "pii" });
    const request = makeScope({ data_class: "pii" });
    expect(scopeCoversRequest(existing, request)).toBe(true);
  });

  it("returns true when request has empty purpose", () => {
    const existing = makeScope({ purpose: ["backup"] });
    const request = makeScope({ purpose: [] });
    expect(scopeCoversRequest(existing, request)).toBe(true);
  });

  it("returns true when both have empty purpose", () => {
    const existing = makeScope({ purpose: [] });
    const request = makeScope({ purpose: [] });
    expect(scopeCoversRequest(existing, request)).toBe(true);
  });

  it("treats secret and credential as equivalent sensitivity", () => {
    const existing = makeScope({ data_class: "secret" });
    const request = makeScope({ data_class: "credential" });
    expect(scopeCoversRequest(existing, request)).toBe(true);
  });
});

// --- buildScopeFromInput ---

describe("buildScopeFromInput", () => {
  it("extracts action from input.request.action", () => {
    const scope = buildScopeFromInput(makeDecision(), makeInput());
    expect(scope.action).toBe("file.write");
  });

  it("extracts purpose from input.request.purpose", () => {
    const scope = buildScopeFromInput(
      makeDecision(),
      makeInput({ request: { action: "x", purpose: ["a", "b"], task_id: "t1" } }),
    );
    expect(scope.purpose).toEqual(["a", "b"]);
  });

  it("extracts destination from input.destination.name", () => {
    const scope = buildScopeFromInput(makeDecision(), makeInput());
    expect(scope.destination).toBe("s3-bucket");
  });

  it("computes highest data class from sensitivity", () => {
    const input = makeInput({
      data: {
        source_trust: [],
        sensitivity: ["public", "pii", "internal"],
        taint_flags: [],
      },
    });
    const scope = buildScopeFromInput(makeDecision(), input);
    expect(scope.data_class).toBe("pii");
  });

  it("defaults to public when sensitivity is empty", () => {
    const input = makeInput({
      data: { source_trust: [], sensitivity: [], taint_flags: [] },
    });
    const scope = buildScopeFromInput(makeDecision(), input);
    expect(scope.data_class).toBe("public");
  });

  it("ignores invalid sensitivity strings", () => {
    const input = makeInput({
      data: {
        source_trust: [],
        sensitivity: ["not-a-class", "internal", "also-invalid"],
        taint_flags: [],
      },
    });
    const scope = buildScopeFromInput(makeDecision(), input);
    expect(scope.data_class).toBe("internal");
  });

  it("defaults to public when all sensitivity strings are invalid", () => {
    const input = makeInput({
      data: { source_trust: [], sensitivity: ["invalid1", "invalid2"], taint_flags: [] },
    });
    const scope = buildScopeFromInput(makeDecision(), input);
    expect(scope.data_class).toBe("public");
  });

  it("returns a frozen scope", () => {
    const scope = buildScopeFromInput(makeDecision(), makeInput());
    expect(Object.isFrozen(scope)).toBe(true);
  });
});
