import { describe, it, expect } from "vitest";
import { InProcessPolicyEngine } from "../local-engine.js";
import { createPolicyBundle } from "../policy-bundle.js";
import { createPolicyRule } from "../policy-rule.js";
import { PolicyEvaluationError } from "../errors.js";
import { parsePolicyInput, type PolicyInput } from "../types.js";

function makeInput(overrides: Record<string, unknown> = {}): PolicyInput {
  return parsePolicyInput({
    principal: { type: "agent", id: "agent-1" },
    request: { action: "read", purpose: [], task_id: "task-1" },
    resource: { type: "file", name: "test.txt" },
    data: { source_trust: [], sensitivity: [], taint_flags: [] },
    destination: { kind: "local", name: "stdout" },
    environment: { host_class: "workstation", policy_bundle: "default" },
    ...overrides,
  });
}

function makeEngine(
  rules: {
    id: string;
    effect:
      | "allow"
      | "allow_with_minimization"
      | "require_approval"
      | "quarantine"
      | "deny";
    evaluate: (input: PolicyInput) => boolean;
  }[],
) {
  const policyRules = rules.map((r) =>
    createPolicyRule({
      id: r.id,
      description: `Rule ${r.id}`,
      effect: r.effect,
      evaluate: r.evaluate,
    }),
  );
  const bundle = createPolicyBundle({ version: "1.0.0", rules: policyRules });
  return new InProcessPolicyEngine(bundle);
}

describe("InProcessPolicyEngine", () => {
  it("returns allow when no rules match", () => {
    const engine = makeEngine([{ id: "r1", effect: "deny", evaluate: () => false }]);
    const decision = engine.evaluate(makeInput());
    expect(decision.decision).toBe("allow");
    expect(decision.policy_id).toBe("pg.default.allow");
    expect(decision.matched_rules).toEqual(["no_rule_matched"]);
  });

  it("returns the bundle version in decisions", () => {
    const engine = makeEngine([{ id: "r1", effect: "allow", evaluate: () => false }]);
    const decision = engine.evaluate(makeInput());
    expect(decision.policy_bundle_version).toBe("1.0.0");
    expect(engine.bundleVersion).toBe("1.0.0");
  });

  it("returns deny when a deny rule matches", () => {
    const engine = makeEngine([{ id: "r1", effect: "deny", evaluate: () => true }]);
    const decision = engine.evaluate(makeInput());
    expect(decision.decision).toBe("deny");
    expect(decision.policy_id).toBe("r1");
    expect(decision.matched_rules).toContain("r1");
  });

  it("returns quarantine when a quarantine rule matches", () => {
    const engine = makeEngine([{ id: "r1", effect: "quarantine", evaluate: () => true }]);
    const decision = engine.evaluate(makeInput());
    expect(decision.decision).toBe("quarantine");
  });

  it("returns require_approval with required_actions", () => {
    const engine = makeEngine([
      { id: "r1", effect: "require_approval", evaluate: () => true },
    ]);
    const decision = engine.evaluate(makeInput());
    expect(decision.decision).toBe("require_approval");
    expect(decision.required_actions).toBeDefined();
    expect(decision.required_actions?.[0]?.type).toBe("user_approval");
  });

  it("returns allow_with_minimization with required_actions", () => {
    const engine = makeEngine([
      { id: "r1", effect: "allow_with_minimization", evaluate: () => true },
    ]);
    const decision = engine.evaluate(makeInput());
    expect(decision.decision).toBe("allow_with_minimization");
    expect(decision.required_actions).toBeDefined();
    expect(decision.required_actions?.[0]?.type).toBe("minimize");
  });

  it("returns allow match with no required_actions", () => {
    const engine = makeEngine([{ id: "r1", effect: "allow", evaluate: () => true }]);
    const decision = engine.evaluate(makeInput());
    expect(decision.decision).toBe("allow");
    expect(decision.required_actions).toBeUndefined();
  });

  it("picks most restrictive effect when multiple rules match", () => {
    const engine = makeEngine([
      { id: "r1", effect: "allow", evaluate: () => true },
      { id: "r2", effect: "deny", evaluate: () => true },
      { id: "r3", effect: "quarantine", evaluate: () => true },
    ]);
    const decision = engine.evaluate(makeInput());
    expect(decision.decision).toBe("deny");
    expect(decision.policy_id).toBe("r2");
  });

  it("collects all matched rule IDs", () => {
    const engine = makeEngine([
      { id: "r1", effect: "allow", evaluate: () => true },
      { id: "r2", effect: "deny", evaluate: () => true },
      { id: "r3", effect: "quarantine", evaluate: () => true },
    ]);
    const decision = engine.evaluate(makeInput());
    expect(decision.matched_rules).toEqual(["r1", "r2", "r3"]);
  });

  it("only includes matching rules in matched_rules", () => {
    const engine = makeEngine([
      { id: "r1", effect: "allow", evaluate: () => true },
      { id: "r2", effect: "deny", evaluate: () => false },
      { id: "r3", effect: "quarantine", evaluate: () => true },
    ]);
    const decision = engine.evaluate(makeInput());
    expect(decision.matched_rules).toEqual(["r1", "r3"]);
    expect(decision.decision).toBe("quarantine");
  });

  it("generates a unique decision_id (uuid format)", () => {
    const engine = makeEngine([{ id: "r1", effect: "allow", evaluate: () => false }]);
    const d1 = engine.evaluate(makeInput());
    const d2 = engine.evaluate(makeInput());
    expect(d1.decision_id).not.toBe(d2.decision_id);
    // UUID v4 format
    expect(d1.decision_id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    );
  });

  it("produces deterministic decisions (same effect, policy_id) for same input", () => {
    const engine = makeEngine([{ id: "r1", effect: "deny", evaluate: () => true }]);
    const input = makeInput();
    const d1 = engine.evaluate(input);
    const d2 = engine.evaluate(input);
    expect(d1.decision).toBe(d2.decision);
    expect(d1.policy_id).toBe(d2.policy_id);
    expect(d1.matched_rules).toEqual(d2.matched_rules);
    // decision_id differs (uuid)
    expect(d1.decision_id).not.toBe(d2.decision_id);
  });

  it("provides explanation from the winning rule", () => {
    const engine = makeEngine([{ id: "r1", effect: "deny", evaluate: () => true }]);
    const decision = engine.evaluate(makeInput());
    expect(decision.explanation).toBe("Rule r1");
  });

  it("provides explanation for default allow", () => {
    const engine = makeEngine([{ id: "r1", effect: "deny", evaluate: () => false }]);
    const decision = engine.evaluate(makeInput());
    expect(decision.explanation).toContain("No policy rules matched");
  });

  it("returns frozen decision objects", () => {
    const engine = makeEngine([{ id: "r1", effect: "deny", evaluate: () => true }]);
    const decision = engine.evaluate(makeInput());
    expect(Object.isFrozen(decision)).toBe(true);
  });

  it("throws PolicyEvaluationError when a rule throws", () => {
    const engine = makeEngine([
      {
        id: "bad",
        effect: "deny",
        evaluate: () => {
          throw new Error("rule crashed");
        },
      },
    ]);
    expect(() => engine.evaluate(makeInput())).toThrow(PolicyEvaluationError);
    expect(() => engine.evaluate(makeInput())).toThrow(/bad/);
  });

  it("uses first rule at winning severity for policy_id", () => {
    const engine = makeEngine([
      { id: "r1", effect: "quarantine", evaluate: () => true },
      { id: "r2", effect: "quarantine", evaluate: () => true },
    ]);
    const decision = engine.evaluate(makeInput());
    expect(decision.policy_id).toBe("r1");
    expect(decision.matched_rules).toEqual(["r1", "r2"]);
  });
});
