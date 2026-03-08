import { describe, it, expect } from "vitest";
import { createPDP } from "../pdp.js";
import { InProcessPolicyEngine } from "../local-engine.js";
import { createDefaultPolicyBundle } from "../default-policies.js";
import { createPolicyBundle } from "../policy-bundle.js";
import { createPolicyRule } from "../policy-rule.js";
import { PolicyValidationError } from "../errors.js";

function validInputData(overrides: Record<string, unknown> = {}) {
  return {
    principal: { type: "agent", id: "agent-1" },
    request: { action: "read", purpose: [], task_id: "task-1" },
    resource: { type: "file", name: "test.txt" },
    data: { source_trust: [], sensitivity: [], taint_flags: [] },
    destination: { kind: "local", name: "stdout" },
    environment: { host_class: "workstation", policy_bundle: "default" },
    ...overrides,
  };
}

describe("createPDP", () => {
  it("returns a frozen PDP object", () => {
    const bundle = createDefaultPolicyBundle();
    const engine = new InProcessPolicyEngine(bundle);
    const pdp = createPDP(engine);
    expect(Object.isFrozen(pdp)).toBe(true);
  });

  it("throws PolicyValidationError on invalid input", () => {
    const bundle = createDefaultPolicyBundle();
    const engine = new InProcessPolicyEngine(bundle);
    const pdp = createPDP(engine);
    expect(() => pdp.evaluate({})).toThrow(PolicyValidationError);
  });

  it("throws PolicyValidationError on null input", () => {
    const bundle = createDefaultPolicyBundle();
    const engine = new InProcessPolicyEngine(bundle);
    const pdp = createPDP(engine);
    expect(() => pdp.evaluate(null)).toThrow(PolicyValidationError);
  });

  it("returns allow for benign input with default bundle", () => {
    const bundle = createDefaultPolicyBundle();
    const engine = new InProcessPolicyEngine(bundle);
    const pdp = createPDP(engine);
    const decision = pdp.evaluate(validInputData());
    expect(decision.decision).toBe("allow");
  });

  it("returns deny for egress of secrets", () => {
    const bundle = createDefaultPolicyBundle();
    const engine = new InProcessPolicyEngine(bundle);
    const pdp = createPDP(engine);
    const decision = pdp.evaluate(
      validInputData({
        request: { action: "http.send", purpose: [], task_id: "t1" },
        data: { sensitivity: ["secret"], source_trust: [], taint_flags: [] },
      }),
    );
    expect(decision.decision).toBe("deny");
    expect(decision.policy_id).toBe("pg.egress.secret.default");
  });

  it("returns require_approval for exec with untrusted instructions", () => {
    const bundle = createDefaultPolicyBundle();
    const engine = new InProcessPolicyEngine(bundle);
    const pdp = createPDP(engine);
    const decision = pdp.evaluate(
      validInputData({
        request: { action: "tool.exec.shell", purpose: [], task_id: "t1" },
        data: {
          taint_flags: ["untrusted_instruction"],
          source_trust: [],
          sensitivity: [],
        },
      }),
    );
    expect(decision.decision).toBe("require_approval");
    expect(decision.policy_id).toBe("pg.exec.untrusted.content");
    expect(decision.required_actions).toBeDefined();
  });

  it("returns quarantine for memory promotion of untrusted content", () => {
    const bundle = createDefaultPolicyBundle();
    const engine = new InProcessPolicyEngine(bundle);
    const pdp = createPDP(engine);
    const decision = pdp.evaluate(
      validInputData({
        request: { action: "memory.write", purpose: ["durable"], task_id: "t1" },
        data: {
          source_trust: ["untrusted_external"],
          sensitivity: [],
          taint_flags: [],
        },
      }),
    );
    expect(decision.decision).toBe("quarantine");
    expect(decision.policy_id).toBe("pg.memory.promotion");
  });

  it("fails closed when engine throws PolicyEvaluationError", () => {
    const throwingRule = createPolicyRule({
      id: "broken",
      description: "This rule always throws",
      effect: "allow",
      evaluate: () => {
        throw new Error("unexpected failure");
      },
    });
    const bundle = createPolicyBundle({
      version: "1.0.0",
      rules: [throwingRule],
    });
    const engine = new InProcessPolicyEngine(bundle);
    const pdp = createPDP(engine);
    const decision = pdp.evaluate(validInputData());
    expect(decision.decision).toBe("deny");
    expect(decision.policy_id).toBe("pg.failclosed");
    expect(decision.explanation).toContain("failing closed");
  });

  it("includes policy_bundle_version in fail-closed decision", () => {
    const throwingRule = createPolicyRule({
      id: "broken",
      description: "Throws",
      effect: "allow",
      evaluate: () => {
        throw new Error("boom");
      },
    });
    const bundle = createPolicyBundle({
      version: "2.5.0",
      rules: [throwingRule],
    });
    const engine = new InProcessPolicyEngine(bundle);
    const pdp = createPDP(engine);
    const decision = pdp.evaluate(validInputData());
    expect(decision.policy_bundle_version).toBe("2.5.0");
  });

  it("returns frozen decisions", () => {
    const bundle = createDefaultPolicyBundle();
    const engine = new InProcessPolicyEngine(bundle);
    const pdp = createPDP(engine);
    const decision = pdp.evaluate(validInputData());
    expect(Object.isFrozen(decision)).toBe(true);
  });

  it("includes decision_id in all decisions", () => {
    const bundle = createDefaultPolicyBundle();
    const engine = new InProcessPolicyEngine(bundle);
    const pdp = createPDP(engine);
    const decision = pdp.evaluate(validInputData());
    expect(decision.decision_id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    );
  });

  it("includes matched_rules in all decisions", () => {
    const bundle = createDefaultPolicyBundle();
    const engine = new InProcessPolicyEngine(bundle);
    const pdp = createPDP(engine);
    const decision = pdp.evaluate(validInputData());
    expect(decision.matched_rules.length).toBeGreaterThanOrEqual(1);
  });

  it("includes explanation in all decisions", () => {
    const bundle = createDefaultPolicyBundle();
    const engine = new InProcessPolicyEngine(bundle);
    const pdp = createPDP(engine);
    const decision = pdp.evaluate(validInputData());
    expect(decision.explanation.length).toBeGreaterThan(0);
  });
});
