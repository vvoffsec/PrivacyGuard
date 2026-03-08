import { describe, it, expect } from "vitest";
import { v4 as uuidv4 } from "uuid";
import {
  parsePolicyInput,
  parsePolicyDecision,
  mostRestrictiveEffect,
  PolicyEffectSchema,
  EFFECT_SEVERITY,
  type PolicyEffect,
} from "../types.js";
import { PolicyValidationError } from "../errors.js";

function validInputData(overrides: Record<string, unknown> = {}) {
  return {
    principal: { type: "agent", id: "agent-1" },
    request: { action: "tool.exec.shell", purpose: [], task_id: "task-1" },
    resource: { type: "file", name: "config.json" },
    data: { source_trust: [], sensitivity: [], taint_flags: [] },
    destination: { kind: "local", name: "stdout" },
    environment: { host_class: "workstation", policy_bundle: "default" },
    ...overrides,
  };
}

function validDecisionData(overrides: Record<string, unknown> = {}) {
  return {
    decision: "allow",
    decision_id: uuidv4(),
    policy_id: "pg.default.allow",
    matched_rules: ["no_rule_matched"],
    explanation: "No rules matched",
    policy_bundle_version: "0.1.0",
    ...overrides,
  };
}

describe("parsePolicyInput", () => {
  it("parses a valid input", () => {
    const data = validInputData();
    const input = parsePolicyInput(data);
    expect(input.principal.type).toBe("agent");
    expect(input.request.action).toBe("tool.exec.shell");
  });

  it("returns a frozen object", () => {
    const input = parsePolicyInput(validInputData());
    expect(Object.isFrozen(input)).toBe(true);
  });

  it("applies defaults for optional arrays", () => {
    const data = validInputData({
      data: {},
      request: { action: "read", task_id: "t1" },
    });
    const input = parsePolicyInput(data);
    expect(input.data.source_trust).toEqual([]);
    expect(input.data.sensitivity).toEqual([]);
    expect(input.data.taint_flags).toEqual([]);
    expect(input.request.purpose).toEqual([]);
  });

  it("throws PolicyValidationError on missing fields", () => {
    expect(() => parsePolicyInput({})).toThrow(PolicyValidationError);
  });

  it("throws PolicyValidationError on invalid principal type", () => {
    expect(() =>
      parsePolicyInput(validInputData({ principal: { type: "robot", id: "x" } })),
    ).toThrow(PolicyValidationError);
  });

  it("throws PolicyValidationError on empty principal id", () => {
    expect(() =>
      parsePolicyInput(validInputData({ principal: { type: "agent", id: "" } })),
    ).toThrow(PolicyValidationError);
  });

  it("throws PolicyValidationError on empty action", () => {
    expect(() =>
      parsePolicyInput(
        validInputData({ request: { action: "", purpose: [], task_id: "t1" } }),
      ),
    ).toThrow(PolicyValidationError);
  });

  it("throws PolicyValidationError on empty task_id", () => {
    expect(() =>
      parsePolicyInput(
        validInputData({ request: { action: "read", purpose: [], task_id: "" } }),
      ),
    ).toThrow(PolicyValidationError);
  });

  it("throws PolicyValidationError on empty resource type", () => {
    expect(() =>
      parsePolicyInput(validInputData({ resource: { type: "", name: "f" } })),
    ).toThrow(PolicyValidationError);
  });

  it("throws PolicyValidationError on empty resource name", () => {
    expect(() =>
      parsePolicyInput(validInputData({ resource: { type: "file", name: "" } })),
    ).toThrow(PolicyValidationError);
  });

  it("throws PolicyValidationError on empty destination kind", () => {
    expect(() =>
      parsePolicyInput(validInputData({ destination: { kind: "", name: "x" } })),
    ).toThrow(PolicyValidationError);
  });

  it("throws PolicyValidationError on empty environment host_class", () => {
    expect(() =>
      parsePolicyInput(
        validInputData({
          environment: { host_class: "", policy_bundle: "default" },
        }),
      ),
    ).toThrow(PolicyValidationError);
  });

  it("provides explanation with path info", () => {
    try {
      parsePolicyInput({});
      expect.fail("should have thrown");
    } catch (error) {
      expect(error).toBeInstanceOf(PolicyValidationError);
      const explanation = (error as PolicyValidationError).toExplanation();
      expect(explanation).toContain("principal");
    }
  });

  it("accepts arbitrary string values in data arrays (forward-compatible)", () => {
    const input = parsePolicyInput(
      validInputData({
        data: {
          source_trust: ["custom_trust_level"],
          sensitivity: ["future_label"],
          taint_flags: ["new_flag"],
        },
      }),
    );
    expect(input.data.source_trust).toContain("custom_trust_level");
    expect(input.data.sensitivity).toContain("future_label");
    expect(input.data.taint_flags).toContain("new_flag");
  });

  it("rejects null input", () => {
    expect(() => parsePolicyInput(null)).toThrow(PolicyValidationError);
  });

  it("rejects non-object input", () => {
    expect(() => parsePolicyInput("string")).toThrow(PolicyValidationError);
  });
});

describe("parsePolicyDecision", () => {
  it("parses a valid decision", () => {
    const data = validDecisionData();
    const decision = parsePolicyDecision(data);
    expect(decision.decision).toBe("allow");
    expect(decision.policy_id).toBe("pg.default.allow");
  });

  it("returns a frozen object", () => {
    const decision = parsePolicyDecision(validDecisionData());
    expect(Object.isFrozen(decision)).toBe(true);
  });

  it("throws on invalid decision effect", () => {
    expect(() =>
      parsePolicyDecision(validDecisionData({ decision: "maybe" })),
    ).toThrow(PolicyValidationError);
  });

  it("throws on empty matched_rules", () => {
    expect(() =>
      parsePolicyDecision(validDecisionData({ matched_rules: [] })),
    ).toThrow(PolicyValidationError);
  });

  it("throws on invalid decision_id (non-uuid)", () => {
    expect(() =>
      parsePolicyDecision(validDecisionData({ decision_id: "not-a-uuid" })),
    ).toThrow(PolicyValidationError);
  });

  it("accepts decision with required_actions", () => {
    const decision = parsePolicyDecision(
      validDecisionData({
        decision: "require_approval",
        required_actions: [{ type: "user_approval", reason: "sensitive" }],
      }),
    );
    expect(decision.required_actions).toHaveLength(1);
  });

  it("accepts decision without required_actions", () => {
    const decision = parsePolicyDecision(validDecisionData());
    expect(decision.required_actions).toBeUndefined();
  });
});

describe("PolicyEffectSchema", () => {
  it("accepts all valid effects", () => {
    const effects = [
      "allow",
      "allow_with_minimization",
      "require_approval",
      "quarantine",
      "deny",
    ];
    for (const effect of effects) {
      expect(PolicyEffectSchema.safeParse(effect).success).toBe(true);
    }
  });

  it("rejects invalid effects", () => {
    expect(PolicyEffectSchema.safeParse("block").success).toBe(false);
    expect(PolicyEffectSchema.safeParse("").success).toBe(false);
  });
});

describe("EFFECT_SEVERITY", () => {
  it("has correct ordering", () => {
    expect(EFFECT_SEVERITY.allow).toBeLessThan(EFFECT_SEVERITY.allow_with_minimization);
    expect(EFFECT_SEVERITY.allow_with_minimization).toBeLessThan(EFFECT_SEVERITY.require_approval);
    expect(EFFECT_SEVERITY.require_approval).toBeLessThan(EFFECT_SEVERITY.quarantine);
    expect(EFFECT_SEVERITY.quarantine).toBeLessThan(EFFECT_SEVERITY.deny);
  });
});

describe("mostRestrictiveEffect", () => {
  it("returns allow for empty array", () => {
    expect(mostRestrictiveEffect([])).toBe("allow");
  });

  it("returns the single effect for single-element array", () => {
    expect(mostRestrictiveEffect(["deny"])).toBe("deny");
    expect(mostRestrictiveEffect(["allow"])).toBe("allow");
  });

  it("returns the most restrictive of multiple effects", () => {
    expect(mostRestrictiveEffect(["allow", "deny"])).toBe("deny");
    expect(
      mostRestrictiveEffect(["allow", "require_approval", "quarantine"]),
    ).toBe("quarantine");
  });

  it("handles all same effects", () => {
    expect(
      mostRestrictiveEffect(["allow", "allow", "allow"]),
    ).toBe("allow");
  });

  it("deny always wins", () => {
    const all: PolicyEffect[] = [
      "allow",
      "allow_with_minimization",
      "require_approval",
      "quarantine",
      "deny",
    ];
    expect(mostRestrictiveEffect(all)).toBe("deny");
  });
});
