import { describe, it, expect } from "vitest";
import { createPolicyBundle } from "../policy-bundle.js";
import { createPolicyRule } from "../policy-rule.js";
import { PolicyBundleError } from "../errors.js";
import { createDefaultPolicyBundle } from "../default-policies.js";

function makeRule(id: string) {
  return createPolicyRule({
    id,
    description: `Rule ${id}`,
    effect: "allow",
    evaluate: () => false,
  });
}

describe("createPolicyBundle", () => {
  it("creates a valid bundle", () => {
    const bundle = createPolicyBundle({
      version: "1.0.0",
      rules: [makeRule("r1")],
    });
    expect(bundle.version).toBe("1.0.0");
    expect(bundle.rules).toHaveLength(1);
    expect(bundle.created_at).toBeDefined();
  });

  it("returns a frozen bundle", () => {
    const bundle = createPolicyBundle({
      version: "1.0.0",
      rules: [makeRule("r1")],
    });
    expect(Object.isFrozen(bundle)).toBe(true);
  });

  it("returns frozen rules array", () => {
    const bundle = createPolicyBundle({
      version: "1.0.0",
      rules: [makeRule("r1")],
    });
    expect(Object.isFrozen(bundle.rules)).toBe(true);
  });

  it("throws PolicyBundleError for empty version", () => {
    expect(() => createPolicyBundle({ version: "", rules: [makeRule("r1")] })).toThrow(
      PolicyBundleError,
    );
  });

  it("throws PolicyBundleError for empty rules", () => {
    expect(() => createPolicyBundle({ version: "1.0.0", rules: [] })).toThrow(
      PolicyBundleError,
    );
  });

  it("throws PolicyBundleError for duplicate rule IDs", () => {
    expect(() =>
      createPolicyBundle({
        version: "1.0.0",
        rules: [makeRule("dup"), makeRule("dup")],
      }),
    ).toThrow(PolicyBundleError);
    expect(() =>
      createPolicyBundle({
        version: "1.0.0",
        rules: [makeRule("dup"), makeRule("dup")],
      }),
    ).toThrow(/Duplicate rule ID/);
  });

  it("accepts multiple unique rules", () => {
    const bundle = createPolicyBundle({
      version: "2.0.0",
      rules: [makeRule("a"), makeRule("b"), makeRule("c")],
    });
    expect(bundle.rules).toHaveLength(3);
  });

  it("has a valid ISO timestamp for created_at", () => {
    const bundle = createPolicyBundle({
      version: "1.0.0",
      rules: [makeRule("r1")],
    });
    expect(() => new Date(bundle.created_at)).not.toThrow();
    expect(new Date(bundle.created_at).toISOString()).toBe(bundle.created_at);
  });
});

describe("createPolicyRule", () => {
  it("creates a valid rule", () => {
    const rule = createPolicyRule({
      id: "test",
      description: "A test rule",
      effect: "deny",
      evaluate: () => true,
    });
    expect(rule.id).toBe("test");
    expect(rule.effect).toBe("deny");
  });

  it("returns a frozen rule", () => {
    const rule = createPolicyRule({
      id: "test",
      description: "A test rule",
      effect: "allow",
      evaluate: () => false,
    });
    expect(Object.isFrozen(rule)).toBe(true);
  });

  it("throws on empty id", () => {
    expect(() =>
      createPolicyRule({
        id: "",
        description: "x",
        effect: "allow",
        evaluate: () => false,
      }),
    ).toThrow(/id/);
  });

  it("throws on empty description", () => {
    expect(() =>
      createPolicyRule({
        id: "r1",
        description: "",
        effect: "allow",
        evaluate: () => false,
      }),
    ).toThrow(/description/);
  });

  it("throws on invalid effect", () => {
    expect(() =>
      createPolicyRule({
        id: "r1",
        description: "x",
        effect: "invalid" as "allow",
        evaluate: () => false,
      }),
    ).toThrow(/effect/);
  });
});

describe("createDefaultPolicyBundle", () => {
  it("has 3 rules", () => {
    const bundle = createDefaultPolicyBundle();
    expect(bundle.rules).toHaveLength(3);
  });

  it("has version 0.1.0", () => {
    const bundle = createDefaultPolicyBundle();
    expect(bundle.version).toBe("0.1.0");
  });

  it("has unique rule IDs", () => {
    const bundle = createDefaultPolicyBundle();
    const ids = bundle.rules.map((r) => r.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
});
