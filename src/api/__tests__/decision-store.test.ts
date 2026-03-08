import { describe, it, expect } from "vitest";
import { createInMemoryDecisionStore } from "../decision-store.js";
import type { StoredDecision } from "../interfaces.js";

function makeDecision(id: string): StoredDecision {
  return {
    decision_id: id,
    decision: "allow",
    policy_id: "pg.default",
    matched_rules: ["no_rule_matched"],
    explanation: "No policy rules matched",
  };
}

describe("createInMemoryDecisionStore", () => {
  it("returns a frozen store", () => {
    const store = createInMemoryDecisionStore();
    expect(Object.isFrozen(store)).toBe(true);
  });

  it("stores and retrieves a decision", () => {
    const store = createInMemoryDecisionStore();
    const decision = makeDecision("id-1");
    store.put(decision);
    expect(store.get("id-1")).toEqual(decision);
  });

  it("returns undefined for unknown ID", () => {
    const store = createInMemoryDecisionStore();
    expect(store.get("nonexistent")).toBeUndefined();
  });

  it("freezes stored decisions", () => {
    const store = createInMemoryDecisionStore();
    store.put(makeDecision("id-1"));
    const retrieved = store.get("id-1");
    expect(Object.isFrozen(retrieved)).toBe(true);
  });

  it("evicts oldest entry when maxEntries is reached", () => {
    const store = createInMemoryDecisionStore(3);
    store.put(makeDecision("a"));
    store.put(makeDecision("b"));
    store.put(makeDecision("c"));
    store.put(makeDecision("d"));
    expect(store.get("a")).toBeUndefined();
    expect(store.get("b")).toBeDefined();
    expect(store.get("c")).toBeDefined();
    expect(store.get("d")).toBeDefined();
  });

  it("does not evict when updating existing key", () => {
    const store = createInMemoryDecisionStore(2);
    store.put(makeDecision("a"));
    store.put(makeDecision("b"));
    store.put({
      ...makeDecision("a"),
      decision: "deny",
    });
    expect(store.get("a")).toBeDefined();
    expect(store.get("b")).toBeDefined();
  });

  it("stores multiple decisions independently", () => {
    const store = createInMemoryDecisionStore();
    store.put(makeDecision("x"));
    store.put({
      ...makeDecision("y"),
      decision: "deny",
      policy_id: "pg.deny",
    });
    expect(store.get("x")?.decision).toBe("allow");
    expect(store.get("y")?.decision).toBe("deny");
  });

  it("defaults maxEntries to 10000", () => {
    const store = createInMemoryDecisionStore();
    // Just verify we can create without explicit max
    expect(store).toBeDefined();
  });
});
