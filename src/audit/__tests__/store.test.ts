import { describe, it, expect } from "vitest";
import { v4 as uuidv4 } from "uuid";
import { sha256Hash } from "../../shared/crypto.js";
import { InMemoryAuditStore } from "../store.js";
import { parseAuditEvent } from "../types.js";
import { AuditValidationError } from "../errors.js";

const HASH = sha256Hash("test");

function validDecisionEventData(overrides: Record<string, unknown> = {}) {
  return {
    event_id: uuidv4(),
    event_type: "decision",
    timestamp: new Date().toISOString(),
    decision_id: uuidv4(),
    actor_id: "user-1",
    agent_id: "agent-1",
    policy_id: "policy-1",
    action: "read",
    result: "allow",
    explanation: "Allowed",
    matched_rules: ["rule-1"],
    input_hashes: [HASH],
    ...overrides,
  };
}

function validToolEventData(overrides: Record<string, unknown> = {}) {
  return {
    event_id: uuidv4(),
    event_type: "tool",
    timestamp: new Date().toISOString(),
    request_id: uuidv4(),
    tool_name: "fs.read",
    args_hash: HASH,
    destination: "local",
    result: "allowed",
    capability_id: uuidv4(),
    ...overrides,
  };
}

describe("InMemoryAuditStore", () => {
  it("starts empty", () => {
    const store = new InMemoryAuditStore();
    expect(store.count()).toBe(0);
    expect(store.all()).toEqual([]);
  });

  it("appends events and increments count", () => {
    const store = new InMemoryAuditStore();
    const event = parseAuditEvent(validDecisionEventData());
    store.append(event);
    expect(store.count()).toBe(1);
  });

  it("preserves order of appended events", () => {
    const store = new InMemoryAuditStore();
    const e1 = parseAuditEvent(validDecisionEventData());
    const e2 = parseAuditEvent(validToolEventData());
    store.append(e1);
    store.append(e2);
    const all = store.all();
    expect(all[0].event_id).toBe(e1.event_id);
    expect(all[1].event_id).toBe(e2.event_id);
  });

  it("all() returns a frozen copy", () => {
    const store = new InMemoryAuditStore();
    store.append(parseAuditEvent(validDecisionEventData()));
    const all = store.all();
    expect(Object.isFrozen(all)).toBe(true);
  });

  it("all() returns a new array each time (no mutation)", () => {
    const store = new InMemoryAuditStore();
    store.append(parseAuditEvent(validDecisionEventData()));
    const all1 = store.all();
    const all2 = store.all();
    expect(all1).not.toBe(all2);
    expect(all1).toEqual(all2);
  });

  it("re-validates on append (defense-in-depth)", () => {
    const store = new InMemoryAuditStore();
    expect(() => {
      store.append({ bogus: true } as never);
    }).toThrow(AuditValidationError);
    expect(store.count()).toBe(0);
  });

  it("has no update or delete methods", () => {
    const store = new InMemoryAuditStore();
    expect("update" in store).toBe(false);
    expect("delete" in store).toBe(false);
    expect("remove" in store).toBe(false);
  });

  it("query delegates to executeQuery", () => {
    const store = new InMemoryAuditStore();
    const e1 = parseAuditEvent(validDecisionEventData());
    const e2 = parseAuditEvent(validToolEventData());
    store.append(e1);
    store.append(e2);
    const results = store.query({ event_type: "decision" });
    expect(results.length).toBe(1);
    expect(results[0].event_type).toBe("decision");
  });

  it("multiple appends work correctly", () => {
    const store = new InMemoryAuditStore();
    for (let i = 0; i < 10; i++) {
      store.append(parseAuditEvent(validDecisionEventData()));
    }
    expect(store.count()).toBe(10);
    expect(store.all().length).toBe(10);
  });

  it("appending does not affect previously retrieved all()", () => {
    const store = new InMemoryAuditStore();
    store.append(parseAuditEvent(validDecisionEventData()));
    const snapshot = store.all();
    store.append(parseAuditEvent(validToolEventData()));
    expect(snapshot.length).toBe(1);
    expect(store.all().length).toBe(2);
  });
});
