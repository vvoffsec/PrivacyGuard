import { describe, it, expect } from "vitest";
import { v4 as uuidv4 } from "uuid";
import { sha256Hash } from "../../shared/crypto.js";
import { parseAuditEvent } from "../types.js";
import { InMemoryAuditStore } from "../store.js";
import { DefaultAuditEmitter, NoOpAuditEmitter } from "../emitter.js";
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

describe("DefaultAuditEmitter", () => {
  it("emits events to the store", () => {
    const store = new InMemoryAuditStore();
    const emitter = new DefaultAuditEmitter(store);
    const event = parseAuditEvent(validDecisionEventData());
    emitter.emit(event);
    expect(emitter.count()).toBe(1);
    expect(store.count()).toBe(1);
  });

  it("re-validates on emit (defense-in-depth)", () => {
    const store = new InMemoryAuditStore();
    const emitter = new DefaultAuditEmitter(store);
    expect(() => {
      emitter.emit({ bogus: true } as never);
    }).toThrow(AuditValidationError);
    expect(emitter.count()).toBe(0);
  });

  it("fail-closed: errors propagate", () => {
    const store = new InMemoryAuditStore();
    const emitter = new DefaultAuditEmitter(store);
    expect(() => {
      emitter.emit({} as never);
    }).toThrow();
  });

  it("query delegates to store", () => {
    const store = new InMemoryAuditStore();
    const emitter = new DefaultAuditEmitter(store);
    emitter.emit(parseAuditEvent(validDecisionEventData()));
    emitter.emit(parseAuditEvent(validToolEventData()));
    const results = emitter.query({ event_type: "tool" });
    expect(results.length).toBe(1);
    expect(results[0].event_type).toBe("tool");
  });

  it("count reflects number of emitted events", () => {
    const store = new InMemoryAuditStore();
    const emitter = new DefaultAuditEmitter(store);
    expect(emitter.count()).toBe(0);
    emitter.emit(parseAuditEvent(validDecisionEventData()));
    expect(emitter.count()).toBe(1);
    emitter.emit(parseAuditEvent(validToolEventData()));
    expect(emitter.count()).toBe(2);
  });

  it("multiple events preserve order", () => {
    const store = new InMemoryAuditStore();
    const emitter = new DefaultAuditEmitter(store);
    const e1 = parseAuditEvent(validDecisionEventData());
    const e2 = parseAuditEvent(validToolEventData());
    emitter.emit(e1);
    emitter.emit(e2);
    const all = store.all();
    expect(all[0].event_id).toBe(e1.event_id);
    expect(all[1].event_id).toBe(e2.event_id);
  });
});

describe("NoOpAuditEmitter", () => {
  it("emit is silent (does not throw)", () => {
    const emitter = new NoOpAuditEmitter();
    const event = parseAuditEvent(validDecisionEventData());
    expect(() => {
      emitter.emit(event);
    }).not.toThrow();
  });

  it("count always returns 0", () => {
    const emitter = new NoOpAuditEmitter();
    emitter.emit(parseAuditEvent(validDecisionEventData()));
    expect(emitter.count()).toBe(0);
  });

  it("query always returns empty frozen array", () => {
    const emitter = new NoOpAuditEmitter();
    const results = emitter.query({});
    expect(results.length).toBe(0);
    expect(Object.isFrozen(results)).toBe(true);
  });

  it("does not store events", () => {
    const emitter = new NoOpAuditEmitter();
    for (let i = 0; i < 5; i++) {
      emitter.emit(parseAuditEvent(validDecisionEventData()));
    }
    expect(emitter.count()).toBe(0);
  });
});
