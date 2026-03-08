import { describe, it, expect } from "vitest";
import { v4 as uuidv4 } from "uuid";
import { sha256Hash } from "../../shared/crypto.js";
import { parseAuditEvent, type AuditEvent } from "../types.js";
import { executeQuery } from "../query.js";

const HASH = sha256Hash("test");

function makeDecision(overrides: Record<string, unknown> = {}): AuditEvent {
  return parseAuditEvent({
    event_id: uuidv4(),
    event_type: "decision",
    timestamp: new Date().toISOString(),
    decision_id: uuidv4(),
    actor_id: "user-1",
    agent_id: "agent-1",
    policy_id: "policy-1",
    action: "read",
    result: "allow",
    explanation: "OK",
    matched_rules: ["rule-1"],
    input_hashes: [HASH],
    ...overrides,
  });
}

function makeApproval(overrides: Record<string, unknown> = {}): AuditEvent {
  return parseAuditEvent({
    event_id: uuidv4(),
    event_type: "approval",
    timestamp: new Date().toISOString(),
    approval_id: uuidv4(),
    actor_id: "user-1",
    decision_id: uuidv4(),
    scope_hash: HASH,
    reason: "Approved",
    status: "granted",
    ...overrides,
  });
}

function makeTool(overrides: Record<string, unknown> = {}): AuditEvent {
  return parseAuditEvent({
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
  });
}

function makeMemory(overrides: Record<string, unknown> = {}): AuditEvent {
  return parseAuditEvent({
    event_id: uuidv4(),
    event_type: "memory",
    timestamp: new Date().toISOString(),
    entry_id: uuidv4(),
    tier: "ephemeral",
    source_trust: "trusted_user",
    sensitivity: ["public"],
    action: "write",
    ...overrides,
  });
}

describe("executeQuery", () => {
  it("returns all events when filter is empty", () => {
    const events = [makeDecision(), makeTool(), makeMemory()];
    const results = executeQuery(events, {});
    expect(results.length).toBe(3);
  });

  it("filters by event_type", () => {
    const events = [makeDecision(), makeTool(), makeMemory()];
    const results = executeQuery(events, { event_type: "decision" });
    expect(results.length).toBe(1);
    expect(results[0].event_type).toBe("decision");
  });

  it("filters by correlation_id", () => {
    const cid = uuidv4();
    const events = [
      makeDecision({ correlation_id: cid }),
      makeDecision(),
      makeTool({ correlation_id: cid }),
    ];
    const results = executeQuery(events, { correlation_id: cid });
    expect(results.length).toBe(2);
  });

  it("filters by actor_id", () => {
    const events = [
      makeDecision({ actor_id: "alice" }),
      makeDecision({ actor_id: "bob" }),
      makeApproval({ actor_id: "alice" }),
    ];
    const results = executeQuery(events, { actor_id: "alice" });
    expect(results.length).toBe(2);
  });

  it("filters by agent_id", () => {
    const events = [
      makeDecision({ agent_id: "agent-A" }),
      makeDecision({ agent_id: "agent-B" }),
      makeTool(), // no agent_id
    ];
    const results = executeQuery(events, { agent_id: "agent-A" });
    expect(results.length).toBe(1);
  });

  it("filters by decision_id across decision and approval events", () => {
    const did = uuidv4();
    const events = [
      makeDecision({ decision_id: did }),
      makeApproval({ decision_id: did }),
      makeDecision(),
    ];
    const results = executeQuery(events, { decision_id: did });
    expect(results.length).toBe(2);
  });

  it("filters by time_from (inclusive)", () => {
    const events = [
      makeDecision({ timestamp: "2026-01-01T00:00:00.000Z" }),
      makeDecision({ timestamp: "2026-06-01T00:00:00.000Z" }),
      makeDecision({ timestamp: "2026-12-01T00:00:00.000Z" }),
    ];
    const results = executeQuery(events, {
      time_from: "2026-06-01T00:00:00.000Z",
    });
    expect(results.length).toBe(2);
  });

  it("filters by time_to (exclusive)", () => {
    const events = [
      makeDecision({ timestamp: "2026-01-01T00:00:00.000Z" }),
      makeDecision({ timestamp: "2026-06-01T00:00:00.000Z" }),
      makeDecision({ timestamp: "2026-12-01T00:00:00.000Z" }),
    ];
    const results = executeQuery(events, {
      time_to: "2026-06-01T00:00:00.000Z",
    });
    expect(results.length).toBe(1);
  });

  it("filters by time range (from + to)", () => {
    const events = [
      makeDecision({ timestamp: "2026-01-01T00:00:00.000Z" }),
      makeDecision({ timestamp: "2026-06-01T00:00:00.000Z" }),
      makeDecision({ timestamp: "2026-12-01T00:00:00.000Z" }),
    ];
    const results = executeQuery(events, {
      time_from: "2026-03-01T00:00:00.000Z",
      time_to: "2026-09-01T00:00:00.000Z",
    });
    expect(results.length).toBe(1);
  });

  it("applies limit", () => {
    const events = [makeDecision(), makeDecision(), makeDecision()];
    const results = executeQuery(events, { limit: 2 });
    expect(results.length).toBe(2);
  });

  it("returns empty array when no events match", () => {
    const events = [makeDecision(), makeTool()];
    const results = executeQuery(events, { event_type: "egress" });
    expect(results.length).toBe(0);
  });

  it("returns empty array for empty input", () => {
    const results = executeQuery([], {});
    expect(results.length).toBe(0);
  });

  it("returns frozen array", () => {
    const results = executeQuery([makeDecision()], {});
    expect(Object.isFrozen(results)).toBe(true);
  });

  it("uses AND semantics for multiple filters", () => {
    const events = [
      makeDecision({ actor_id: "alice", agent_id: "agent-A" }),
      makeDecision({ actor_id: "alice", agent_id: "agent-B" }),
      makeDecision({ actor_id: "bob", agent_id: "agent-A" }),
    ];
    const results = executeQuery(events, {
      actor_id: "alice",
      agent_id: "agent-A",
    });
    expect(results.length).toBe(1);
  });

  it("agent_id filter excludes events without agent_id", () => {
    const events = [makeTool(), makeMemory()];
    const results = executeQuery(events, { agent_id: "agent-1" });
    expect(results.length).toBe(0);
  });

  it("actor_id filter excludes events without actor_id", () => {
    const events = [makeTool(), makeMemory()];
    const results = executeQuery(events, { actor_id: "user-1" });
    expect(results.length).toBe(0);
  });
});
