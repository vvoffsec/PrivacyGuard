import { describe, it, expect } from "vitest";
import { createDecisionExplainHandler } from "../handlers/decision-explain.js";
import { createInMemoryDecisionStore } from "../decision-store.js";
import { createNoOpAuditEmitter, createSpyAuditEmitter } from "./helpers.js";

const KNOWN_ID = "12345678-1234-4234-8234-123456789012";
const UNKNOWN_ID = "99999999-9999-4999-8999-999999999999";

function createHandler(
  overrides: {
    auditEmitter?: ReturnType<typeof createSpyAuditEmitter>;
  } = {},
) {
  const decisionStore = createInMemoryDecisionStore();
  const auditEmitter = overrides.auditEmitter ?? createNoOpAuditEmitter();
  const handler = createDecisionExplainHandler({
    decisionStore,
    auditEmitter,
  });
  return { handler, decisionStore, auditEmitter };
}

describe("createDecisionExplainHandler", () => {
  it("returns stored decision for known ID", () => {
    const { handler, decisionStore } = createHandler();
    decisionStore.put({
      decision_id: KNOWN_ID,
      decision: "deny",
      policy_id: "pg.egress.secret.default",
      matched_rules: ["pg.egress.secret.default"],
      explanation: "Denied secret egress",
    });

    const result = handler({ decision_id: KNOWN_ID });
    expect(result.ok).toBe(true);
    if (result.ok) {
      const data = result.data as {
        decision_id: string;
        decision: string;
        policy_id: string;
        explanation: string;
      };
      expect(data.decision_id).toBe(KNOWN_ID);
      expect(data.decision).toBe("deny");
      expect(data.policy_id).toBe("pg.egress.secret.default");
      expect(data.explanation).toBe("Denied secret egress");
    }
  });

  it("returns DECISION_NOT_FOUND for unknown ID", () => {
    const { handler } = createHandler();
    const result = handler({ decision_id: UNKNOWN_ID });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("DECISION_NOT_FOUND");
      expect(result.error.message).toContain(UNKNOWN_ID);
    }
  });

  it("returns VALIDATION_ERROR for missing decision_id", () => {
    const { handler } = createHandler();
    const result = handler({});
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("VALIDATION_ERROR");
    }
  });

  it("returns VALIDATION_ERROR for invalid UUID format", () => {
    const { handler } = createHandler();
    const result = handler({ decision_id: "not-a-uuid" });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("VALIDATION_ERROR");
    }
  });

  it("includes matched_rules in response", () => {
    const { handler, decisionStore } = createHandler();
    decisionStore.put({
      decision_id: KNOWN_ID,
      decision: "allow",
      policy_id: "pg.default",
      matched_rules: ["rule-a", "rule-b"],
      explanation: "Allowed",
    });

    const result = handler({ decision_id: KNOWN_ID });
    expect(result.ok).toBe(true);
    if (result.ok) {
      const data = result.data as { matched_rules: string[] };
      expect(data.matched_rules).toEqual(["rule-a", "rule-b"]);
    }
  });

  it("emits audit event for successful lookup", () => {
    const auditEmitter = createSpyAuditEmitter();
    const { handler, decisionStore } = createHandler({ auditEmitter });
    decisionStore.put({
      decision_id: KNOWN_ID,
      decision: "allow",
      policy_id: "pg.default",
      matched_rules: ["no_rule_matched"],
      explanation: "Allowed",
    });

    handler({ decision_id: KNOWN_ID });
    expect(auditEmitter.events).toHaveLength(1);
    expect(auditEmitter.events[0].event_type).toBe("decision.explain");
    expect(auditEmitter.events[0].result).toBe("allow");
  });

  it("emits audit event for not-found lookup", () => {
    const auditEmitter = createSpyAuditEmitter();
    const { handler } = createHandler({ auditEmitter });
    handler({ decision_id: UNKNOWN_ID });
    expect(auditEmitter.events).toHaveLength(1);
    expect(auditEmitter.events[0].result).toBe("deny");
  });

  it("does not emit audit for validation errors", () => {
    const auditEmitter = createSpyAuditEmitter();
    const { handler } = createHandler({ auditEmitter });
    handler({});
    expect(auditEmitter.events).toHaveLength(0);
  });

  it("returns all fields from stored decision", () => {
    const { handler, decisionStore } = createHandler();
    decisionStore.put({
      decision_id: KNOWN_ID,
      decision: "require_approval",
      policy_id: "pg.exec.untrusted.content",
      matched_rules: ["pg.exec.untrusted.content"],
      explanation: "Require approval before executing tools with untrusted content",
    });

    const result = handler({ decision_id: KNOWN_ID });
    expect(result.ok).toBe(true);
    if (result.ok) {
      const data = result.data as Record<string, unknown>;
      expect(data.decision).toBe("require_approval");
      expect(data.policy_id).toBe("pg.exec.untrusted.content");
    }
  });
});
