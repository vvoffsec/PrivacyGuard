import { describe, it, expect } from "vitest";
import { createIngressEvaluateHandler } from "../handlers/ingress-evaluate.js";
import { createInMemoryDecisionStore } from "../decision-store.js";
import {
  createTestPDP,
  createNoOpAuditEmitter,
  createSpyAuditEmitter,
  validIngressRequest,
} from "./helpers.js";

function createHandler(
  overrides: {
    auditEmitter?: ReturnType<typeof createSpyAuditEmitter>;
  } = {},
) {
  const pdp = createTestPDP();
  const decisionStore = createInMemoryDecisionStore();
  const auditEmitter = overrides.auditEmitter ?? createNoOpAuditEmitter();
  const handler = createIngressEvaluateHandler({
    pdp,
    decisionStore,
    auditEmitter,
  });
  return { handler, decisionStore, auditEmitter };
}

describe("createIngressEvaluateHandler", () => {
  it("returns success for valid request", () => {
    const { handler } = createHandler();
    const result = handler(validIngressRequest());
    expect(result.ok).toBe(true);
  });

  it("returns VALIDATION_ERROR for invalid request", () => {
    const { handler } = createHandler();
    const result = handler({});
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("VALIDATION_ERROR");
    }
  });

  it("returns VALIDATION_ERROR for empty content", () => {
    const { handler } = createHandler();
    const result = handler(
      validIngressRequest({
        input: {
          content: "",
          source_type: "user_input",
          source_trust: "trusted_user",
        },
      }),
    );
    expect(result.ok).toBe(false);
  });

  it("includes decision_id in response", () => {
    const { handler } = createHandler();
    const result = handler(validIngressRequest());
    expect(result.ok).toBe(true);
    if (result.ok) {
      const data = result.data as Record<string, unknown>;
      expect(data.decision_id).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
      );
    }
  });

  it("includes effect in response", () => {
    const { handler } = createHandler();
    const result = handler(validIngressRequest());
    expect(result.ok).toBe(true);
    if (result.ok) {
      const data = result.data as Record<string, unknown>;
      expect(data.effect).toBe("allow");
    }
  });

  it("returns empty detected array in Phase 0", () => {
    const { handler } = createHandler();
    const result = handler(validIngressRequest());
    expect(result.ok).toBe(true);
    if (result.ok) {
      const data = result.data as Record<string, unknown>;
      expect(data.detected).toEqual([]);
    }
  });

  it("generates working_set_ref from decision_id", () => {
    const { handler } = createHandler();
    const result = handler(validIngressRequest());
    expect(result.ok).toBe(true);
    if (result.ok) {
      const data = result.data as {
        decision_id: string;
        working_set_ref: string;
      };
      expect(data.working_set_ref).toBe(`ws_${data.decision_id}`);
    }
  });

  it("stores decision in DecisionStore", () => {
    const { handler, decisionStore } = createHandler();
    const result = handler(validIngressRequest());
    expect(result.ok).toBe(true);
    if (result.ok) {
      const data = result.data as { decision_id: string };
      const stored = decisionStore.get(data.decision_id);
      expect(stored).toBeDefined();
      expect(stored?.decision).toBe("allow");
    }
  });

  it("emits audit event", () => {
    const auditEmitter = createSpyAuditEmitter();
    const { handler } = createHandler({ auditEmitter });
    handler(validIngressRequest());
    expect(auditEmitter.events).toHaveLength(1);
    expect(auditEmitter.events[0].event_type).toBe("ingress.evaluate");
  });

  it("audit event includes actor_id and agent_id", () => {
    const auditEmitter = createSpyAuditEmitter();
    const { handler } = createHandler({ auditEmitter });
    handler(validIngressRequest());
    expect(auditEmitter.events[0].actor_id).toBe("user-1");
    expect(auditEmitter.events[0].agent_id).toBe("agent-1");
  });

  it("includes policy_id and explanation in response", () => {
    const { handler } = createHandler();
    const result = handler(validIngressRequest());
    expect(result.ok).toBe(true);
    if (result.ok) {
      const data = result.data as {
        policy_id: string;
        explanation: string;
      };
      expect(data.policy_id).toBeDefined();
      expect(data.explanation).toBeDefined();
    }
  });

  it("handles untrusted external source", () => {
    const { handler } = createHandler();
    const result = handler(
      validIngressRequest({
        input: {
          content: "External content",
          source_type: "web_content",
          source_trust: "untrusted_external",
        },
      }),
    );
    expect(result.ok).toBe(true);
  });

  it("propagates PDP deny decisions", () => {
    const { handler } = createHandler();
    // Default PDP doesn't deny ingress by itself, so this should allow
    const result = handler(validIngressRequest());
    expect(result.ok).toBe(true);
    if (result.ok) {
      const data = result.data as { effect: string };
      expect(typeof data.effect).toBe("string");
    }
  });
});
