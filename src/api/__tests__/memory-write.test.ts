import { describe, it, expect } from "vitest";
import { createMemoryWriteHandler } from "../handlers/memory-write.js";
import { createInMemoryDecisionStore } from "../decision-store.js";
import { createPDP } from "../../pdp/pdp.js";
import { InProcessPolicyEngine } from "../../pdp/local-engine.js";
import { createDefaultPolicyBundle } from "../../pdp/default-policies.js";
import {
  createTestPDP,
  createNoOpAuditEmitter,
  createSpyAuditEmitter,
  validMemoryWriteRequest,
} from "./helpers.js";

function createHandler(
  overrides: {
    auditEmitter?: ReturnType<typeof createSpyAuditEmitter>;
    pdp?: ReturnType<typeof createPDP>;
  } = {},
) {
  const pdp = overrides.pdp ?? createTestPDP();
  const decisionStore = createInMemoryDecisionStore();
  const auditEmitter = overrides.auditEmitter ?? createNoOpAuditEmitter();
  const handler = createMemoryWriteHandler({
    pdp,
    decisionStore,
    auditEmitter,
  });
  return { handler, decisionStore, auditEmitter };
}

describe("createMemoryWriteHandler", () => {
  it("returns success for valid request", () => {
    const { handler } = createHandler();
    const result = handler(validMemoryWriteRequest());
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

  it("returns VALIDATION_ERROR for missing entry", () => {
    const { handler } = createHandler();
    const result = handler({
      memory_tier: "session",
      agent_id: "agent-1",
      task_id: "task-1",
    });
    expect(result.ok).toBe(false);
  });

  it("includes entry_id (UUID) in response", () => {
    const { handler } = createHandler();
    const result = handler(validMemoryWriteRequest());
    expect(result.ok).toBe(true);
    if (result.ok) {
      const data = result.data as { entry_id: string };
      expect(data.entry_id).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
      );
    }
  });

  it("effective_tier matches requested tier when allowed", () => {
    const { handler } = createHandler();
    const result = handler(validMemoryWriteRequest({ memory_tier: "session" }));
    expect(result.ok).toBe(true);
    if (result.ok) {
      const data = result.data as { effective_tier: string };
      expect(data.effective_tier).toBe("session");
    }
  });

  it("downgrades to quarantined when PDP quarantines", () => {
    // Create PDP with quarantine rule for untrusted durable writes
    const bundle = createDefaultPolicyBundle();
    const engine = new InProcessPolicyEngine(bundle);
    const pdp = createPDP(engine);
    const { handler } = createHandler({ pdp });

    const result = handler(
      validMemoryWriteRequest({
        memory_tier: "durable",
        entry: {
          key: "external-data",
          value: "untrusted content",
          source_trust: "untrusted_external",
        },
      }),
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      const data = result.data as {
        effective_tier: string;
        effect: string;
      };
      expect(data.effect).toBe("quarantine");
      expect(data.effective_tier).toBe("quarantined");
    }
  });

  it("passes through ttl_seconds as effective_ttl", () => {
    const { handler } = createHandler();
    const result = handler(validMemoryWriteRequest({ ttl_seconds: 600 }));
    expect(result.ok).toBe(true);
    if (result.ok) {
      const data = result.data as { effective_ttl: number };
      expect(data.effective_ttl).toBe(600);
    }
  });

  it("effective_ttl is undefined when ttl_seconds not provided", () => {
    const { handler } = createHandler();
    const result = handler(validMemoryWriteRequest());
    expect(result.ok).toBe(true);
    if (result.ok) {
      const data = result.data as { effective_ttl?: number };
      expect(data.effective_ttl).toBeUndefined();
    }
  });

  it("stores decision in DecisionStore", () => {
    const { handler, decisionStore } = createHandler();
    const result = handler(validMemoryWriteRequest());
    expect(result.ok).toBe(true);
    if (result.ok) {
      const data = result.data as { decision_id: string };
      const stored = decisionStore.get(data.decision_id);
      expect(stored).toBeDefined();
    }
  });

  it("emits audit event", () => {
    const auditEmitter = createSpyAuditEmitter();
    const { handler } = createHandler({ auditEmitter });
    handler(validMemoryWriteRequest());
    expect(auditEmitter.events).toHaveLength(1);
    expect(auditEmitter.events[0].event_type).toBe("memory.write");
    expect(auditEmitter.events[0].action).toBe("memory.write");
  });

  it("audit event includes agent_id", () => {
    const auditEmitter = createSpyAuditEmitter();
    const { handler } = createHandler({ auditEmitter });
    handler(validMemoryWriteRequest());
    expect(auditEmitter.events[0].agent_id).toBe("agent-1");
  });

  it("includes policy_id and explanation in response", () => {
    const { handler } = createHandler();
    const result = handler(validMemoryWriteRequest());
    expect(result.ok).toBe(true);
    if (result.ok) {
      const data = result.data as {
        policy_id: string;
        explanation: string;
      };
      expect(data.policy_id).toBeDefined();
      expect(data.explanation.length).toBeGreaterThan(0);
    }
  });

  it("handles ephemeral tier", () => {
    const { handler } = createHandler();
    const result = handler(validMemoryWriteRequest({ memory_tier: "ephemeral" }));
    expect(result.ok).toBe(true);
    if (result.ok) {
      const data = result.data as { effective_tier: string };
      expect(data.effective_tier).toBe("ephemeral");
    }
  });

  it("rejects quarantined as requested tier", () => {
    const { handler } = createHandler();
    const result = handler(validMemoryWriteRequest({ memory_tier: "quarantined" }));
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("VALIDATION_ERROR");
    }
  });
});
