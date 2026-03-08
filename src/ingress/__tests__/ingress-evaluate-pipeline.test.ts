import { describe, it, expect } from "vitest";
import { createIngressEvaluateHandler } from "../../api/handlers/ingress-evaluate.js";
import { createInMemoryDecisionStore } from "../../api/decision-store.js";
import {
  createTestPDP,
  createNoOpAuditEmitter,
  createSpyAuditEmitter,
  validIngressRequest,
} from "../../api/__tests__/helpers.js";
import { createDefaultIngressPipeline } from "../pipeline.js";

function createHandlerWithPipeline(
  overrides: {
    auditEmitter?: ReturnType<typeof createSpyAuditEmitter>;
  } = {},
) {
  const pdp = createTestPDP();
  const decisionStore = createInMemoryDecisionStore();
  const auditEmitter = overrides.auditEmitter ?? createNoOpAuditEmitter();
  const pipeline = createDefaultIngressPipeline();
  const handler = createIngressEvaluateHandler({
    pdp,
    decisionStore,
    auditEmitter,
    pipeline,
  });
  return { handler, decisionStore, auditEmitter };
}

describe("ingress-evaluate handler with pipeline", () => {
  it("returns success for clean content", () => {
    const { handler } = createHandlerWithPipeline();
    const result = handler(validIngressRequest());
    expect(result.ok).toBe(true);
  });

  it("populates detected array when PII found", () => {
    const { handler } = createHandlerWithPipeline();
    const result = handler(
      validIngressRequest({
        input: {
          content: "Contact me at user@example.com",
          source_type: "user_input",
          source_trust: "trusted_user",
        },
      }),
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      const data = result.data as { detected: { data_class: string }[] };
      expect(data.detected.length).toBeGreaterThan(0);
      expect(data.detected.some((d) => d.data_class === "pii")).toBe(true);
    }
  });

  it("returns empty detected for clean content", () => {
    const { handler } = createHandlerWithPipeline();
    const result = handler(validIngressRequest());
    expect(result.ok).toBe(true);
    if (result.ok) {
      const data = result.data as { detected: unknown[] };
      expect(data.detected).toEqual([]);
    }
  });

  it("includes content_hash in audit event extra", () => {
    const auditEmitter = createSpyAuditEmitter();
    const { handler } = createHandlerWithPipeline({ auditEmitter });
    handler(validIngressRequest());
    expect(auditEmitter.events).toHaveLength(1);
    expect(auditEmitter.events[0].extra).toBeDefined();
    const extra = auditEmitter.events[0].extra as Record<string, unknown>;
    expect(extra.content_hash).toMatch(/^sha256:/);
  });

  it("includes injection info in audit event extra", () => {
    const auditEmitter = createSpyAuditEmitter();
    const { handler } = createHandlerWithPipeline({ auditEmitter });
    handler(validIngressRequest());
    const extra = auditEmitter.events[0].extra as Record<string, unknown>;
    expect(extra.injection_detected).toBe(false);
  });

  it("stores decision for pipeline-evaluated content", () => {
    const { handler, decisionStore } = createHandlerWithPipeline();
    const result = handler(validIngressRequest());
    expect(result.ok).toBe(true);
    if (result.ok) {
      const data = result.data as { decision_id: string };
      expect(decisionStore.get(data.decision_id)).toBeDefined();
    }
  });

  it("returns PIPELINE_ERROR when pipeline fails", () => {
    const pdp = createTestPDP();
    const decisionStore = createInMemoryDecisionStore();
    const auditEmitter = createNoOpAuditEmitter();
    const failingPipeline = {
      evaluate: () => {
        throw new Error("Pipeline exploded");
      },
    };
    const handler = createIngressEvaluateHandler({
      pdp,
      decisionStore,
      auditEmitter,
      pipeline: failingPipeline,
    });

    const result = handler(validIngressRequest());
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("PIPELINE_ERROR");
    }
  });

  it("still works without pipeline (backward compat)", () => {
    const pdp = createTestPDP();
    const decisionStore = createInMemoryDecisionStore();
    const auditEmitter = createNoOpAuditEmitter();
    const handler = createIngressEvaluateHandler({
      pdp,
      decisionStore,
      auditEmitter,
      // no pipeline
    });

    const result = handler(validIngressRequest());
    expect(result.ok).toBe(true);
    if (result.ok) {
      const data = result.data as { detected: unknown[] };
      expect(data.detected).toEqual([]);
    }
  });

  it("handles untrusted content with PII through pipeline", () => {
    const { handler } = createHandlerWithPipeline();
    const result = handler(
      validIngressRequest({
        input: {
          content: "Email: user@example.com, SSN: 123-45-6789",
          source_type: "web_content",
          source_trust: "untrusted_external",
        },
      }),
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      const data = result.data as { detected: { data_class: string }[] };
      expect(data.detected.some((d) => d.data_class === "pii")).toBe(true);
    }
  });

  it("generates working_set_ref from decision_id", () => {
    const { handler } = createHandlerWithPipeline();
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
});
