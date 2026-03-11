import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createApprovalOrchestrator } from "../orchestrator.js";
import { createApprovalStore } from "../approval-store.js";
import type {
  ApprovalOrchestrator,
  ApprovalOrchestratorConfig,
  ApprovalUxAdapter,
  ApprovalStore,
  ApprovalResponse,
  ApprovalPrompt,
} from "../types.js";
import type { PolicyDecision, PolicyInput } from "../../pdp/types.js";
import type { AuditEvent } from "../../audit/types.js";
import { ApprovalValidationError, ApprovalOrchestratorError } from "../errors.js";

// --- Test helpers ---

function makeDecision(overrides: Partial<PolicyDecision> = {}): PolicyDecision {
  return {
    decision: "require_approval",
    decision_id: "550e8400-e29b-41d4-a716-446655440000",
    policy_id: "pg.test.policy",
    matched_rules: ["rule-1"],
    explanation: "Requires approval",
    policy_bundle_version: "1.0.0",
    ...overrides,
  } as PolicyDecision;
}

function makeInput(overrides: Partial<Record<string, unknown>> = {}): PolicyInput {
  return {
    principal: { type: "agent", id: "agent-1" },
    request: { action: "file.write", purpose: ["backup"], task_id: "task-1" },
    resource: { type: "file", name: "config.json" },
    data: { source_trust: [], sensitivity: ["confidential"], taint_flags: [] },
    destination: { kind: "cloud-storage", name: "s3-bucket" },
    environment: { host_class: "production", policy_bundle: "v1" },
    ...overrides,
  } as PolicyInput;
}

function makeApprovedResponse(
  overrides: Partial<ApprovalResponse> = {},
): ApprovalResponse {
  return {
    approved: true,
    actor_id: "user-1",
    reason: "Approved for backup",
    ...overrides,
  } as ApprovalResponse;
}

function makeDeniedResponse(overrides: Partial<ApprovalResponse> = {}): ApprovalResponse {
  return {
    approved: false,
    actor_id: "user-1",
    reason: "Not authorized for this action",
    ...overrides,
  } as ApprovalResponse;
}

interface TrackedAdapter extends ApprovalUxAdapter {
  calls: ApprovalPrompt[];
}

function createTrackedAdapter(response: ApprovalResponse): TrackedAdapter {
  const calls: ApprovalPrompt[] = [];
  return {
    calls,
    requestApproval(prompt: ApprovalPrompt): ApprovalResponse {
      calls.push(prompt);
      return response;
    },
  };
}

interface TrackedEmitter {
  emit(event: AuditEvent): void;
  query(): readonly AuditEvent[];
  count(): number;
  events: AuditEvent[];
}

function createTrackedEmitter(): TrackedEmitter {
  const events: AuditEvent[] = [];
  return {
    events,
    emit(event: AuditEvent): void {
      events.push(event);
    },
    query(): readonly AuditEvent[] {
      return [];
    },
    count(): number {
      return 0;
    },
  };
}

function createTestOrchestrator(overrides: Partial<ApprovalOrchestratorConfig> = {}): {
  orchestrator: ApprovalOrchestrator;
  store: ApprovalStore;
  adapter: TrackedAdapter;
  emitter: TrackedEmitter;
} {
  const store = overrides.store ?? createApprovalStore();
  const adapter =
    (overrides.uxAdapter as TrackedAdapter | undefined) ??
    createTrackedAdapter(makeApprovedResponse());
  const emitter =
    (overrides.auditEmitter as TrackedEmitter | undefined) ?? createTrackedEmitter();

  const orchestrator = createApprovalOrchestrator({
    store,
    uxAdapter: adapter,
    auditEmitter: emitter,
    defaultTtlSeconds: overrides.defaultTtlSeconds ?? 300,
  });

  return { orchestrator, store, adapter, emitter };
}

// --- Tests ---

describe("createApprovalOrchestrator", () => {
  // --- Guard clause ---

  describe("guard clause", () => {
    it("throws ApprovalValidationError when decision is not require_approval", () => {
      const { orchestrator } = createTestOrchestrator();
      const decision = makeDecision({ decision: "allow" });
      expect(() => orchestrator.evaluate(decision, makeInput())).toThrow(
        ApprovalValidationError,
      );
    });

    it("includes the actual decision in the error message", () => {
      const { orchestrator } = createTestOrchestrator();
      const decision = makeDecision({ decision: "deny" });
      expect(() => orchestrator.evaluate(decision, makeInput())).toThrow(/deny/);
    });

    it("accepts require_approval decisions", () => {
      const { orchestrator } = createTestOrchestrator();
      expect(() => orchestrator.evaluate(makeDecision(), makeInput())).not.toThrow(
        ApprovalValidationError,
      );
    });
  });

  // --- Fresh approval flow ---

  describe("fresh approval flow", () => {
    it("returns approved=true when adapter approves", () => {
      const adapter = createTrackedAdapter(makeApprovedResponse());
      const { orchestrator } = createTestOrchestrator({ uxAdapter: adapter });
      const result = orchestrator.evaluate(makeDecision(), makeInput());
      expect(result.approved).toBe(true);
    });

    it("returns approved=false when adapter denies", () => {
      const adapter = createTrackedAdapter(makeDeniedResponse());
      const { orchestrator } = createTestOrchestrator({ uxAdapter: adapter });
      const result = orchestrator.evaluate(makeDecision(), makeInput());
      expect(result.approved).toBe(false);
    });

    it("sets prompt_shown=true for fresh approvals", () => {
      const { orchestrator } = createTestOrchestrator();
      const result = orchestrator.evaluate(makeDecision(), makeInput());
      expect(result.prompt_shown).toBe(true);
    });

    it("includes approval_id in result", () => {
      const { orchestrator } = createTestOrchestrator();
      const result = orchestrator.evaluate(makeDecision(), makeInput());
      expect(result.approval_id).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
      );
    });

    it("includes scope_hash in result", () => {
      const { orchestrator } = createTestOrchestrator();
      const result = orchestrator.evaluate(makeDecision(), makeInput());
      expect(result.scope_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
    });

    it("includes reason from adapter response", () => {
      const adapter = createTrackedAdapter(makeApprovedResponse({ reason: "LGTM" }));
      const { orchestrator } = createTestOrchestrator({ uxAdapter: adapter });
      const result = orchestrator.evaluate(makeDecision(), makeInput());
      expect(result.reason).toBe("LGTM");
    });

    it("sets expires_at for approved responses", () => {
      const { orchestrator } = createTestOrchestrator();
      const result = orchestrator.evaluate(makeDecision(), makeInput());
      expect(result.expires_at).toBeDefined();
    });

    it("does not set expires_at for denied responses", () => {
      const adapter = createTrackedAdapter(makeDeniedResponse());
      const { orchestrator } = createTestOrchestrator({ uxAdapter: adapter });
      const result = orchestrator.evaluate(makeDecision(), makeInput());
      expect(result.expires_at).toBeUndefined();
    });

    it("passes correct prompt to adapter", () => {
      const adapter = createTrackedAdapter(makeApprovedResponse());
      const { orchestrator } = createTestOrchestrator({ uxAdapter: adapter });
      orchestrator.evaluate(makeDecision(), makeInput());
      expect(adapter.calls).toHaveLength(1);
      const prompt = adapter.calls[0];
      expect(prompt.action).toBe("file.write");
      expect(prompt.destination).toBe("s3-bucket");
      expect(prompt.policy_id).toBe("pg.test.policy");
    });

    it("returns frozen result", () => {
      const { orchestrator } = createTestOrchestrator();
      const result = orchestrator.evaluate(makeDecision(), makeInput());
      expect(Object.isFrozen(result)).toBe(true);
    });
  });

  // --- Cached approval ---

  describe("cached approval", () => {
    it("reuses cached granted approval", () => {
      const adapter = createTrackedAdapter(makeApprovedResponse());
      const { orchestrator } = createTestOrchestrator({ uxAdapter: adapter });
      const decision = makeDecision();
      const input = makeInput();

      // First call — triggers prompt
      orchestrator.evaluate(decision, input);
      expect(adapter.calls).toHaveLength(1);

      // Second call — should use cache
      const result = orchestrator.evaluate(decision, input);
      expect(result.prompt_shown).toBe(false);
      expect(result.approved).toBe(true);
      expect(adapter.calls).toHaveLength(1);
    });

    it("does not reuse denied cached approval (re-prompts)", () => {
      const adapter = createTrackedAdapter(makeDeniedResponse());
      const { orchestrator } = createTestOrchestrator({ uxAdapter: adapter });
      const decision = makeDecision();
      const input = makeInput();

      // First call — denied
      orchestrator.evaluate(decision, input);

      // Second call — should re-prompt because denied is not "granted"
      orchestrator.evaluate(decision, input);
      expect(adapter.calls).toHaveLength(2);
    });
  });

  // --- TTL handling ---

  describe("TTL handling", () => {
    beforeEach(() => {
      vi.useFakeTimers();
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it("uses default TTL of 300 seconds", () => {
      const now = Date.now();
      vi.setSystemTime(now);

      const { orchestrator } = createTestOrchestrator();
      const result = orchestrator.evaluate(makeDecision(), makeInput());

      expect(result.expires_at).toBeDefined();
      const expiresAt = new Date(result.expires_at ?? "").getTime();
      expect(expiresAt).toBeCloseTo(now + 300_000, -2);
    });

    it("uses custom TTL from config", () => {
      const now = Date.now();
      vi.setSystemTime(now);

      const { orchestrator } = createTestOrchestrator({ defaultTtlSeconds: 600 });
      const result = orchestrator.evaluate(makeDecision(), makeInput());

      expect(result.expires_at).toBeDefined();
      const expiresAt = new Date(result.expires_at ?? "").getTime();
      expect(expiresAt).toBeCloseTo(now + 600_000, -2);
    });

    it("uses TTL from adapter response if provided", () => {
      const now = Date.now();
      vi.setSystemTime(now);

      const adapter = createTrackedAdapter(
        makeApprovedResponse({ expires_in_seconds: 60 }),
      );
      const { orchestrator } = createTestOrchestrator({ uxAdapter: adapter });
      const result = orchestrator.evaluate(makeDecision(), makeInput());

      expect(result.expires_at).toBeDefined();
      const expiresAt = new Date(result.expires_at ?? "").getTime();
      expect(expiresAt).toBeCloseTo(now + 60_000, -2);
    });

    it("re-prompts after cached approval expires", () => {
      const now = Date.now();
      vi.setSystemTime(now);

      const adapter = createTrackedAdapter(
        makeApprovedResponse({ expires_in_seconds: 10 }),
      );
      const { orchestrator } = createTestOrchestrator({ uxAdapter: adapter });
      const decision = makeDecision();
      const input = makeInput();

      // First call
      orchestrator.evaluate(decision, input);
      expect(adapter.calls).toHaveLength(1);

      // Advance past TTL
      vi.setSystemTime(now + 11_000);

      // Second call — cache expired, should re-prompt
      orchestrator.evaluate(decision, input);
      expect(adapter.calls).toHaveLength(2);
    });
  });

  // --- Audit emission ---

  describe("audit emission", () => {
    it("emits an approval event on grant", () => {
      const emitter = createTrackedEmitter();
      const { orchestrator } = createTestOrchestrator({ auditEmitter: emitter });
      orchestrator.evaluate(makeDecision(), makeInput());
      expect(emitter.events).toHaveLength(1);
      expect(emitter.events[0].event_type).toBe("approval");
    });

    it("emits an approval event on denial", () => {
      const emitter = createTrackedEmitter();
      const adapter = createTrackedAdapter(makeDeniedResponse());
      const { orchestrator } = createTestOrchestrator({
        auditEmitter: emitter,
        uxAdapter: adapter,
      });
      orchestrator.evaluate(makeDecision(), makeInput());
      expect(emitter.events).toHaveLength(1);
    });

    it("does not emit when using cached approval", () => {
      const emitter = createTrackedEmitter();
      const { orchestrator } = createTestOrchestrator({ auditEmitter: emitter });
      const decision = makeDecision();
      const input = makeInput();

      orchestrator.evaluate(decision, input);
      orchestrator.evaluate(decision, input); // cached

      expect(emitter.events).toHaveLength(1); // only first call
    });

    it("emitted event has correct status for grant", () => {
      const emitter = createTrackedEmitter();
      const { orchestrator } = createTestOrchestrator({ auditEmitter: emitter });
      orchestrator.evaluate(makeDecision(), makeInput());
      const event = emitter.events[0];
      if ("status" in event) {
        expect(event.status).toBe("granted");
      }
    });

    it("emitted event has correct status for denial", () => {
      const emitter = createTrackedEmitter();
      const adapter = createTrackedAdapter(makeDeniedResponse());
      const { orchestrator } = createTestOrchestrator({
        auditEmitter: emitter,
        uxAdapter: adapter,
      });
      orchestrator.evaluate(makeDecision(), makeInput());
      const event = emitter.events[0];
      if ("status" in event) {
        expect(event.status).toBe("denied");
      }
    });
  });

  // --- Store recording ---

  describe("store recording", () => {
    it("stores granted approval in the store", () => {
      const { orchestrator, store } = createTestOrchestrator();
      const result = orchestrator.evaluate(makeDecision(), makeInput());
      expect(store.count()).toBe(1);
      const found = store.findByScope(result.scope_hash);
      expect(found?.status).toBe("granted");
    });

    it("stores denied approval in the store", () => {
      const adapter = createTrackedAdapter(makeDeniedResponse());
      const { orchestrator, store } = createTestOrchestrator({ uxAdapter: adapter });
      const result = orchestrator.evaluate(makeDecision(), makeInput());
      expect(store.count()).toBe(1);
      const found = store.findByScope(result.scope_hash);
      expect(found?.status).toBe("denied");
    });
  });

  // --- Error propagation ---

  describe("error propagation", () => {
    it("wraps unexpected errors in ApprovalOrchestratorError", () => {
      const adapter: ApprovalUxAdapter = {
        requestApproval: () => {
          throw new Error("UX adapter crashed");
        },
      };
      const { orchestrator } = createTestOrchestrator({
        uxAdapter: adapter as TrackedAdapter,
      });
      expect(() => orchestrator.evaluate(makeDecision(), makeInput())).toThrow(
        ApprovalOrchestratorError,
      );
    });

    it("preserves cause in wrapped errors", () => {
      const adapter: ApprovalUxAdapter = {
        requestApproval: () => {
          throw new Error("Connection lost");
        },
      };
      const { orchestrator } = createTestOrchestrator({
        uxAdapter: adapter as TrackedAdapter,
      });
      try {
        orchestrator.evaluate(makeDecision(), makeInput());
        expect.fail("Should have thrown");
      } catch (e) {
        expect(e).toBeInstanceOf(ApprovalOrchestratorError);
        expect((e as ApprovalOrchestratorError).cause?.message).toBe("Connection lost");
      }
    });

    it("does not wrap ApprovalValidationError", () => {
      const { orchestrator } = createTestOrchestrator();
      const decision = makeDecision({ decision: "allow" });
      expect(() => orchestrator.evaluate(decision, makeInput())).toThrow(
        ApprovalValidationError,
      );
    });
  });
});
