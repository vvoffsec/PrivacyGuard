import { InProcessPolicyEngine } from "../../pdp/local-engine.js";
import { createDefaultPolicyBundle } from "../../pdp/default-policies.js";
import { createPDP } from "../../pdp/pdp.js";
import type { PDP } from "../../pdp/pdp.js";
import type {
  AuditEmitter,
  AuditEventData,
  CapabilityTokenValidator,
  TokenValidationResult,
} from "../interfaces.js";

export function createNoOpAuditEmitter(): AuditEmitter {
  return Object.freeze({
    emit(_event: AuditEventData): void {
      // no-op for tests
    },
  });
}

export function createSpyAuditEmitter(): AuditEmitter & {
  events: AuditEventData[];
} {
  const events: AuditEventData[] = [];
  return {
    emit(event: AuditEventData): void {
      events.push(event);
    },
    events,
  };
}

export function createAlwaysValidTokenValidator(): CapabilityTokenValidator {
  return Object.freeze({
    validate(
      _token: string,
      _context: { agent_id: string; task_id: string },
    ): TokenValidationResult {
      return {
        valid: true,
        claims: {
          agent_id: _context.agent_id,
          task_id: _context.task_id,
          purpose_tag: "general",
          allowed_tools: ["*"],
          max_data_class: "secret",
          allowed_destinations: ["*"],
          memory_tier: "durable",
          expires_at: new Date(Date.now() + 3600000).toISOString(),
        },
      };
    },
  });
}

export function createAlwaysInvalidTokenValidator(
  reason?: string,
): CapabilityTokenValidator {
  return Object.freeze({
    validate(
      _token: string,
      _context: { agent_id: string; task_id: string },
    ): TokenValidationResult {
      return {
        valid: false,
        rejection_reason: reason ?? "Token rejected for testing",
      };
    },
  });
}

export function createTestPDP(): PDP {
  const bundle = createDefaultPolicyBundle();
  const engine = new InProcessPolicyEngine(bundle);
  return createPDP(engine);
}

export function validIngressRequest(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    input: {
      content: "Hello, world!",
      source_type: "user_input",
      source_trust: "trusted_user",
    },
    actor_id: "user-1",
    agent_id: "agent-1",
    purpose: "user_request",
    task_id: "task-1",
    ...overrides,
  };
}

export function validToolAuthorizeRequest(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    tool: {
      name: "file_read",
      action: "read",
    },
    capability_token: "valid-test-token",
    agent_id: "agent-1",
    task_id: "task-1",
    ...overrides,
  };
}

export function validMemoryWriteRequest(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    entry: {
      key: "test-key",
      value: "test-value",
      source_trust: "trusted_user",
    },
    memory_tier: "session",
    agent_id: "agent-1",
    task_id: "task-1",
    ...overrides,
  };
}
