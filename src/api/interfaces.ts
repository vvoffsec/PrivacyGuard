import type { DataClass } from "../data-model/data-class.js";
import type { PolicyEffect } from "../pdp/types.js";

// --- Capability Token Contracts (Plan 03) ---

export interface CapabilityTokenClaims {
  readonly agent_id: string;
  readonly task_id: string;
  readonly purpose_tag: string;
  readonly allowed_tools: readonly string[];
  readonly max_data_class: DataClass;
  readonly allowed_destinations: readonly string[];
  readonly memory_tier: string;
  readonly expires_at: string;
}

export interface TokenValidationResult {
  readonly valid: boolean;
  readonly claims?: CapabilityTokenClaims;
  readonly rejection_reason?: string;
}

export interface CapabilityTokenValidator {
  validate(
    token: string,
    context: { agent_id: string; task_id: string },
  ): TokenValidationResult;
}

// --- Audit Event Contracts (Plan 05) ---

export interface AuditEventData {
  readonly event_type: string;
  readonly timestamp: string;
  readonly decision_id?: string;
  readonly actor_id?: string;
  readonly agent_id?: string;
  readonly action: string;
  readonly result: PolicyEffect;
  readonly policy_id?: string;
  readonly matched_rules?: readonly string[];
  readonly explanation?: string;
  readonly extra?: Readonly<Record<string, unknown>>;
}

export interface AuditEmitter {
  emit(event: AuditEventData): void;
}

// --- Decision Store Contracts ---

export interface StoredDecision {
  readonly decision_id: string;
  readonly decision: PolicyEffect;
  readonly policy_id: string;
  readonly matched_rules: readonly string[];
  readonly explanation: string;
}

export interface DecisionStore {
  get(id: string): StoredDecision | undefined;
  put(decision: StoredDecision): void;
}
