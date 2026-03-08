import { v4 as uuidv4 } from "uuid";
import type { PDP } from "../../pdp/pdp.js";
import type { AuditEmitter, DecisionStore } from "../interfaces.js";
import type { ApiResult } from "../result.js";
import { apiSuccess, apiError } from "../result.js";
import { ApiValidationError } from "../errors.js";
import { parseMemoryWriteRequest, type MemoryWriteResponse } from "../types.js";
import type { ApiHandler } from "../transport.js";

export interface MemoryWriteConfig {
  readonly pdp: PDP;
  readonly decisionStore: DecisionStore;
  readonly auditEmitter: AuditEmitter;
}

export function createMemoryWriteHandler(config: MemoryWriteConfig): ApiHandler {
  const { pdp, decisionStore, auditEmitter } = config;

  return (request: unknown): ApiResult<unknown> => {
    let req;
    try {
      req = parseMemoryWriteRequest(request);
    } catch (error) {
      if (error instanceof ApiValidationError) {
        return apiError("VALIDATION_ERROR", "Invalid memory write request", error.issues);
      }
      throw error;
    }

    const policyInput = {
      principal: { type: "agent" as const, id: req.agent_id },
      request: {
        action: "memory.write",
        purpose: [req.memory_tier],
        task_id: req.task_id,
      },
      resource: { type: "memory", name: req.entry.key },
      data: {
        source_trust: [req.entry.source_trust],
        sensitivity: req.entry.sensitivity,
        taint_flags: [],
      },
      destination: { kind: "local", name: "memory_store" },
      environment: { host_class: "workstation", policy_bundle: "default" },
    };

    const decision = pdp.evaluate(policyInput);

    decisionStore.put({
      decision_id: decision.decision_id,
      decision: decision.decision,
      policy_id: decision.policy_id,
      matched_rules: decision.matched_rules,
      explanation: decision.explanation,
    });

    auditEmitter.emit({
      event_type: "memory.write",
      timestamp: new Date().toISOString(),
      decision_id: decision.decision_id,
      agent_id: req.agent_id,
      action: "memory.write",
      result: decision.decision,
      policy_id: decision.policy_id,
      matched_rules: decision.matched_rules,
      explanation: decision.explanation,
    });

    // PDP can downgrade tier to "quarantined"
    const effectiveTier =
      decision.decision === "quarantine" ? "quarantined" : req.memory_tier;

    const response: MemoryWriteResponse = {
      decision_id: decision.decision_id,
      effect: decision.decision,
      policy_id: decision.policy_id,
      explanation: decision.explanation,
      entry_id: uuidv4(),
      effective_tier: effectiveTier,
      effective_ttl: req.ttl_seconds,
    };

    return apiSuccess(response);
  };
}
