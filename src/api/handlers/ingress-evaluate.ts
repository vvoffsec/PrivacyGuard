import type { PDP } from "../../pdp/pdp.js";
import type { AuditEmitter, DecisionStore } from "../interfaces.js";
import type { ApiResult } from "../result.js";
import { apiSuccess, apiError } from "../result.js";
import { ApiValidationError } from "../errors.js";
import { parseIngressEvaluateRequest, type IngressEvaluateResponse } from "../types.js";
import type { ApiHandler } from "../transport.js";

export interface IngressEvaluateConfig {
  readonly pdp: PDP;
  readonly decisionStore: DecisionStore;
  readonly auditEmitter: AuditEmitter;
}

export function createIngressEvaluateHandler(config: IngressEvaluateConfig): ApiHandler {
  const { pdp, decisionStore, auditEmitter } = config;

  return (request: unknown): ApiResult<unknown> => {
    let req;
    try {
      req = parseIngressEvaluateRequest(request);
    } catch (error) {
      if (error instanceof ApiValidationError) {
        return apiError(
          "VALIDATION_ERROR",
          "Invalid ingress evaluate request",
          error.issues,
        );
      }
      throw error;
    }

    const policyInput = {
      principal: { type: "agent" as const, id: req.agent_id },
      request: {
        action: "ingress.evaluate",
        purpose: [req.purpose],
        task_id: req.task_id,
      },
      resource: { type: "content", name: req.input.source_type },
      data: {
        source_trust: [req.input.source_trust],
        sensitivity: [],
        taint_flags: [],
      },
      destination: { kind: "local", name: "working_set" },
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
      event_type: "ingress.evaluate",
      timestamp: new Date().toISOString(),
      decision_id: decision.decision_id,
      actor_id: req.actor_id,
      agent_id: req.agent_id,
      action: "ingress.evaluate",
      result: decision.decision,
      policy_id: decision.policy_id,
      matched_rules: decision.matched_rules,
      explanation: decision.explanation,
    });

    const response: IngressEvaluateResponse = {
      decision_id: decision.decision_id,
      effect: decision.decision,
      policy_id: decision.policy_id,
      explanation: decision.explanation,
      detected: [], // Phase 0: empty until Sensitivity Engine (Phase 1)
      working_set_ref: `ws_${decision.decision_id}`,
    };

    return apiSuccess(response);
  };
}
