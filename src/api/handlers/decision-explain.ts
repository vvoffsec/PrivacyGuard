import type { AuditEmitter, DecisionStore } from "../interfaces.js";
import type { ApiResult } from "../result.js";
import { apiSuccess, apiError } from "../result.js";
import { ApiValidationError } from "../errors.js";
import { parseDecisionExplainRequest, type DecisionExplainResponse } from "../types.js";
import type { ApiHandler } from "../transport.js";

export interface DecisionExplainConfig {
  readonly decisionStore: DecisionStore;
  readonly auditEmitter: AuditEmitter;
}

export function createDecisionExplainHandler(config: DecisionExplainConfig): ApiHandler {
  const { decisionStore, auditEmitter } = config;

  return (request: unknown): ApiResult<unknown> => {
    let req;
    try {
      req = parseDecisionExplainRequest(request);
    } catch (error) {
      if (error instanceof ApiValidationError) {
        return apiError(
          "VALIDATION_ERROR",
          "Invalid decision explain request",
          error.issues,
        );
      }
      throw error;
    }

    const stored = decisionStore.get(req.decision_id);

    if (!stored) {
      auditEmitter.emit({
        event_type: "decision.explain",
        timestamp: new Date().toISOString(),
        decision_id: req.decision_id,
        action: "decision.explain",
        result: "deny",
        explanation: "Decision not found",
      });

      return apiError("DECISION_NOT_FOUND", `Decision ${req.decision_id} not found`);
    }

    auditEmitter.emit({
      event_type: "decision.explain",
      timestamp: new Date().toISOString(),
      decision_id: req.decision_id,
      action: "decision.explain",
      result: stored.decision,
      explanation: stored.explanation,
    });

    const response: DecisionExplainResponse = {
      decision_id: stored.decision_id,
      decision: stored.decision,
      policy_id: stored.policy_id,
      matched_rules: [...stored.matched_rules],
      explanation: stored.explanation,
    };

    return apiSuccess(response);
  };
}
