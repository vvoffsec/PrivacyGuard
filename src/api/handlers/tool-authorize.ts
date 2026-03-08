import type { PDP } from "../../pdp/pdp.js";
import type {
  AuditEmitter,
  CapabilityTokenValidator,
  DecisionStore,
} from "../interfaces.js";
import type { ApiResult } from "../result.js";
import { apiSuccess, apiError } from "../result.js";
import { ApiValidationError } from "../errors.js";
import { parseToolAuthorizeRequest, type ToolAuthorizeResponse } from "../types.js";
import type { ApiHandler } from "../transport.js";

export interface ToolAuthorizeConfig {
  readonly pdp: PDP;
  readonly tokenValidator: CapabilityTokenValidator;
  readonly decisionStore: DecisionStore;
  readonly auditEmitter: AuditEmitter;
}

export function createToolAuthorizeHandler(config: ToolAuthorizeConfig): ApiHandler {
  const { pdp, tokenValidator, decisionStore, auditEmitter } = config;

  return (request: unknown): ApiResult<unknown> => {
    let req;
    try {
      req = parseToolAuthorizeRequest(request);
    } catch (error) {
      if (error instanceof ApiValidationError) {
        return apiError(
          "VALIDATION_ERROR",
          "Invalid tool authorize request",
          error.issues,
        );
      }
      throw error;
    }

    // Validate capability token first
    const tokenResult = tokenValidator.validate(req.capability_token, {
      agent_id: req.agent_id,
      task_id: req.task_id,
    });

    if (!tokenResult.valid) {
      const response: ToolAuthorizeResponse = {
        decision_id: "00000000-0000-4000-8000-000000000000",
        effect: "deny",
        policy_id: "pg.token.invalid",
        explanation: tokenResult.rejection_reason ?? "Capability token is invalid",
        reasons: [tokenResult.rejection_reason ?? "Capability token is invalid"],
      };

      auditEmitter.emit({
        event_type: "tool.authorize",
        timestamp: new Date().toISOString(),
        agent_id: req.agent_id,
        action: `tool.${req.tool.action}`,
        result: "deny",
        policy_id: "pg.token.invalid",
        explanation: tokenResult.rejection_reason ?? "Capability token is invalid",
      });

      return apiSuccess(response);
    }

    const policyInput = {
      principal: { type: "agent" as const, id: req.agent_id },
      request: {
        action: `tool.${req.tool.action}`,
        purpose: [],
        task_id: req.task_id,
      },
      resource: { type: "tool", name: req.tool.name },
      data: {
        source_trust: [],
        sensitivity: req.data_sensitivity ?? [],
        taint_flags: [],
      },
      destination: {
        kind: req.requested_destination ? "remote" : "local",
        name: req.requested_destination ?? "local",
      },
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
      event_type: "tool.authorize",
      timestamp: new Date().toISOString(),
      decision_id: decision.decision_id,
      agent_id: req.agent_id,
      action: `tool.${req.tool.action}`,
      result: decision.decision,
      policy_id: decision.policy_id,
      matched_rules: decision.matched_rules,
      explanation: decision.explanation,
    });

    const response: ToolAuthorizeResponse = {
      decision_id: decision.decision_id,
      effect: decision.decision,
      policy_id: decision.policy_id,
      explanation: decision.explanation,
      reasons: [...decision.matched_rules],
      approval_prompt_ref:
        decision.decision === "require_approval"
          ? `approval_${decision.decision_id}`
          : undefined,
    };

    return apiSuccess(response);
  };
}
