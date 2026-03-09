import { v4 as uuidv4 } from "uuid";
import { checkScope } from "../capabilities/scope.js";
import type { CapabilityTokenClaims, TokenValidationResult } from "../api/interfaces.js";
import { mostRestrictiveEffect, type PolicyEffect } from "../pdp/types.js";
import type {
  ToolGateway,
  ToolGatewayConfig,
  ToolGatewayRequest,
  ToolGatewayResult,
  ToolCategory,
} from "./types.js";
import { postureToEffect } from "./types.js";
import { DataClassSchema, highestDataClass } from "../data-model/data-class.js";

const DENY_DECISION_ID = "00000000-0000-4000-8000-000000000000";

function buildDenyResult(
  policyId: string,
  explanation: string,
  category?: ToolCategory,
): ToolGatewayResult {
  return Object.freeze({
    decision: "deny" as PolicyEffect,
    decision_id: DENY_DECISION_ID,
    policy_id: policyId,
    explanation,
    matched_rules: [policyId],
    category,
  });
}

function parseDataClasses(
  classes: string[],
): ReturnType<typeof DataClassSchema.safeParse>[] {
  return classes.map((c) => DataClassSchema.safeParse(c));
}

export function createToolGateway(config: ToolGatewayConfig): ToolGateway {
  const {
    pdp,
    tokenValidator,
    categoryClassifier,
    argumentValidator,
    argumentSanitizer,
  } = config;

  function authorize(request: ToolGatewayRequest): ToolGatewayResult {
    try {
      // 1. Classify tool
      const category = categoryClassifier.classify(request.tool_name);
      if (!category) {
        return buildDenyResult(
          "pg.gateway.unknown_tool",
          `Unknown tool "${request.tool_name}" — cannot classify`,
        );
      }

      // 2. Validate arguments
      const parameters = request.tool_parameters ?? {};
      const validation = argumentValidator.validate(category.name, parameters);
      if (!validation.valid) {
        return Object.freeze({
          decision: "deny" as PolicyEffect,
          decision_id: DENY_DECISION_ID,
          policy_id: "pg.gateway.invalid_args",
          explanation: `Argument validation failed: ${validation.errors.join("; ")}`,
          matched_rules: ["pg.gateway.invalid_args"],
          category,
          argument_validation: validation,
        });
      }

      // 3. Sanitize arguments
      const sanitization = argumentSanitizer.sanitize(category.name, parameters);
      if (!sanitization.safe) {
        const criticalFindings = sanitization.findings
          .filter((f) => f.severity === "critical")
          .map((f) => f.description);
        return Object.freeze({
          decision: "deny" as PolicyEffect,
          decision_id: DENY_DECISION_ID,
          policy_id: "pg.gateway.injection_detected",
          explanation: `Injection/traversal detected: ${criticalFindings.join("; ")}`,
          matched_rules: ["pg.gateway.injection_detected"],
          category,
          sanitization,
          argument_validation: validation,
        });
      }

      // 4. Validate capability token
      const tokenResult = tokenValidator.validate(request.capability_token_raw, {
        agent_id: request.agent_id,
        task_id: request.task_id,
      });
      if (!tokenResult.valid) {
        return Object.freeze({
          decision: "deny" as PolicyEffect,
          decision_id: DENY_DECISION_ID,
          policy_id: "pg.gateway.token_invalid",
          explanation: tokenResult.rejection_reason ?? "Capability token is invalid",
          matched_rules: ["pg.gateway.token_invalid"],
          category,
          sanitization,
          argument_validation: validation,
        });
      }

      // 5. Check scope
      const claims = (
        tokenResult as TokenValidationResult & { claims: CapabilityTokenClaims }
      ).claims;
      const validClasses = parseDataClasses(request.data_sensitivity ?? [])
        .filter((r) => r.success)
        .map((r) => r.data);
      const dataClass =
        validClasses.length > 0 ? highestDataClass(validClasses) : undefined;
      const scopeResult = checkScope(
        {
          token_id: uuidv4(),
          agent_id: claims.agent_id,
          task_id: claims.task_id,
          purpose_tags: [claims.purpose_tag],
          working_set_hash: "scope-check",
          allowed_tools: [...claims.allowed_tools],
          max_data_class: claims.max_data_class,
          allowed_destinations: [...claims.allowed_destinations],
          memory_tier: claims.memory_tier as "ephemeral" | "session" | "durable",
          approval_state: "not_required",
          ttl: 300,
          issued_at: new Date().toISOString(),
          expires_at: claims.expires_at,
          signature: "scope-check",
          revoked: false,
          source_decision_id: uuidv4(),
        },
        {
          tool: request.tool_name,
          destination: request.requested_destination,
          data_class: dataClass,
        },
      );

      if (!scopeResult.allowed) {
        return Object.freeze({
          decision: "deny" as PolicyEffect,
          decision_id: DENY_DECISION_ID,
          policy_id: "pg.gateway.scope_violation",
          explanation: `Scope violation: ${scopeResult.denial_reasons.join("; ")}`,
          matched_rules: ["pg.gateway.scope_violation"],
          category,
          sanitization,
          argument_validation: validation,
        });
      }

      // 6. Build enriched PolicyInput with taint flags
      const taintFlags = [...(request.taint_flags ?? [])];
      taintFlags.push(`tool_risk:${category.risk_level}`);
      taintFlags.push(`category:${category.name}`);
      if (sanitization.findings.length > 0) {
        taintFlags.push("sanitization_warning");
      }

      const policyInput = {
        principal: { type: "agent" as const, id: request.agent_id },
        request: {
          action: `tool.${request.tool_action}`,
          purpose: [],
          task_id: request.task_id,
        },
        resource: { type: "tool", name: request.tool_name },
        data: {
          source_trust: [],
          sensitivity: request.data_sensitivity ?? [],
          taint_flags: taintFlags,
        },
        destination: {
          kind: request.requested_destination ? "remote" : "local",
          name: request.requested_destination ?? "local",
        },
        environment: { host_class: "workstation", policy_bundle: "default" },
      };

      // 7. Evaluate PDP
      const decision = pdp.evaluate(policyInput);

      // 8. Apply category default posture (most restrictive wins)
      const categoryEffect = postureToEffect(category.default_posture);
      const finalDecision = mostRestrictiveEffect([decision.decision, categoryEffect]);

      const decisionId = decision.decision_id;
      const matchedRules = [...decision.matched_rules];
      if (finalDecision !== decision.decision) {
        matchedRules.push(
          `category_default:${category.name}:${category.default_posture}`,
        );
      }

      const explanation =
        finalDecision !== decision.decision
          ? `${decision.explanation} (escalated by category "${category.name}" default posture: ${category.default_posture})`
          : decision.explanation;

      return Object.freeze({
        decision: finalDecision,
        decision_id: decisionId,
        policy_id: decision.policy_id,
        explanation,
        matched_rules: matchedRules,
        category,
        sanitization,
        argument_validation: validation,
        approval_prompt_ref:
          finalDecision === "require_approval" ? `approval_${decisionId}` : undefined,
      });
    } catch {
      // Fail closed on any uncaught error
      return buildDenyResult(
        "pg.gateway.error",
        "Internal gateway error — failing closed",
      );
    }
  }

  return { authorize };
}
