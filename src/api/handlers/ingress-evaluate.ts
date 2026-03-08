import type { PDP } from "../../pdp/pdp.js";
import type { AuditEmitter, DecisionStore } from "../interfaces.js";
import type { ApiResult } from "../result.js";
import { apiSuccess, apiError } from "../result.js";
import { ApiValidationError } from "../errors.js";
import {
  parseIngressEvaluateRequest,
  type IngressEvaluateResponse,
  type DetectedClassSummary,
  type ConfidenceLevel,
} from "../types.js";
import type { ApiHandler } from "../transport.js";
import type { IngressPipeline } from "../../ingress/types.js";
import type { DataClass } from "../../data-model/data-class.js";

export interface IngressEvaluateConfig {
  readonly pdp: PDP;
  readonly decisionStore: DecisionStore;
  readonly auditEmitter: AuditEmitter;
  readonly pipeline?: IngressPipeline;
}

function toConfidenceLevel(confidence: number): ConfidenceLevel {
  if (confidence >= 0.8) return "high";
  if (confidence >= 0.5) return "medium";
  return "low";
}

function buildDetectedSummaries(
  entities: readonly {
    type: string;
    confidence: number;
  }[],
  dataClasses: DataClass[],
): DetectedClassSummary[] {
  if (dataClasses.length === 0) return [];

  // Map entity types to data classes (from sensitivity engine results)
  const classMap = new Map<DataClass, { count: number; maxConfidence: number }>();

  // Use data classes from sensitivity result
  for (const dc of dataClasses) {
    if (!classMap.has(dc)) {
      classMap.set(dc, { count: 0, maxConfidence: 0 });
    }
  }

  // Count entities per data class by type mapping
  for (const entity of entities) {
    // Determine data class from entity type
    const dc = entityTypeToDataClass(entity.type);
    const entry = classMap.get(dc);
    if (entry) {
      entry.count++;
      entry.maxConfidence = Math.max(entry.maxConfidence, entity.confidence);
    } else {
      classMap.set(dc, { count: 1, maxConfidence: entity.confidence });
    }
  }

  const summaries: DetectedClassSummary[] = [];
  for (const [data_class, { count, maxConfidence }] of classMap) {
    summaries.push({
      data_class,
      confidence: toConfidenceLevel(maxConfidence),
      entity_count: count,
    });
  }
  return summaries;
}

function entityTypeToDataClass(type: string): DataClass {
  switch (type) {
    case "email":
    case "phone":
    case "ssn":
    case "credit_card":
      return "pii";
    case "api_key":
    case "high_entropy_string":
      return "secret";
    case "aws_access_key":
      return "credential";
    case "ipv4":
      return "internal";
    default:
      return "public";
  }
}

export function createIngressEvaluateHandler(config: IngressEvaluateConfig): ApiHandler {
  const { pdp, decisionStore, auditEmitter, pipeline } = config;

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

    // When there is a pipeline, run it and use enriched data
    if (pipeline) {
      let pipelineResult;
      try {
        pipelineResult = pipeline.evaluate(
          {
            content: req.input.content,
            source_type: req.input.source_type,
            source_trust: req.input.source_trust,
            metadata: req.input.metadata,
          },
          {
            actor_id: req.actor_id,
            agent_id: req.agent_id,
            purpose: req.purpose,
            task_id: req.task_id,
          },
        );
      } catch {
        // Pipeline failure should auto-deny
        return apiError(
          "PIPELINE_ERROR",
          "Ingress pipeline failed — content denied (fail closed)",
        );
      }

      // Override policy input with pipeline-enriched data
      const policyInput = {
        ...pipelineResult.policy_input,
        principal: { type: "agent" as const, id: req.agent_id },
        request: {
          action: "ingress.evaluate",
          purpose: [req.purpose],
          task_id: req.task_id,
        },
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
        extra: {
          content_hash: pipelineResult.parsed.content_hash,
          injection_detected: pipelineResult.injection.detected,
          injection_confidence: pipelineResult.injection.confidence,
          entity_count: pipelineResult.sensitivity.entities.length,
        },
      });

      const detected = buildDetectedSummaries(
        pipelineResult.sensitivity.entities,
        pipelineResult.sensitivity.data_classes,
      );

      const response: IngressEvaluateResponse = {
        decision_id: decision.decision_id,
        effect: decision.decision,
        policy_id: decision.policy_id,
        explanation: decision.explanation,
        detected,
        working_set_ref: `ws_${decision.decision_id}`,
      };

      return apiSuccess(response);
    }

    // Phase 0 fallback if no pipeline
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
