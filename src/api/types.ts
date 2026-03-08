import { z } from "zod";
import { DataClassSchema } from "../data-model/data-class.js";
import {
  SourceTrustSchema,
  RetentionClassSchema,
  SourceTypeSchema,
} from "../data-model/envelope.js";
import { PolicyEffectSchema } from "../pdp/types.js";
import { ApiValidationError } from "./errors.js";

// --- Shared schemas ---

export const ConfidenceLevelSchema = z.enum(["low", "medium", "high"]);
export type ConfidenceLevel = z.infer<typeof ConfidenceLevelSchema>;

export const MemoryTierSchema = z.enum(["ephemeral", "session", "durable"]);
export type MemoryTier = z.infer<typeof MemoryTierSchema>;

// --- Ingress Evaluate ---

export const IngressInputSchema = z.object({
  content: z.string().min(1),
  source_type: SourceTypeSchema,
  source_trust: SourceTrustSchema,
  metadata: z.record(z.string(), z.unknown()).optional(),
});
export type IngressInput = Readonly<z.infer<typeof IngressInputSchema>>;

export const IngressEvaluateRequestSchema = z.object({
  input: IngressInputSchema,
  actor_id: z.string().min(1),
  agent_id: z.string().min(1),
  purpose: z.string().min(1),
  task_id: z.string().min(1),
});
export type IngressEvaluateRequest = Readonly<
  z.infer<typeof IngressEvaluateRequestSchema>
>;

export const DetectedClassSummarySchema = z.object({
  data_class: DataClassSchema,
  confidence: ConfidenceLevelSchema,
  entity_count: z.number().int().nonnegative(),
});
export type DetectedClassSummary = Readonly<z.infer<typeof DetectedClassSummarySchema>>;

export const IngressEvaluateResponseSchema = z.object({
  decision_id: z.uuid(),
  effect: PolicyEffectSchema,
  policy_id: z.string().min(1),
  explanation: z.string().min(1),
  detected: z.array(DetectedClassSummarySchema),
  working_set_ref: z.string().min(1),
});
export type IngressEvaluateResponse = Readonly<
  z.infer<typeof IngressEvaluateResponseSchema>
>;

// --- Tool Authorize ---

export const ToolDescriptorSchema = z.object({
  name: z.string().min(1),
  action: z.string().min(1),
  parameters: z.record(z.string(), z.unknown()).optional(),
});
export type ToolDescriptor = Readonly<z.infer<typeof ToolDescriptorSchema>>;

export const ToolAuthorizeRequestSchema = z.object({
  tool: ToolDescriptorSchema,
  capability_token: z.string().min(1),
  agent_id: z.string().min(1),
  task_id: z.string().min(1),
  requested_destination: z.string().optional(),
  data_sensitivity: z.array(DataClassSchema).optional(),
});
export type ToolAuthorizeRequest = Readonly<z.infer<typeof ToolAuthorizeRequestSchema>>;

export const ToolAuthorizeResponseSchema = z.object({
  decision_id: z.uuid(),
  effect: PolicyEffectSchema,
  policy_id: z.string().min(1),
  explanation: z.string().min(1),
  reasons: z.array(z.string()),
  approval_prompt_ref: z.string().optional(),
});
export type ToolAuthorizeResponse = Readonly<z.infer<typeof ToolAuthorizeResponseSchema>>;

// --- Memory Write ---

export const MemoryEntrySchema = z.object({
  key: z.string().min(1),
  value: z.string(),
  source_trust: SourceTrustSchema,
  sensitivity: z.array(DataClassSchema).default([]),
});
export type MemoryEntry = Readonly<z.infer<typeof MemoryEntrySchema>>;

export const MemoryWriteRequestSchema = z.object({
  entry: MemoryEntrySchema,
  memory_tier: MemoryTierSchema,
  agent_id: z.string().min(1),
  task_id: z.string().min(1),
  ttl_seconds: z.number().int().positive().optional(),
});
export type MemoryWriteRequest = Readonly<z.infer<typeof MemoryWriteRequestSchema>>;

export const MemoryWriteResponseSchema = z.object({
  decision_id: z.uuid(),
  effect: PolicyEffectSchema,
  policy_id: z.string().min(1),
  explanation: z.string().min(1),
  entry_id: z.uuid(),
  effective_tier: RetentionClassSchema,
  effective_ttl: z.number().int().positive().optional(),
});
export type MemoryWriteResponse = Readonly<z.infer<typeof MemoryWriteResponseSchema>>;

// --- Decision Explain ---

export const DecisionExplainRequestSchema = z.object({
  decision_id: z.uuid(),
});
export type DecisionExplainRequest = Readonly<
  z.infer<typeof DecisionExplainRequestSchema>
>;

export const DecisionExplainResponseSchema = z.object({
  decision_id: z.uuid(),
  decision: PolicyEffectSchema,
  policy_id: z.string().min(1),
  matched_rules: z.array(z.string()).min(1),
  explanation: z.string().min(1),
});
export type DecisionExplainResponse = Readonly<
  z.infer<typeof DecisionExplainResponseSchema>
>;

// --- Parse functions ---

export function parseIngressEvaluateRequest(data: unknown): IngressEvaluateRequest {
  const result = IngressEvaluateRequestSchema.safeParse(data);
  if (!result.success) {
    throw new ApiValidationError(result.error.issues);
  }
  return Object.freeze(result.data) as IngressEvaluateRequest;
}

export function parseToolAuthorizeRequest(data: unknown): ToolAuthorizeRequest {
  const result = ToolAuthorizeRequestSchema.safeParse(data);
  if (!result.success) {
    throw new ApiValidationError(result.error.issues);
  }
  return Object.freeze(result.data) as ToolAuthorizeRequest;
}

export function parseMemoryWriteRequest(data: unknown): MemoryWriteRequest {
  const result = MemoryWriteRequestSchema.safeParse(data);
  if (!result.success) {
    throw new ApiValidationError(result.error.issues);
  }
  return Object.freeze(result.data) as MemoryWriteRequest;
}

export function parseDecisionExplainRequest(data: unknown): DecisionExplainRequest {
  const result = DecisionExplainRequestSchema.safeParse(data);
  if (!result.success) {
    throw new ApiValidationError(result.error.issues);
  }
  return Object.freeze(result.data) as DecisionExplainRequest;
}
