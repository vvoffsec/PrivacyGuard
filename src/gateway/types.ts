import { z } from "zod";
import { PolicyEffectSchema } from "../pdp/types.js";
import type { PolicyEffect } from "../pdp/types.js";
import type { PDP } from "../pdp/pdp.js";
import type { CapabilityTokenValidator } from "../api/interfaces.js";

// --- Enums ---

export const ToolRiskLevelSchema = z.enum(["low", "medium", "high", "critical"]);
export type ToolRiskLevel = z.infer<typeof ToolRiskLevelSchema>;

export const ToolCategoryNameSchema = z.enum([
  "exec",
  "fs_write",
  "fs_read",
  "browser",
  "send",
  "package",
  "config",
]);
export type ToolCategoryName = z.infer<typeof ToolCategoryNameSchema>;

export const DefaultPostureSchema = z.enum(["allow", "require_approval", "deny"]);
export type DefaultPosture = z.infer<typeof DefaultPostureSchema>;

// --- Tool Category ---

export const ToolCategorySchema = z.object({
  name: ToolCategoryNameSchema,
  risk_level: ToolRiskLevelSchema,
  default_posture: DefaultPostureSchema,
  description: z.string().min(1),
});
export type ToolCategory = Readonly<z.infer<typeof ToolCategorySchema>>;

// --- Sanitization ---

export const SanitizationFindingSchema = z.object({
  pattern_name: z.string().min(1),
  severity: ToolRiskLevelSchema,
  matched_value: z.string().max(100),
  description: z.string().min(1),
});
export type SanitizationFinding = Readonly<z.infer<typeof SanitizationFindingSchema>>;

export const SanitizationResultSchema = z.object({
  safe: z.boolean(),
  findings: z.array(SanitizationFindingSchema),
});
export type SanitizationResult = Readonly<z.infer<typeof SanitizationResultSchema>>;

// --- Argument Validation ---

export const ArgumentValidationResultSchema = z.object({
  valid: z.boolean(),
  errors: z.array(z.string()),
});
export type ArgumentValidationResult = Readonly<
  z.infer<typeof ArgumentValidationResultSchema>
>;

// --- Gateway Request ---

export const ToolGatewayRequestSchema = z.object({
  tool_name: z.string().min(1),
  tool_action: z.string().min(1),
  tool_parameters: z.record(z.string(), z.unknown()).optional(),
  agent_id: z.string().min(1),
  task_id: z.string().min(1),
  capability_token_raw: z.string().min(1),
  data_sensitivity: z.array(z.string()).optional(),
  requested_destination: z.string().optional(),
  taint_flags: z.array(z.string()).optional(),
});
export type ToolGatewayRequest = Readonly<z.infer<typeof ToolGatewayRequestSchema>>;

// --- Gateway Result ---

export const ToolGatewayResultSchema = z.object({
  decision: PolicyEffectSchema,
  decision_id: z.uuid(),
  policy_id: z.string().min(1),
  explanation: z.string().min(1),
  matched_rules: z.array(z.string()),
  category: ToolCategorySchema.optional(),
  sanitization: SanitizationResultSchema.optional(),
  argument_validation: ArgumentValidationResultSchema.optional(),
  approval_prompt_ref: z.string().optional(),
});
export type ToolGatewayResult = Readonly<z.infer<typeof ToolGatewayResultSchema>>;

// --- Interfaces ---

export interface ToolCategoryClassifier {
  classify(toolName: string): ToolCategory | undefined;
  registerMapping(toolName: string, categoryName: ToolCategoryName): void;
}

export interface ArgumentValidator {
  validate(
    categoryName: ToolCategoryName,
    parameters: Record<string, unknown>,
  ): ArgumentValidationResult;
}

export interface ArgumentSanitizer {
  sanitize(
    categoryName: ToolCategoryName,
    parameters: Record<string, unknown>,
  ): SanitizationResult;
}

export interface ToolGateway {
  authorize(request: ToolGatewayRequest): ToolGatewayResult;
}

export interface ToolGatewayConfig {
  readonly pdp: PDP;
  readonly tokenValidator: CapabilityTokenValidator;
  readonly categoryClassifier: ToolCategoryClassifier;
  readonly argumentValidator: ArgumentValidator;
  readonly argumentSanitizer: ArgumentSanitizer;
}

// --- Parse helpers ---

export function parseToolGatewayRequest(data: unknown): ToolGatewayRequest {
  const result = ToolGatewayRequestSchema.safeParse(data);
  if (!result.success) {
    const messages = result.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`);
    throw new Error(`Invalid ToolGatewayRequest: ${messages.join("; ")}`);
  }
  return Object.freeze(result.data) as ToolGatewayRequest;
}

// --- Utility: map DefaultPosture to PolicyEffect ---

export function postureToEffect(posture: DefaultPosture): PolicyEffect {
  return posture as PolicyEffect;
}
