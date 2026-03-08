import { z } from "zod";
import { PolicyValidationError } from "./errors.js";

// --- Sub-schemas ---

export const PrincipalSchema = z.object({
  type: z.enum(["agent", "user", "system"]),
  id: z.string().min(1),
});

export const RequestSchema = z.object({
  action: z.string().min(1),
  purpose: z.array(z.string()).default([]),
  task_id: z.string().min(1),
});

export const ResourceSchema = z.object({
  type: z.string().min(1),
  name: z.string().min(1),
});

export const DataContextSchema = z.object({
  source_trust: z.array(z.string()).default([]),
  sensitivity: z.array(z.string()).default([]),
  taint_flags: z.array(z.string()).default([]),
});

export const DestinationContextSchema = z.object({
  kind: z.string().min(1),
  name: z.string().min(1),
});

export const EnvironmentSchema = z.object({
  host_class: z.string().min(1),
  policy_bundle: z.string().min(1),
});

export const PolicyInputSchema = z.object({
  principal: PrincipalSchema,
  request: RequestSchema,
  resource: ResourceSchema,
  data: DataContextSchema,
  destination: DestinationContextSchema,
  environment: EnvironmentSchema,
});

export type PolicyInput = Readonly<z.infer<typeof PolicyInputSchema>>;

// --- PolicyEffect ---

export const PolicyEffectSchema = z.enum([
  "allow",
  "allow_with_minimization",
  "require_approval",
  "quarantine",
  "deny",
]);

export type PolicyEffect = z.infer<typeof PolicyEffectSchema>;

export const EFFECT_SEVERITY: Record<PolicyEffect, number> = {
  allow: 0,
  allow_with_minimization: 1,
  require_approval: 2,
  quarantine: 3,
  deny: 4,
} as const;

export function mostRestrictiveEffect(effects: PolicyEffect[]): PolicyEffect {
  if (effects.length === 0) {
    return "allow";
  }
  let highest: PolicyEffect = effects[0];
  for (const effect of effects) {
    if (EFFECT_SEVERITY[effect] > EFFECT_SEVERITY[highest]) {
      highest = effect;
    }
  }
  return highest;
}

// --- RequiredAction ---

export const RequiredActionSchema = z.object({
  type: z.string().min(1),
  reason: z.string().min(1),
  scope_hash: z.string().optional(),
});

export type RequiredAction = z.infer<typeof RequiredActionSchema>;

// --- PolicyDecision ---

export const PolicyDecisionSchema = z.object({
  decision: PolicyEffectSchema,
  decision_id: z.uuid(),
  policy_id: z.string().min(1),
  matched_rules: z.array(z.string()).min(1),
  explanation: z.string().min(1),
  required_actions: z.array(RequiredActionSchema).optional(),
  policy_bundle_version: z.string().min(1),
});

export type PolicyDecision = Readonly<z.infer<typeof PolicyDecisionSchema>>;

// --- Parse functions ---

export function parsePolicyInput(data: unknown): PolicyInput {
  const result = PolicyInputSchema.safeParse(data);
  if (!result.success) {
    throw new PolicyValidationError(result.error.issues);
  }
  return Object.freeze(result.data) as PolicyInput;
}

export function parsePolicyDecision(data: unknown): PolicyDecision {
  const result = PolicyDecisionSchema.safeParse(data);
  if (!result.success) {
    throw new PolicyValidationError(result.error.issues);
  }
  return Object.freeze(result.data) as PolicyDecision;
}
