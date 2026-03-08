import { z } from "zod";
import { DataClassSchema } from "../data-model/index.js";
import { TokenValidationError } from "./errors.js";

// --- Memory Tier ---

export const MemoryTierSchema = z.enum(["ephemeral", "session", "durable"]);

export type MemoryTier = z.infer<typeof MemoryTierSchema>;

export const MEMORY_TIER_ORDER: Record<MemoryTier, number> = {
  ephemeral: 0,
  session: 1,
  durable: 2,
} as const;

// --- Approval State ---

export const ApprovalStateSchema = z.enum([
  "not_required",
  "pending",
  "approved",
  "denied",
]);

export type ApprovalState = z.infer<typeof ApprovalStateSchema>;

// --- Capability Token ---

export const CapabilityTokenSchema = z.object({
  token_id: z.uuid(),
  agent_id: z.string().min(1),
  task_id: z.string().min(1),
  purpose_tags: z.array(z.string().min(1)).min(1),
  working_set_hash: z.string().min(1),
  allowed_tools: z.array(z.string().min(1)).default([]),
  max_data_class: DataClassSchema,
  allowed_destinations: z.array(z.string().min(1)).default([]),
  memory_tier: MemoryTierSchema,
  approval_state: ApprovalStateSchema,
  ttl: z.number().int().positive(),
  issued_at: z.iso.datetime(),
  expires_at: z.iso.datetime(),
  signature: z.string().min(1),
  revoked: z.boolean(),
  source_decision_id: z.uuid(),
});

export type CapabilityToken = Readonly<z.infer<typeof CapabilityTokenSchema>>;

// --- Mint Token Request ---

export const MintTokenRequestSchema = z.object({
  agent_id: z.string().min(1),
  task_id: z.string().min(1),
  purpose_tags: z.array(z.string().min(1)).min(1),
  working_set_hash: z.string().min(1),
  allowed_tools: z.array(z.string().min(1)).default([]),
  max_data_class: DataClassSchema,
  allowed_destinations: z.array(z.string().min(1)).default([]),
  memory_tier: MemoryTierSchema.default("ephemeral"),
  approval_state: ApprovalStateSchema.default("not_required"),
  ttl: z.number().int().positive().default(300),
});

export type MintTokenRequest = Readonly<z.infer<typeof MintTokenRequestSchema>>;

// --- Token Validation Result ---

export const TokenFailureReasonSchema = z.enum([
  "expired",
  "revoked",
  "invalid_signature",
  "validation_error",
]);

export type TokenFailureReason = z.infer<typeof TokenFailureReasonSchema>;

export const TokenValidationResultSchema = z.object({
  valid: z.boolean(),
  token_id: z.string().optional(),
  failure_reason: TokenFailureReasonSchema.optional(),
  failure_message: z.string().optional(),
});

export type TokenValidationResult = Readonly<z.infer<typeof TokenValidationResultSchema>>;

// --- Scope Check ---

export const ScopeCheckRequestSchema = z.object({
  tool: z.string().min(1).optional(),
  destination: z.string().min(1).optional(),
  data_class: DataClassSchema.optional(),
  memory_tier: MemoryTierSchema.optional(),
});

export type ScopeCheckRequest = Readonly<z.infer<typeof ScopeCheckRequestSchema>>;

export const ScopeCheckResultSchema = z.object({
  allowed: z.boolean(),
  denial_reasons: z.array(z.string()),
});

export type ScopeCheckResult = Readonly<z.infer<typeof ScopeCheckResultSchema>>;

// --- Parse functions ---

export function parseCapabilityToken(data: unknown): CapabilityToken {
  const result = CapabilityTokenSchema.safeParse(data);
  if (!result.success) {
    throw new TokenValidationError(result.error.issues);
  }
  return Object.freeze(result.data) as CapabilityToken;
}

export function parseMintTokenRequest(data: unknown): MintTokenRequest {
  const result = MintTokenRequestSchema.safeParse(data);
  if (!result.success) {
    throw new TokenValidationError(result.error.issues);
  }
  return Object.freeze(result.data) as MintTokenRequest;
}
