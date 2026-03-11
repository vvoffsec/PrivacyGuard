import { z } from "zod";
import { DataClassSchema } from "../data-model/data-class.js";
import { ApprovalStatusSchema } from "../audit/types.js";
import type { ApprovalEvent } from "../audit/types.js";
import type { AuditEmitter } from "../audit/emitter.js";
import type { PolicyDecision, PolicyInput } from "../pdp/types.js";

// Re-export for convenience
export type { ApprovalEvent, AuditEmitter, PolicyDecision, PolicyInput };
export { ApprovalStatusSchema };
export type ApprovalStatus = z.infer<typeof ApprovalStatusSchema>;

// Approval Scope

export const ApprovalScopeSchema = z.object({
  action: z.string().min(1),
  purpose: z.array(z.string().min(1)).default([]),
  destination: z.string().min(1),
  data_class: DataClassSchema,
});

export type ApprovalScope = Readonly<z.infer<typeof ApprovalScopeSchema>>;

// Approval Record

export const ApprovalRecordSchema = z.object({
  approval_id: z.uuid(),
  decision_id: z.uuid(),
  actor_id: z.string().min(1),
  scope: ApprovalScopeSchema,
  scope_hash: z.string().regex(/^sha256:[0-9a-f]{64}$/),
  reason: z.string().min(1),
  status: ApprovalStatusSchema,
  created_at: z.iso.datetime(),
  expires_at: z.iso.datetime().optional(),
});

export type ApprovalRecord = Readonly<z.infer<typeof ApprovalRecordSchema>>;

// Approval Prompt

export const ApprovalPromptSchema = z.object({
  prompt_id: z.string().min(1),
  decision_id: z.uuid(),
  action: z.string().min(1),
  data_classes: z.array(DataClassSchema).default([]),
  destination: z.string().min(1),
  destination_kind: z.string().min(1),
  reasons: z.array(z.string().min(1)).default([]),
  explanation: z.string().min(1),
  policy_id: z.string().min(1),
  scope_hash: z.string().regex(/^sha256:[0-9a-f]{64}$/),
});

export type ApprovalPrompt = Readonly<z.infer<typeof ApprovalPromptSchema>>;

// Approval Response

export const ApprovalResponseSchema = z.object({
  approved: z.boolean(),
  actor_id: z.string().min(1),
  reason: z.string().min(1),
  expires_in_seconds: z.number().int().positive().optional(),
});

export type ApprovalResponse = Readonly<z.infer<typeof ApprovalResponseSchema>>;

// Approval Orchestrator Result

export const ApprovalOrchestratorResultSchema = z.object({
  approved: z.boolean(),
  approval_id: z.uuid().optional(),
  prompt_shown: z.boolean(),
  scope_hash: z.string().regex(/^sha256:[0-9a-f]{64}$/),
  reason: z.string().min(1),
  expires_at: z.iso.datetime().optional(),
});

export type ApprovalOrchestratorResult = Readonly<
  z.infer<typeof ApprovalOrchestratorResultSchema>
>;

// Interfaces

export interface ApprovalUxAdapter {
  requestApproval(prompt: ApprovalPrompt): ApprovalResponse;
}

export interface ApprovalStore {
  put(record: ApprovalRecord): void;
  findByScope(scopeHash: string): ApprovalRecord | undefined;
  revoke(approvalId: string): boolean;
  count(): number;
}

export interface ApprovalOrchestrator {
  evaluate(decision: PolicyDecision, input: PolicyInput): ApprovalOrchestratorResult;
}

export interface ApprovalOrchestratorConfig {
  store: ApprovalStore;
  uxAdapter: ApprovalUxAdapter;
  auditEmitter: AuditEmitter;
  defaultTtlSeconds?: number;
}

// Parse helpers

export function parseApprovalRecord(data: unknown): ApprovalRecord {
  const result = ApprovalRecordSchema.safeParse(data);
  if (!result.success) {
    const messages = result.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`);
    throw new Error(`Invalid ApprovalRecord: ${messages.join("; ")}`);
  }
  return Object.freeze(result.data) as ApprovalRecord;
}

export function parseApprovalPrompt(data: unknown): ApprovalPrompt {
  const result = ApprovalPromptSchema.safeParse(data);
  if (!result.success) {
    const messages = result.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`);
    throw new Error(`Invalid ApprovalPrompt: ${messages.join("; ")}`);
  }
  return Object.freeze(result.data) as ApprovalPrompt;
}

export function parseApprovalResponse(data: unknown): ApprovalResponse {
  const result = ApprovalResponseSchema.safeParse(data);
  if (!result.success) {
    const messages = result.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`);
    throw new Error(`Invalid ApprovalResponse: ${messages.join("; ")}`);
  }
  return Object.freeze(result.data) as ApprovalResponse;
}
