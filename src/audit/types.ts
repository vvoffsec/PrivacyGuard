import { z } from "zod";
import { DataClassSchema } from "../data-model/data-class.js";
import { SourceTrustSchema } from "../data-model/envelope.js";
import { PolicyEffectSchema } from "../pdp/types.js";
import { AuditConsistencyError, AuditValidationError } from "./errors.js";

// --- Shared schemas ---

export const EventTypeSchema = z.enum([
  "decision",
  "approval",
  "tool",
  "memory",
  "egress",
  "integrity",
]);

export type EventType = z.infer<typeof EventTypeSchema>;

const Sha256HashSchema = z.string().regex(/^sha256:[0-9a-f]{64}$/);

const AuditEventBaseSchema = z.object({
  event_id: z.uuid(),
  event_type: EventTypeSchema,
  timestamp: z.iso.datetime(),
  correlation_id: z.uuid().optional(),
});

// --- 6 Event Schemas ---

export const DecisionEventSchema = AuditEventBaseSchema.extend({
  event_type: z.literal("decision"),
  decision_id: z.uuid(),
  actor_id: z.string().min(1),
  agent_id: z.string().min(1),
  policy_id: z.string().min(1),
  action: z.string().min(1),
  result: PolicyEffectSchema,
  explanation: z.string().min(1),
  matched_rules: z.array(z.string().min(1)).min(1),
  input_hashes: z.array(Sha256HashSchema).default([]),
});

export type DecisionEvent = Readonly<z.infer<typeof DecisionEventSchema>>;

export const ApprovalStatusSchema = z.enum(["granted", "denied", "expired", "revoked"]);

export const ApprovalEventSchema = AuditEventBaseSchema.extend({
  event_type: z.literal("approval"),
  approval_id: z.uuid(),
  actor_id: z.string().min(1),
  decision_id: z.uuid(),
  scope_hash: Sha256HashSchema,
  reason: z.string().min(1),
  expires_at: z.iso.datetime().optional(),
  status: ApprovalStatusSchema,
});

export type ApprovalEvent = Readonly<z.infer<typeof ApprovalEventSchema>>;

export const ToolResultSchema = z.enum(["allowed", "denied", "error"]);

export const ToolEventSchema = AuditEventBaseSchema.extend({
  event_type: z.literal("tool"),
  request_id: z.uuid(),
  tool_name: z.string().min(1),
  args_hash: Sha256HashSchema,
  destination: z.string().min(1),
  result: ToolResultSchema,
  capability_id: z.uuid(),
});

export type ToolEvent = Readonly<z.infer<typeof ToolEventSchema>>;

export const MemoryTierSchema = z.enum(["ephemeral", "quarantined", "trusted"]);
export const MemoryActionSchema = z.enum([
  "write",
  "promote",
  "quarantine",
  "delete",
  "expire",
]);

export const MemoryEventSchema = AuditEventBaseSchema.extend({
  event_type: z.literal("memory"),
  entry_id: z.uuid(),
  tier: MemoryTierSchema,
  source_trust: SourceTrustSchema,
  sensitivity: z.array(DataClassSchema).min(1),
  ttl: z.number().int().positive().optional(),
  action: MemoryActionSchema,
});

export type MemoryEvent = Readonly<z.infer<typeof MemoryEventSchema>>;

export const EgressTransformSchema = z.enum([
  "none",
  "mask",
  "tokenize",
  "redact",
  "hash",
]);

export const EgressEventSchema = AuditEventBaseSchema.extend({
  event_type: z.literal("egress"),
  egress_id: z.uuid(),
  destination: z.string().min(1),
  classes_detected: z.array(DataClassSchema).default([]),
  transform_applied: EgressTransformSchema,
  bytes_sent: z.number().int().nonnegative(),
  blocked: z.boolean(),
});

export type EgressEvent = Readonly<z.infer<typeof EgressEventSchema>>;

export const SignatureStatusSchema = z.enum(["valid", "invalid", "missing", "expired"]);

export const IntegrityEventSchema = AuditEventBaseSchema.extend({
  event_type: z.literal("integrity"),
  artifact_id: z.string().min(1),
  provenance_ref: z.url().optional(),
  signature_status: SignatureStatusSchema,
  bundle_version: z.string().min(1),
});

export type IntegrityEvent = Readonly<z.infer<typeof IntegrityEventSchema>>;

// --- Discriminated union ---

export const AuditEventSchema = z.discriminatedUnion("event_type", [
  DecisionEventSchema,
  ApprovalEventSchema,
  ToolEventSchema,
  MemoryEventSchema,
  EgressEventSchema,
  IntegrityEventSchema,
]);

export type AuditEvent = Readonly<z.infer<typeof AuditEventSchema>>;

// --- Parse function ---

export function parseAuditEvent(data: unknown): AuditEvent {
  const result = AuditEventSchema.safeParse(data);
  if (!result.success) {
    const issues = result.error.issues;
    const hasConsistencyIssue = issues.some((i) => i.code === "custom");
    if (hasConsistencyIssue) {
      throw new AuditConsistencyError(issues);
    }
    throw new AuditValidationError(issues);
  }
  return Object.freeze(result.data) as AuditEvent;
}
