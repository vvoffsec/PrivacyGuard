import { z } from "zod";
import { DataClassSchema } from "./data-class.js";
import { DetectedEntitySchema } from "./entity.js";
import { EnvelopeConsistencyError, EnvelopeValidationError } from "./errors.js";

export const SourceTypeSchema = z.enum([
  "user_input",
  "local_file",
  "web_content",
  "email_content",
  "tool_output",
  "memory_content",
  "generated",
]);

export const SourceTrustSchema = z.enum([
  "trusted_user",
  "trusted_local",
  "untrusted_external",
  "generated_unverified",
]);

export const RetentionClassSchema = z.enum([
  "ephemeral",
  "session",
  "durable",
  "quarantined",
]);

export const DestinationSchema = z.enum(["local_only", "approved_remote", "any_remote"]);

export const PurposeTagSchema = z.enum([
  "user_request",
  "agent_task",
  "audit",
  "debug",
  "analytics",
]);

export const TaintFlagSchema = z.enum([
  "contains_pii",
  "contains_secret",
  "untrusted_instruction",
  "prompt_injection_suspected",
]);

const ContentEnvelopeBaseSchema = z.object({
  content_id: z.uuid(),
  source_type: SourceTypeSchema,
  source_trust: SourceTrustSchema,
  retention_class: RetentionClassSchema,
  sensitivity: z.array(DataClassSchema).min(1).default(["public"]),
  entities: z.array(DetectedEntitySchema).default([]),
  allowed_destinations: z.array(DestinationSchema).min(1),
  purpose_tags: z.array(PurposeTagSchema).default([]),
  taint_flags: z.array(TaintFlagSchema).default([]),
  provenance_ref: z.url().optional(),
  created_at: z.iso.datetime(),
});

export const ContentEnvelopeSchema = ContentEnvelopeBaseSchema.superRefine(
  (data, ctx) => {
    const hasSensitivity = (cls: string) => data.sensitivity.includes(cls as never);
    const hasTaint = (flag: string) => data.taint_flags.includes(flag as never);

    // 1. secret/credential in sensitivity → contains_secret must be in taint_flags
    if (
      (hasSensitivity("secret") || hasSensitivity("credential")) &&
      !hasTaint("contains_secret")
    ) {
      ctx.addIssue({
        code: "custom",
        message:
          "sensitivity includes secret/credential but taint_flags is missing contains_secret",
        path: ["taint_flags"],
      });
    }

    // 2. pii in sensitivity → contains_pii must be in taint_flags
    if (hasSensitivity("pii") && !hasTaint("contains_pii")) {
      ctx.addIssue({
        code: "custom",
        message: "sensitivity includes pii but taint_flags is missing contains_pii",
        path: ["taint_flags"],
      });
    }

    // 3. untrusted_external + durable retention → rejected
    if (
      data.source_trust === "untrusted_external" &&
      data.retention_class === "durable"
    ) {
      ctx.addIssue({
        code: "custom",
        message:
          "untrusted_external content cannot have durable retention (must be ephemeral or quarantined)",
        path: ["retention_class"],
      });
    }
  },
);

export type ContentEnvelope = Readonly<z.infer<typeof ContentEnvelopeBaseSchema>>;

/**
 * Parse and validate raw data into a ContentEnvelope.
 * Throws EnvelopeValidationError or EnvelopeConsistencyError on failure.
 */
export function parseEnvelope(data: unknown): ContentEnvelope {
  const result = ContentEnvelopeSchema.safeParse(data);
  if (!result.success) {
    const issues = result.error.issues;
    const hasConsistencyIssue = issues.some((i) => i.code === "custom");
    if (hasConsistencyIssue) {
      throw new EnvelopeConsistencyError(issues);
    }
    throw new EnvelopeValidationError(issues);
  }
  return Object.freeze(result.data) as ContentEnvelope;
}

/** Fields that can be patched via updateEnvelope. content_id is excluded. */
type PatchableFields = Partial<Omit<ContentEnvelope, "content_id">>;

/**
 * Returns a new validated ContentEnvelope with the patch applied.
 * content_id cannot be changed.
 */
export function updateEnvelope(
  existing: ContentEnvelope,
  patch: PatchableFields,
): ContentEnvelope {
  const merged = { ...existing, ...patch, content_id: existing.content_id };
  return parseEnvelope(merged);
}
