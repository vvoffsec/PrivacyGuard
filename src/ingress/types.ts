import { z } from "zod";
import {
  SourceTypeSchema,
  SourceTrustSchema,
  TaintFlagSchema,
  RetentionClassSchema,
} from "../data-model/envelope.js";
import type { ContentEnvelope } from "../data-model/envelope.js";
import type { PolicyInput } from "../pdp/types.js";

// Re-export sensitivity types from the standalone module
export type {
  SensitivityResult,
  SensitivityEngine,
  PatternRecognizer,
} from "../sensitivity/types.js";

export { SensitivityResultSchema } from "../sensitivity/types.js";

// --- Content Format ---

export const ContentFormatSchema = z.enum([
  "text/plain",
  "text/markdown",
  "text/html",
  "application/json",
  "file/metadata",
]);
export type ContentFormat = z.infer<typeof ContentFormatSchema>;

// --- Parsed Content ---

export const ParsedContentSchema = z.object({
  format: ContentFormatSchema,
  normalized_text: z.string(),
  content_hash: z.string().regex(/^sha256:[0-9a-f]{64}$/),
  byte_length: z.number().int().nonnegative(),
  metadata: z.record(z.string(), z.unknown()).optional(),
});
export type ParsedContent = Readonly<z.infer<typeof ParsedContentSchema>>;

// --- Trust Classification ---

export const TrustClassificationSchema = z.object({
  source_trust: SourceTrustSchema,
  default_taint_flags: z.array(TaintFlagSchema),
  retention_class: RetentionClassSchema,
});
export type TrustClassification = Readonly<z.infer<typeof TrustClassificationSchema>>;

// --- Injection Check Result ---

export const InjectionCheckResultSchema = z.object({
  detected: z.boolean(),
  confidence: z.number().min(0).max(1),
  matched_patterns: z.array(z.string()),
  taint_flags: z.array(TaintFlagSchema),
});
export type InjectionCheckResult = Readonly<z.infer<typeof InjectionCheckResultSchema>>;

// --- Ingress Pipeline Result ---

export interface IngressPipelineResult {
  readonly envelope: ContentEnvelope;
  readonly policy_input: PolicyInput;
  readonly parsed: ParsedContent;
  readonly sensitivity: import("../sensitivity/types.js").SensitivityResult;
  readonly injection: InjectionCheckResult;
}

// --- Stage Interfaces ---

export interface ContentParser {
  parse(content: string, metadata?: Record<string, unknown>): ParsedContent;
}

export interface TrustClassifier {
  classify(
    source_type: z.infer<typeof SourceTypeSchema>,
    source_trust?: z.infer<typeof SourceTrustSchema>,
  ): TrustClassification;
}

export interface InjectionDetector {
  check(
    content: string,
    source_trust: z.infer<typeof SourceTrustSchema>,
  ): InjectionCheckResult;
}

export interface InjectionPattern {
  readonly name: string;
  readonly pattern: RegExp;
  readonly confidence: number;
  readonly description: string;
}

export interface EnvelopeAssembler {
  assemble(input: EnvelopeAssemblerInput): {
    envelope: ContentEnvelope;
    policy_input: PolicyInput;
  };
}

export interface EnvelopeAssemblerInput {
  readonly content: string;
  readonly source_type: z.infer<typeof SourceTypeSchema>;
  readonly parsed: ParsedContent;
  readonly trust: TrustClassification;
  readonly sensitivity: import("../sensitivity/types.js").SensitivityResult;
  readonly injection: InjectionCheckResult;
  readonly metadata?: Record<string, unknown>;
}

// --- Pipeline Config ---

export interface IngressPipelineConfig {
  readonly contentParser: ContentParser;
  readonly trustClassifier: TrustClassifier;
  readonly sensitivityEngine: import("../sensitivity/types.js").SensitivityEngine;
  readonly injectionDetector: InjectionDetector;
  readonly envelopeAssembler: EnvelopeAssembler;
}

export interface IngressPipeline {
  evaluate(
    input: {
      content: string;
      source_type: z.infer<typeof SourceTypeSchema>;
      source_trust?: z.infer<typeof SourceTrustSchema>;
      metadata?: Record<string, unknown>;
    },
    context: {
      actor_id: string;
      agent_id: string;
      purpose: string;
      task_id: string;
    },
  ): IngressPipelineResult;
}
