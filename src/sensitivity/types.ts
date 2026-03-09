import { z } from "zod";
import { DataClassSchema } from "../data-model/data-class.js";
import { DetectedEntitySchema, EntitySpanSchema } from "../data-model/entity.js";
import { TaintFlagSchema } from "../data-model/envelope.js";
import type { DataClass } from "../data-model/data-class.js";
import type { DetectedEntity } from "../data-model/entity.js";

// --- Confidence Signals ---

export const ConfidenceSignalsSchema = z.object({
  pattern_matched: z.boolean(),
  checksum_validated: z.boolean().optional(),
  format_validated: z.boolean().optional(),
  context_validated: z.boolean().optional(),
  entropy_score: z.number().optional(),
});
export type ConfidenceSignals = z.infer<typeof ConfidenceSignalsSchema>;

// --- Detection Match ---

export const DetectionMatchSchema = z.object({
  value: z.string(),
  span: EntitySpanSchema,
  signals: ConfidenceSignalsSchema.optional(),
});
export type DetectionMatch = z.infer<typeof DetectionMatchSchema>;

// --- Pattern Recognizer ---

export interface PatternRecognizer {
  readonly name: string;
  readonly data_class: DataClass;
  readonly default_confidence: number;
  detect(content: string): readonly DetectionMatch[];
}

// --- Secret Handle ---

export const SecretHandleSchema = z.object({
  handle_id: z.string().regex(/^secretref:\/\/[a-z_]+\/[0-9a-f]{8}$/),
  entity_type: z.string().min(1),
  value_hash: z.string().regex(/^sha256:[0-9a-f]{64}$/),
  data_class: DataClassSchema,
});
export type SecretHandle = z.infer<typeof SecretHandleSchema>;

// --- Secret Handle Registry ---

export interface SecretHandleRegistry {
  register(entity_type: string, value_hash: string, data_class: DataClass): SecretHandle;
  lookup(handle_id: string): SecretHandle | undefined;
  lookupByHash(value_hash: string): SecretHandle | undefined;
  size(): number;
  clear(): void;
}

// --- Sensitivity Result ---

export const SensitivityResultSchema = z.object({
  entities: z.array(DetectedEntitySchema),
  data_classes: z.array(DataClassSchema),
  taint_flags: z.array(TaintFlagSchema),
  secret_handles: z.array(SecretHandleSchema).optional(),
});
export type SensitivityResult = Readonly<z.infer<typeof SensitivityResultSchema>>;

// --- Engine Config ---

export interface SensitivityEngineConfig {
  readonly recognizers?: PatternRecognizer[];
  readonly additional_recognizers?: PatternRecognizer[];
  readonly entropy_threshold?: number;
  readonly generate_secret_handles?: boolean;
}

// --- Sensitivity Engine ---

export interface SensitivityEngine {
  scan(content: string): SensitivityResult;
}

// --- Internal Entity with Data Class ---

export type EntityWithClass = DetectedEntity & { _data_class: DataClass };
