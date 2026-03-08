// Types and interfaces
export type {
  ContentFormat,
  ParsedContent,
  TrustClassification,
  SensitivityResult,
  InjectionCheckResult,
  IngressPipelineResult,
  ContentParser,
  TrustClassifier,
  SensitivityEngine,
  PatternRecognizer,
  InjectionDetector,
  InjectionPattern,
  EnvelopeAssembler,
  EnvelopeAssemblerInput,
  IngressPipelineConfig,
  IngressPipeline,
} from "./types.js";

// Schemas
export {
  ContentFormatSchema,
  ParsedContentSchema,
  TrustClassificationSchema,
  SensitivityResultSchema,
  InjectionCheckResultSchema,
} from "./types.js";

// Errors
export {
  IngressParseError,
  IngressClassificationError,
  IngressPipelineError,
} from "./errors.js";

// Factories
export { createContentParser } from "./content-parser.js";
export { createTrustClassifier } from "./trust-classifier.js";
export { createPatternSensitivityEngine } from "./sensitivity-engine.js";
export { createInjectionDetector } from "./injection-detector.js";
export { createEnvelopeAssembler } from "./envelope-assembler.js";
export { createIngressPipeline, createDefaultIngressPipeline } from "./pipeline.js";
