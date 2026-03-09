// Types and interfaces
export type {
  ConfidenceSignals,
  DetectionMatch,
  PatternRecognizer,
  SecretHandle,
  SecretHandleRegistry,
  SensitivityResult,
  SensitivityEngineConfig,
  SensitivityEngine,
  EntityWithClass,
} from "./types.js";

// Schemas
export {
  ConfidenceSignalsSchema,
  DetectionMatchSchema,
  SecretHandleSchema,
  SensitivityResultSchema,
} from "./types.js";

// Errors
export { SensitivityDetectionError } from "./errors.js";

// Utilities
export { shannonEntropy } from "./entropy.js";
export { computeConfidence } from "./confidence.js";
export { deduplicateEntities } from "./deduplication.js";

// Secret handles
export { createSecretHandleRegistry } from "./secret-handle.js";

// Recognizers
export {
  createEmailRecognizer,
  createPhoneRecognizer,
  createSSNRecognizer,
  createCreditCardRecognizer,
  luhnCheck,
  createApiKeyRecognizer,
  createAwsKeyRecognizer,
  createIPv4Recognizer,
  createOAuthTokenRecognizer,
  createPasswordRecognizer,
  createHighEntropyRecognizer,
} from "./recognizers/index.js";

// Engine
export { createSensitivityEngine } from "./engine.js";
