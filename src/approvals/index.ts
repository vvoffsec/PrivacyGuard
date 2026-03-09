// Types
export type {
  ApprovalStatus,
  ApprovalScope,
  ApprovalRecord,
  ApprovalPrompt,
  ApprovalResponse,
  ApprovalOrchestratorResult,
  ApprovalUxAdapter,
  ApprovalStore,
  ApprovalOrchestrator,
  ApprovalOrchestratorConfig,
} from "./types.js";

// Schemas
export {
  ApprovalStatusSchema,
  ApprovalScopeSchema,
  ApprovalRecordSchema,
  ApprovalPromptSchema,
  ApprovalResponseSchema,
  ApprovalOrchestratorResultSchema,
  parseApprovalRecord,
  parseApprovalPrompt,
  parseApprovalResponse,
} from "./types.js";

// Errors
export {
  ApprovalValidationError,
  ApprovalExpiredError,
  ApprovalOrchestratorError,
} from "./errors.js";

// Scope utilities
export { computeScopeHash, scopeCoversRequest, buildScopeFromInput } from "./scope.js";

// Prompt generator
export { generateApprovalPrompt } from "./prompt-generator.js";

// Store factory
export { createApprovalStore } from "./approval-store.js";

// Orchestrator factory
export { createApprovalOrchestrator } from "./orchestrator.js";
