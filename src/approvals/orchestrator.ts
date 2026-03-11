import { v4 as uuidv4 } from "uuid";
import { createApprovalEvent } from "../audit/factories.js";
import type {
  ApprovalOrchestrator,
  ApprovalOrchestratorConfig,
  ApprovalOrchestratorResult,
  PolicyDecision,
  PolicyInput,
} from "./types.js";
import { buildScopeFromInput, computeScopeHash, scopeCoversRequest } from "./scope.js";
import { generateApprovalPrompt } from "./prompt-generator.js";
import { ApprovalOrchestratorError, ApprovalValidationError } from "./errors.js";

const DEFAULT_TTL_SECONDS = 300;

/**
 * Creates an ApprovalOrchestrator that mediates the approval flow:
 * check cached → prompt → record → audit.
 */
export function createApprovalOrchestrator(
  config: ApprovalOrchestratorConfig,
): ApprovalOrchestrator {
  const { store, uxAdapter, auditEmitter } = config;
  const defaultTtl = config.defaultTtlSeconds ?? DEFAULT_TTL_SECONDS;

  return {
    evaluate(decision: PolicyDecision, input: PolicyInput): ApprovalOrchestratorResult {
      // Guard — only process require_approval decisions
      if (decision.decision !== "require_approval") {
        throw new ApprovalValidationError(
          `Expected decision 'require_approval', got '${decision.decision}'`,
          { stage: "orchestrator" },
        );
      }

      try {
        // Build scope + scope_hash
        const scope = buildScopeFromInput(decision, input);
        const scopeHash = computeScopeHash(scope);

        // Check store for existing approval
        const cached = store.findByScope(scopeHash);
        if (cached?.status === "granted" && scopeCoversRequest(cached.scope, scope)) {
          // Cached and valid → return immediately
          return Object.freeze({
            approved: true,
            approval_id: cached.approval_id,
            prompt_shown: false,
            scope_hash: scopeHash,
            reason: cached.reason,
            expires_at: cached.expires_at,
          }) as ApprovalOrchestratorResult;
        }

        // Generate prompt
        const prompt = generateApprovalPrompt(decision, input);

        // Request approval from UX adapter
        const response = uxAdapter.requestApproval(prompt);

        // Create ApprovalRecord
        const approvalId = uuidv4();
        const now = new Date();
        const ttlSeconds = response.expires_in_seconds ?? defaultTtl;
        const expiresAt = response.approved
          ? new Date(now.getTime() + ttlSeconds * 1000).toISOString()
          : undefined;

        const record = {
          approval_id: approvalId,
          decision_id: decision.decision_id,
          actor_id: response.actor_id,
          scope,
          scope_hash: scopeHash,
          reason: response.reason,
          status: response.approved ? ("granted" as const) : ("denied" as const),
          created_at: now.toISOString(),
          expires_at: expiresAt,
        };

        store.put(record);

        // Emit audit event
        const auditEvent = createApprovalEvent({
          approval_id: approvalId,
          actor_id: response.actor_id,
          decision_id: decision.decision_id,
          scope_hash: scopeHash,
          reason: response.reason,
          status: response.approved ? "granted" : "denied",
          expires_at: expiresAt,
        });

        auditEmitter.emit(auditEvent);

        // Return result
        return Object.freeze({
          approved: response.approved,
          approval_id: approvalId,
          prompt_shown: true,
          scope_hash: scopeHash,
          reason: response.reason,
          expires_at: expiresAt,
        }) as ApprovalOrchestratorResult;
      } catch (error) {
        if (
          error instanceof ApprovalValidationError ||
          error instanceof ApprovalOrchestratorError
        ) {
          throw error;
        }
        throw new ApprovalOrchestratorError(
          "Unexpected error during approval evaluation",
          error instanceof Error ? error : new Error(String(error)),
          { stage: "orchestrator" },
        );
      }
    },
  };
}
