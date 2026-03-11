import { sha256Hash } from "../shared/crypto.js";
import {
  DataClassSchema,
  highestDataClass,
  isAtLeast,
  type DataClass,
} from "../data-model/data-class.js";
import type { PolicyDecision, PolicyInput } from "../pdp/types.js";
import type { ApprovalScope } from "./types.js";
import { ApprovalScopeSchema } from "./types.js";
import { ApprovalValidationError } from "./errors.js";

/**
 * Computes a deterministic SHA-256 hash from an ApprovalScope.
 * Canonical form: `action|purpose1,purpose2,...|destination|data_class`
 * Purposes are sorted alphabetically for order-independence.
 */
export function computeScopeHash(scope: ApprovalScope): string {
  const parsed = ApprovalScopeSchema.safeParse(scope);
  if (!parsed.success) {
    throw new ApprovalValidationError("Invalid scope for hash computation", {
      stage: "scope",
    });
  }
  const s = parsed.data;
  const sortedPurposes = [...s.purpose].sort();
  const canonical = `${s.action}|${sortedPurposes.join(",")}|${s.destination}|${s.data_class}`;
  return sha256Hash(canonical);
}

/**
 * Checks whether an existing approval scope covers a new request scope.
 * - Same action, same destination
 * - Existing purpose is superset of request purpose
 * - Existing data_class is at least as sensitive as request data_class
 */
export function scopeCoversRequest(
  existing: ApprovalScope,
  request: ApprovalScope,
): boolean {
  if (existing.action !== request.action) return false;
  if (existing.destination !== request.destination) return false;

  // Existing purpose must be a superset of request purpose
  const existingPurposes = new Set(existing.purpose);
  for (const p of request.purpose) {
    if (!existingPurposes.has(p)) return false;
  }

  // Existing data_class must be at least as sensitive as request
  if (!isAtLeast(existing.data_class, request.data_class)) return false;

  return true;
}

/**
 * Builds an ApprovalScope from a PolicyDecision and PolicyInput.
 */
export function buildScopeFromInput(
  decision: PolicyDecision,
  input: PolicyInput,
): ApprovalScope {
  // Parse sensitivity strings through DataClassSchema, ignoring invalid ones
  const validClasses: DataClass[] = [];
  for (const s of input.data.sensitivity) {
    const parsed = DataClassSchema.safeParse(s);
    if (parsed.success) {
      validClasses.push(parsed.data);
    }
  }
  const dataClass = highestDataClass(validClasses);

  // Suppress unused variable warning — decision is accepted for API consistency
  void decision;

  const scope: ApprovalScope = {
    action: input.request.action,
    purpose: [...input.request.purpose],
    destination: input.destination.name,
    data_class: dataClass,
  };

  return Object.freeze(scope);
}
