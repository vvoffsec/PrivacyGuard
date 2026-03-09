import type { ConfidenceSignals } from "./types.js";

/**
 * Computes final confidence score from base confidence + validation signals.
 *
 * Rules:
 * - Checksum validated (Luhn, etc.): boost to max(base, 0.95)
 * - Format validated (JWT header, SSN area rules): boost to max(base, 0.9)
 * - Context validated (key-value context): boost by +0.05
 * - High entropy (>5.0): boost by +0.05
 * - Pattern-only (no signals or no validations): cap at min(base, 0.7)
 */
export function computeConfidence(base: number, signals?: ConfidenceSignals): number {
  if (!signals) {
    return Math.min(base, 0.7);
  }

  const hasValidation =
    signals.checksum_validated === true ||
    signals.format_validated === true ||
    signals.context_validated === true;

  const hasHighEntropy =
    signals.entropy_score !== undefined && signals.entropy_score > 5.0;

  if (!hasValidation && !hasHighEntropy) {
    return Math.min(base, 0.7);
  }

  let confidence = base;

  if (signals.checksum_validated === true) {
    confidence = Math.max(confidence, 0.95);
  }

  if (signals.format_validated === true) {
    confidence = Math.max(confidence, 0.9);
  }

  if (signals.context_validated === true) {
    confidence = Math.min(confidence + 0.05, 1.0);
  }

  if (signals.entropy_score !== undefined && signals.entropy_score > 5.0) {
    confidence = Math.min(confidence + 0.05, 1.0);
  }

  return Math.round(confidence * 100) / 100;
}
