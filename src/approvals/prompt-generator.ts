import type { DataClass } from "../data-model/data-class.js";
import { DataClassSchema } from "../data-model/data-class.js";
import type { PolicyDecision, PolicyInput, ApprovalPrompt } from "./types.js";
import { parseApprovalPrompt } from "./types.js";
import { buildScopeFromInput, computeScopeHash } from "./scope.js";

/**
 * Generates an ApprovalPrompt from a PolicyDecision and PolicyInput.
 * The prompt is shown to the user to request approval for a high-risk action.
 */
export function generateApprovalPrompt(
  decision: PolicyDecision,
  input: PolicyInput,
): ApprovalPrompt {
  const scope = buildScopeFromInput(decision, input);
  const scopeHash = computeScopeHash(scope);

  // Parse data classes from sensitivity, ignoring invalid ones
  const dataClasses: DataClass[] = [];
  for (const s of input.data.sensitivity) {
    const parsed = DataClassSchema.safeParse(s);
    if (parsed.success) {
      dataClasses.push(parsed.data);
    }
  }

  // Build human-readable explanation
  const explanationParts = [
    `Action '${input.request.action}' requires approval.`,
    `Destination: ${input.destination.name} (${input.destination.kind}).`,
  ];
  if (dataClasses.length > 0) {
    explanationParts.push(`Data classes: ${dataClasses.join(", ")}.`);
  }
  if (decision.matched_rules.length > 0) {
    explanationParts.push(`Matched rules: ${decision.matched_rules.join(", ")}.`);
  }
  explanationParts.push(`Policy: ${decision.policy_id}.`);

  return parseApprovalPrompt({
    prompt_id: `approval_${decision.decision_id}`,
    decision_id: decision.decision_id,
    action: input.request.action,
    data_classes: dataClasses,
    destination: input.destination.name,
    destination_kind: input.destination.kind,
    reasons: [...decision.matched_rules],
    explanation: explanationParts.join(" "),
    policy_id: decision.policy_id,
    scope_hash: scopeHash,
  });
}
