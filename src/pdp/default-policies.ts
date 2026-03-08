import { createPolicyRule, type PolicyRule } from "./policy-rule.js";
import { createPolicyBundle, type PolicyBundle } from "./policy-bundle.js";

const EGRESS_ACTIONS = [
  "model.remote_prompt",
  "http.send",
  "message.send",
  "upload.file",
];

export const egressSecretDeny: PolicyRule = createPolicyRule({
  id: "pg.egress.secret.default",
  description: "Deny egress of content marked as secret to any remote destination",
  effect: "deny",
  evaluate: (input) =>
    EGRESS_ACTIONS.includes(input.request.action) &&
    input.data.sensitivity.includes("secret"),
});

export const execUntrustedApproval: PolicyRule = createPolicyRule({
  id: "pg.exec.untrusted.content",
  description:
    "Require approval before executing tools with untrusted instruction content",
  effect: "require_approval",
  evaluate: (input) =>
    input.request.action.startsWith("tool.exec") &&
    input.data.taint_flags.includes("untrusted_instruction"),
});

export const memoryPromotionQuarantine: PolicyRule = createPolicyRule({
  id: "pg.memory.promotion",
  description: "Quarantine untrusted external content being promoted to durable memory",
  effect: "quarantine",
  evaluate: (input) =>
    input.request.action === "memory.write" &&
    input.request.purpose.includes("durable") &&
    input.data.source_trust.includes("untrusted_external"),
});

export function createDefaultPolicyBundle(): PolicyBundle {
  return createPolicyBundle({
    version: "0.1.0",
    rules: [egressSecretDeny, execUntrustedApproval, memoryPromotionQuarantine],
  });
}
