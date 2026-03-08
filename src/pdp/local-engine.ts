import { v4 as uuidv4 } from "uuid";
import type { PolicyEngine } from "./engine.js";
import type { PolicyBundle } from "./policy-bundle.js";
import { PolicyEvaluationError } from "./errors.js";
import {
  type PolicyDecision,
  type PolicyInput,
  type PolicyEffect,
  EFFECT_SEVERITY,
  mostRestrictiveEffect,
} from "./types.js";

export class InProcessPolicyEngine implements PolicyEngine {
  private readonly bundle: PolicyBundle;

  constructor(bundle: PolicyBundle) {
    this.bundle = bundle;
  }

  get bundleVersion(): string {
    return this.bundle.version;
  }

  evaluate(input: PolicyInput): PolicyDecision {
    const matchedRules: { id: string; effect: PolicyEffect; description: string }[] = [];

    for (const rule of this.bundle.rules) {
      try {
        if (rule.evaluate(input)) {
          matchedRules.push({
            id: rule.id,
            effect: rule.effect,
            description: rule.description,
          });
        }
      } catch (error) {
        const message =
          error instanceof Error ? error.message : String(error);
        throw new PolicyEvaluationError(
          `Rule "${rule.id}" threw during evaluation: ${message}`,
        );
      }
    }

    if (matchedRules.length === 0) {
      return Object.freeze({
        decision: "allow" as const,
        decision_id: uuidv4(),
        policy_id: "pg.default.allow",
        matched_rules: ["no_rule_matched"],
        explanation: "No policy rules matched; defaulting to allow",
        policy_bundle_version: this.bundle.version,
      });
    }

    const effects = matchedRules.map((r) => r.effect);
    const winningEffect = mostRestrictiveEffect(effects);

    // First rule at the winning severity provides policy_id
    // Safe: matchedRules is non-empty and winningEffect comes from their effects
    const winningRule = matchedRules.find(
      (r) => EFFECT_SEVERITY[r.effect] === EFFECT_SEVERITY[winningEffect],
    ) as { id: string; effect: PolicyEffect; description: string };

    const decision: PolicyDecision = Object.freeze({
      decision: winningEffect,
      decision_id: uuidv4(),
      policy_id: winningRule.id,
      matched_rules: matchedRules.map((r) => r.id),
      explanation: winningRule.description,
      required_actions:
        winningEffect === "require_approval"
          ? [
              {
                type: "user_approval",
                reason: winningRule.description,
              },
            ]
          : winningEffect === "allow_with_minimization"
            ? [
                {
                  type: "minimize",
                  reason: winningRule.description,
                },
              ]
            : undefined,
      policy_bundle_version: this.bundle.version,
    });

    return decision;
  }
}
