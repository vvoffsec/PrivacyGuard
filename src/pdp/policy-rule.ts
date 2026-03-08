import type { PolicyEffect, PolicyInput } from "./types.js";

export interface PolicyRule {
  readonly id: string;
  readonly description: string;
  readonly effect: PolicyEffect;
  readonly evaluate: (input: PolicyInput) => boolean;
}

export function createPolicyRule(config: PolicyRule): Readonly<PolicyRule> {
  if (!config.id || config.id.length === 0) {
    throw new Error("PolicyRule id must be a non-empty string");
  }
  if (!config.description || config.description.length === 0) {
    throw new Error("PolicyRule description must be a non-empty string");
  }
  const validEffects = [
    "allow",
    "allow_with_minimization",
    "require_approval",
    "quarantine",
    "deny",
  ];
  if (!validEffects.includes(config.effect)) {
    throw new Error(`PolicyRule effect must be one of: ${validEffects.join(", ")}`);
  }
  if (typeof config.evaluate !== "function") {
    throw new Error("PolicyRule evaluate must be a function");
  }
  return Object.freeze({
    id: config.id,
    description: config.description,
    effect: config.effect,
    evaluate: config.evaluate,
  });
}
