import { PolicyBundleError } from "./errors.js";
import type { PolicyRule } from "./policy-rule.js";

export interface PolicyBundle {
  readonly version: string;
  readonly rules: readonly PolicyRule[];
  readonly created_at: string;
}

export function createPolicyBundle(config: {
  version: string;
  rules: PolicyRule[];
}): PolicyBundle {
  if (config.version.length === 0) {
    throw new PolicyBundleError("Policy bundle version must be a non-empty string");
  }
  if (config.rules.length === 0) {
    throw new PolicyBundleError("Policy bundle must contain at least one rule");
  }

  const ids = new Set<string>();
  for (const rule of config.rules) {
    if (ids.has(rule.id)) {
      throw new PolicyBundleError(`Duplicate rule ID: ${rule.id}`);
    }
    ids.add(rule.id);
  }

  return Object.freeze({
    version: config.version,
    rules: Object.freeze([...config.rules]),
    created_at: new Date().toISOString(),
  });
}
