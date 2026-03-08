import { v4 as uuidv4 } from "uuid";
import type { PolicyEngine } from "./engine.js";
import { PolicyEvaluationError } from "./errors.js";
import { parsePolicyInput, type PolicyDecision } from "./types.js";

export interface PDP {
  evaluate(input: unknown): PolicyDecision;
}

export function createPDP(engine: PolicyEngine): PDP {
  return Object.freeze({
    evaluate(input: unknown): PolicyDecision {
      const validatedInput = parsePolicyInput(input);

      try {
        return engine.evaluate(validatedInput);
      } catch (error) {
        if (error instanceof PolicyEvaluationError) {
          return Object.freeze({
            decision: "deny" as const,
            decision_id: uuidv4(),
            policy_id: "pg.failclosed",
            matched_rules: ["evaluation_error"],
            explanation: "Policy evaluation failed; failing closed.",
            policy_bundle_version: engine.bundleVersion,
          });
        }
        throw error;
      }
    },
  });
}
