import type { PolicyDecision, PolicyInput } from "./types.js";

export interface PolicyEngine {
  evaluate(input: PolicyInput): PolicyDecision;
  readonly bundleVersion: string;
}
