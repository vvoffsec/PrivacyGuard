import type { z } from "zod";

type ZodIssue = z.core.$ZodIssue;

export class PolicyValidationError extends Error {
  public readonly issues: ZodIssue[];

  constructor(issues: ZodIssue[]) {
    super(`Policy validation failed: ${issues.length} issue(s)`);
    this.name = "PolicyValidationError";
    this.issues = issues;
  }

  toExplanation(): string {
    return this.issues
      .map(
        (issue, i) =>
          `${i + 1}. [${issue.path.map(String).join(".")}] ${issue.message}`,
      )
      .join("\n");
  }
}

export class PolicyBundleError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PolicyBundleError";
  }
}

export class PolicyEvaluationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PolicyEvaluationError";
  }
}
