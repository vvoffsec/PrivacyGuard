import type { z } from "zod";

type ZodIssue = z.core.$ZodIssue;

export class EnvelopeValidationError extends Error {
  public readonly issues: ZodIssue[];

  constructor(issues: ZodIssue[]) {
    super(`Envelope validation failed: ${issues.length} issue(s)`);
    this.name = "EnvelopeValidationError";
    this.issues = issues;
  }

  toExplanation(): string {
    return this.issues
      .map(
        (issue, i) => `${i + 1}. [${issue.path.map(String).join(".")}] ${issue.message}`,
      )
      .join("\n");
  }
}

export class EnvelopeConsistencyError extends EnvelopeValidationError {
  constructor(issues: ZodIssue[]) {
    super(issues);
    this.name = "EnvelopeConsistencyError";
  }
}
