import type { z } from "zod";

type ZodIssue = z.core.$ZodIssue;

export class AuditValidationError extends Error {
  public readonly issues: ZodIssue[];

  constructor(issues: ZodIssue[]) {
    super(`Audit event validation failed: ${issues.length} issue(s)`);
    this.name = "AuditValidationError";
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

export class AuditConsistencyError extends AuditValidationError {
  constructor(issues: ZodIssue[]) {
    super(issues);
    this.name = "AuditConsistencyError";
  }
}

export class AuditStoreError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AuditStoreError";
  }
}
