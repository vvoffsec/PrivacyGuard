import type { z } from "zod";

type ZodIssue = z.core.$ZodIssue;

export class ApiValidationError extends Error {
  public readonly issues: ZodIssue[];

  constructor(issues: ZodIssue[]) {
    super(`API validation failed: ${issues.length} issue(s)`);
    this.name = "ApiValidationError";
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

export class ApiHandlerError extends Error {
  public readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "ApiHandlerError";
    this.code = code;
  }

  toExplanation(): string {
    return `[${this.code}] ${this.message}`;
  }
}
