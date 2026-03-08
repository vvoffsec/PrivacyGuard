import type { z } from "zod";

type ZodIssue = z.core.$ZodIssue;

export class TokenValidationError extends Error {
  public readonly issues: ZodIssue[];

  constructor(issues: ZodIssue[]) {
    super(`Token validation failed: ${issues.length} issue(s)`);
    this.name = "TokenValidationError";
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

export class TokenExpiredError extends Error {
  public readonly tokenId: string;
  public readonly expiredAt: string;

  constructor(tokenId: string, expiredAt: string) {
    super(`Token ${tokenId} expired at ${expiredAt}`);
    this.name = "TokenExpiredError";
    this.tokenId = tokenId;
    this.expiredAt = expiredAt;
  }
}

export class TokenRevokedError extends Error {
  public readonly tokenId: string;

  constructor(tokenId: string) {
    super(`Token ${tokenId} has been revoked`);
    this.name = "TokenRevokedError";
    this.tokenId = tokenId;
  }
}

export class TokenSignatureError extends Error {
  public readonly tokenId: string;

  constructor(tokenId: string) {
    super(`Token ${tokenId} has an invalid signature`);
    this.name = "TokenSignatureError";
    this.tokenId = tokenId;
  }
}

export class TokenScopeError extends Error {
  public readonly tokenId: string;
  public readonly reasons: string[];

  constructor(tokenId: string, reasons: string[]) {
    super(`Token ${tokenId} scope violation: ${reasons.join("; ")}`);
    this.name = "TokenScopeError";
    this.tokenId = tokenId;
    this.reasons = reasons;
  }
}

export class TokenMintError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TokenMintError";
  }
}
