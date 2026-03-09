type ApprovalStage = "prompt" | "store" | "scope" | "orchestrator";

interface ApprovalErrorContext {
  readonly stage: ApprovalStage;
  readonly approval_id?: string;
}

export class ApprovalValidationError extends Error {
  public readonly context: ApprovalErrorContext;

  constructor(message: string, context?: Partial<ApprovalErrorContext>) {
    super(message);
    this.name = "ApprovalValidationError";
    this.context = { stage: "scope", ...context };
  }

  toExplanation(): string {
    return `Approval validation failed at stage '${this.context.stage}': ${this.message}`;
  }
}

export class ApprovalExpiredError extends Error {
  public readonly context: ApprovalErrorContext;

  constructor(
    message: string,
    approvalId: string,
    context?: Partial<ApprovalErrorContext>,
  ) {
    super(message);
    this.name = "ApprovalExpiredError";
    this.context = { stage: "store", approval_id: approvalId, ...context };
  }

  toExplanation(): string {
    return `Approval expired at stage '${this.context.stage}': ${this.message} (approval_id: ${this.context.approval_id ?? "unknown"})`;
  }
}

export class ApprovalOrchestratorError extends Error {
  public readonly context: ApprovalErrorContext;
  public override readonly cause?: Error;

  constructor(message: string, cause?: Error, context?: Partial<ApprovalErrorContext>) {
    super(message);
    this.name = "ApprovalOrchestratorError";
    this.cause = cause;
    this.context = { stage: "orchestrator", ...context };
  }

  toExplanation(): string {
    const base = `Approval orchestrator failed at stage '${this.context.stage}': ${this.message}`;
    if (this.cause) {
      return `${base} (caused by: ${this.cause.message})`;
    }
    return base;
  }
}
