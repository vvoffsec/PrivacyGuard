type GatewayStage = "classify" | "validate" | "sanitize" | "authorize" | "gateway";

interface GatewayErrorContext {
  readonly tool_name?: string;
  readonly category?: string;
  readonly stage: GatewayStage;
}

export class GatewayValidationError extends Error {
  public readonly context: GatewayErrorContext;

  constructor(message: string, context?: Partial<GatewayErrorContext>) {
    super(message);
    this.name = "GatewayValidationError";
    this.context = { stage: "validate", ...context };
  }

  toExplanation(): string {
    return `Argument validation failed at stage '${this.context.stage}': ${this.message}`;
  }
}

export class GatewayClassificationError extends Error {
  public readonly context: GatewayErrorContext;

  constructor(message: string, context?: Partial<GatewayErrorContext>) {
    super(message);
    this.name = "GatewayClassificationError";
    this.context = { stage: "classify", ...context };
  }

  toExplanation(): string {
    return `Tool classification failed at stage '${this.context.stage}': ${this.message}`;
  }
}

export class GatewayAuthorizationError extends Error {
  public readonly context: GatewayErrorContext;
  public override readonly cause?: Error;

  constructor(message: string, cause?: Error, context?: Partial<GatewayErrorContext>) {
    super(message);
    this.name = "GatewayAuthorizationError";
    this.cause = cause;
    this.context = { stage: "gateway", ...context };
  }

  toExplanation(): string {
    const base = `Gateway authorization failed at stage '${this.context.stage}': ${this.message}`;
    if (this.cause) {
      return `${base} (caused by: ${this.cause.message})`;
    }
    return base;
  }
}
