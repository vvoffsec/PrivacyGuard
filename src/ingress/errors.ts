type IngressStage =
  | "parse"
  | "classify"
  | "sensitivity"
  | "injection"
  | "assemble"
  | "pipeline";

interface IngressErrorContext {
  readonly content_hash?: string;
  readonly source_type?: string;
  readonly stage: IngressStage;
}

export class IngressParseError extends Error {
  public readonly context: IngressErrorContext;

  constructor(message: string, context?: Partial<IngressErrorContext>) {
    super(message);
    this.name = "IngressParseError";
    this.context = { stage: "parse", ...context };
  }

  toExplanation(): string {
    return `Content parsing failed at stage '${this.context.stage}': ${this.message}`;
  }
}

export class IngressClassificationError extends Error {
  public readonly context: IngressErrorContext;

  constructor(message: string, context?: Partial<IngressErrorContext>) {
    super(message);
    this.name = "IngressClassificationError";
    this.context = { stage: "classify", ...context };
  }

  toExplanation(): string {
    return `Trust classification failed at stage '${this.context.stage}': ${this.message}`;
  }
}

export class IngressPipelineError extends Error {
  public readonly context: IngressErrorContext;
  public override readonly cause?: Error;

  constructor(
    message: string,
    cause?: Error,
    context?: Partial<IngressErrorContext>,
  ) {
    super(message);
    this.name = "IngressPipelineError";
    this.cause = cause;
    this.context = { stage: "pipeline", ...context };
  }

  toExplanation(): string {
    const base = `Ingress pipeline failed at stage '${this.context.stage}': ${this.message}`;
    if (this.cause) {
      return `${base} (caused by: ${this.cause.message})`;
    }
    return base;
  }
}
