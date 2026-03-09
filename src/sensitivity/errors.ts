export class SensitivityDetectionError extends Error {
  public readonly code = "SENSITIVITY_DETECTION_ERROR";
  public readonly details: Record<string, unknown>;

  constructor(message: string, details: Record<string, unknown> = {}) {
    super(message);
    this.name = "SensitivityDetectionError";
    this.details = details;
  }

  toExplanation(): string {
    const parts = [this.message];
    const recognizer = this.details.recognizer;
    if (typeof recognizer === "string") {
      parts.push(`Recognizer: ${recognizer}`);
    }
    const stage = this.details.stage;
    if (typeof stage === "string") {
      parts.push(`Stage: ${stage}`);
    }
    return parts.join(" | ");
  }
}
