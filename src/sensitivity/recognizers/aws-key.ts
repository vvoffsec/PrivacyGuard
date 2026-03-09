import type { DetectionMatch, PatternRecognizer } from "../types.js";
import { execAll } from "./utils.js";

export function createAwsKeyRecognizer(): PatternRecognizer {
  return {
    name: "aws_access_key",
    data_class: "credential",
    default_confidence: 0.95,
    detect(content: string): DetectionMatch[] {
      return execAll(/\bAKIA[0-9A-Z]{16}\b/g, content).map((m) => ({
        value: m[0],
        span: { start: m.index, end: m.index + m[0].length },
        signals: {
          pattern_matched: true,
          format_validated: true,
        },
      }));
    },
  };
}
