import type { DetectionMatch, PatternRecognizer } from "../types.js";
import { execAll } from "./utils.js";

export function createEmailRecognizer(): PatternRecognizer {
  return {
    name: "email",
    data_class: "pii",
    default_confidence: 0.9,
    detect(content: string): DetectionMatch[] {
      return execAll(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, content).map(
        (m) => ({
          value: m[0],
          span: { start: m.index, end: m.index + m[0].length },
          signals: { pattern_matched: true, format_validated: true },
        }),
      );
    },
  };
}
