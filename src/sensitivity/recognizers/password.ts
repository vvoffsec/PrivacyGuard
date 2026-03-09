import type { DetectionMatch, PatternRecognizer } from "../types.js";
import { execAll } from "./utils.js";

export function createPasswordRecognizer(): PatternRecognizer {
  return {
    name: "password",
    data_class: "credential",
    default_confidence: 0.75,
    detect(content: string): DetectionMatch[] {
      return execAll(
        /\b(?:password|passwd|pwd|pass)\s*[=:]\s*["']?([^\s"']{1,}(?:\s[^\s"']+)*)["']?/gi,
        content,
      ).map((m) => ({
          value: m[0],
          span: { start: m.index, end: m.index + m[0].length },
          signals: {
            pattern_matched: true,
            context_validated: true,
          },
        }));
    },
  };
}
