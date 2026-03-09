import type { DetectionMatch, PatternRecognizer } from "../types.js";
import { execAll } from "./utils.js";

export function createApiKeyRecognizer(): PatternRecognizer {
  return {
    name: "api_key",
    data_class: "secret",
    default_confidence: 0.8,
    detect(content: string): DetectionMatch[] {
      return execAll(
        /\b(?:api[_-]?key|token|secret|api[_-]?secret)\s*[=:]\s*["']?([a-zA-Z0-9_\-./+=]{8,})["']?/gi,
        content,
      ).map((m) => ({
        value: m[0],
        span: { start: m.index, end: m.index + m[0].length },
        signals: {
          pattern_matched: true,
          format_validated: true,
          context_validated: true,
        },
      }));
    },
  };
}
