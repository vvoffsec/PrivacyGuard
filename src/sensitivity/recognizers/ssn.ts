import type { DetectionMatch, PatternRecognizer } from "../types.js";
import { execAll } from "./utils.js";

export function createSSNRecognizer(): PatternRecognizer {
  return {
    name: "ssn",
    data_class: "pii",
    default_confidence: 0.85,
    detect(content: string): DetectionMatch[] {
      const results: DetectionMatch[] = [];
      for (const m of execAll(/\b\d{3}-\d{2}-\d{4}\b/g, content)) {
        const area = parseInt(m[0].substring(0, 3), 10);
        const validArea = area !== 0 && area !== 666 && area < 900;
        if (validArea) {
          results.push({
            value: m[0],
            span: { start: m.index, end: m.index + m[0].length },
            signals: {
              pattern_matched: true,
              format_validated: true,
            },
          });
        }
      }
      return results;
    },
  };
}
