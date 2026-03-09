import type { DetectionMatch, PatternRecognizer } from "../types.js";
import { execAll } from "./utils.js";

export function createPhoneRecognizer(): PatternRecognizer {
  return {
    name: "phone",
    data_class: "pii",
    default_confidence: 0.7,
    detect(content: string): DetectionMatch[] {
      const results: DetectionMatch[] = [];
      for (const m of execAll(
        /(?:\+1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b/g,
        content,
      )) {
        const digits = m[0].replace(/\D/g, "");
        if (digits.length >= 10 && digits.length <= 11) {
          results.push({
            value: m[0],
            span: { start: m.index, end: m.index + m[0].length },
            signals: {
              pattern_matched: true,
              format_validated: digits.length >= 10,
            },
          });
        }
      }
      return results;
    },
  };
}
