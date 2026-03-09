import type { DetectionMatch, PatternRecognizer } from "../types.js";
import { shannonEntropy } from "../entropy.js";
import { execAll } from "./utils.js";

export function createHighEntropyRecognizer(threshold = 4.5): PatternRecognizer {
  return {
    name: "high_entropy_string",
    data_class: "secret",
    default_confidence: 0.6,
    detect(content: string): DetectionMatch[] {
      const results: DetectionMatch[] = [];
      for (const m of execAll(
        /\b(?:key|token|secret|api_key|apikey|auth|credential|private_key)\s*[=:]\s*["']?([a-zA-Z0-9_\-./+=]{20,})["']?/gi,
        content,
      )) {
        const valueStr = m[1];
        if (valueStr) {
          const score = shannonEntropy(valueStr);
          if (score > threshold) {
            results.push({
              value: m[0],
              span: { start: m.index, end: m.index + m[0].length },
              signals: {
                pattern_matched: true,
                entropy_score: score,
              },
            });
          }
        }
      }
      return results;
    },
  };
}
