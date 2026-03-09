import type { DetectionMatch, PatternRecognizer } from "../types.js";
import { execAll } from "./utils.js";

/**
 * Validates a digit string using the Luhn algorithm.
 */
export function luhnCheck(digits: string): boolean {
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = parseInt(digits[i], 10);
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

export function createCreditCardRecognizer(): PatternRecognizer {
  return {
    name: "credit_card",
    data_class: "pii",
    default_confidence: 0.9,
    detect(content: string): DetectionMatch[] {
      const results: DetectionMatch[] = [];
      for (const m of execAll(/\b(?:\d[ -]*?){13,19}\b/g, content)) {
        const digits = m[0].replace(/\D/g, "");
        if (digits.length >= 13 && digits.length <= 19 && luhnCheck(digits)) {
          results.push({
            value: m[0],
            span: { start: m.index, end: m.index + m[0].length },
            signals: {
              pattern_matched: true,
              checksum_validated: true,
            },
          });
        }
      }
      return results;
    },
  };
}
