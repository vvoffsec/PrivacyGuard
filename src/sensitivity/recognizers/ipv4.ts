import type { DetectionMatch, PatternRecognizer } from "../types.js";
import { execAll } from "./utils.js";

export function createIPv4Recognizer(): PatternRecognizer {
  return {
    name: "ipv4",
    data_class: "internal",
    default_confidence: 0.5,
    detect(content: string): DetectionMatch[] {
      return execAll(
        /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
        content,
      ).map((m) => ({
        value: m[0],
        span: { start: m.index, end: m.index + m[0].length },
        signals: { pattern_matched: true },
      }));
    },
  };
}
