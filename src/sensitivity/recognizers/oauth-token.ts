import type { DetectionMatch, PatternRecognizer } from "../types.js";
import { execAll } from "./utils.js";

/**
 * Attempts to decode a base64url string and parse as JSON.
 * Returns the parsed object or undefined on failure.
 */
function tryDecodeJwtHeader(segment: string): Record<string, unknown> | undefined {
  try {
    // base64url -> base64
    const base64 = segment.replace(/-/g, "+").replace(/_/g, "/");
    const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
    const decoded = atob(padded);
    const parsed: unknown = JSON.parse(decoded);
    if (typeof parsed === "object" && parsed !== null && "alg" in parsed) {
      return parsed as Record<string, unknown>;
    }
    return undefined;
  } catch {
    return undefined;
  }
}

export function createOAuthTokenRecognizer(): PatternRecognizer {
  return {
    name: "oauth_token",
    data_class: "credential",
    default_confidence: 0.9,
    detect(content: string): DetectionMatch[] {
      const results: DetectionMatch[] = [];

      // JWT pattern: eyJ...eyJ...signature
      for (const m of execAll(
        /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
        content,
      )) {
        const parts = m[0].split(".");
        const header = tryDecodeJwtHeader(parts[0]);
        results.push({
          value: m[0],
          span: { start: m.index, end: m.index + m[0].length },
          signals: {
            pattern_matched: true,
            format_validated: header !== undefined,
          },
        });
      }

      // Bearer token pattern in headers/configs
      for (const m of execAll(/\bBearer\s+([A-Za-z0-9_\-./+=]{20,})\b/g, content)) {
        // Avoid double-counting JWTs already matched above
        const tokenValue = m[1];
        if (tokenValue && !tokenValue.startsWith("eyJ")) {
          results.push({
            value: m[0],
            span: { start: m.index, end: m.index + m[0].length },
            signals: {
              pattern_matched: true,
              context_validated: true,
            },
          });
        }
      }

      return results;
    },
  };
}
