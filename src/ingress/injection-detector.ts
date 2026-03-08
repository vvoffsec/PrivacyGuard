import type { z } from "zod";
import type { SourceTrustSchema, TaintFlagSchema } from "../data-model/envelope.js";
import type {
  InjectionDetector,
  InjectionCheckResult,
  InjectionPattern,
} from "./types.js";

type SourceTrust = z.infer<typeof SourceTrustSchema>;
type TaintFlag = z.infer<typeof TaintFlagSchema>;

// Injection Patterns

const CRITICAL_PATTERNS: InjectionPattern[] = [
  {
    name: "zero_width_chars",
    pattern: /\u200B|\u200C|\u200D|\uFEFF/,
    confidence: 0.85,
    description: "Zero-width Unicode characters used for delimiter attacks",
  },
  {
    name: "encoded_instruction",
    pattern:
      /(?:[A-Za-z0-9+/]{20,}={0,2})/,
    confidence: 0.6,
    description: "Base64-encoded fragments that may contain hidden instructions",
  },
];

const STANDARD_PATTERNS: InjectionPattern[] = [
  {
    name: "hidden_instruction_marker",
    pattern: /\b(?:system\s*prompt|admin\s*override|internal\s*instruction)\b/i,
    confidence: 0.8,
    description: "Hidden instruction markers like 'system prompt' or 'admin override'",
  },
  {
    name: "role_assumption",
    pattern:
      /\b(?:ignore\s+(?:all\s+)?previous\s+instructions|you\s+are\s+now|forget\s+your\s+instructions|disregard\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|rules|guidelines))\b/i,
    confidence: 0.9,
    description: "Role assumption attempts like 'ignore previous instructions'",
  },
  {
    name: "html_injection",
    pattern:
      /<!--[\s\S]*?-->|display\s*:\s*none|visibility\s*:\s*hidden|<\s*div\s+[^>]*style\s*=\s*["'][^"']*display\s*:\s*none/i,
    confidence: 0.7,
    description: "HTML injection via hidden comments or display:none elements",
  },
  {
    name: "command_injection",
    pattern:
      /\b(?:eval\s*\(|exec\s*\(|os\.popen\s*\(|subprocess\s*\.\s*(?:call|run|Popen)\s*\(|child_process|require\s*\(\s*['"](?:child_process|fs|os)['"])/i,
    confidence: 0.75,
    description: "Command injection hints like eval(), exec(), os.popen()",
  },
  {
    name: "jailbreak_phrase",
    pattern:
      /\b(?:DAN\s+mode|bypass\s+safety|do\s+anything\s+now|ignore\s+(?:safety|content)\s+(?:policy|filter|guidelines)|pretend\s+you\s+(?:have\s+no|don'?t\s+have)\s+(?:restrictions|rules|limits))\b/i,
    confidence: 0.85,
    description: "Jailbreak phrases like 'DAN mode' or 'bypass safety'",
  },
];

/**
 * Checks if a base64 string decodes to instruction-like text.
 */
function isBase64Instruction(match: string): boolean {
  try {
    const decoded = Buffer.from(match, "base64").toString("utf-8");
    // Check if decoded text looks like instructions
    const instructionPatterns = [
      /ignore\s+previous/i,
      /you\s+are\s+now/i,
      /system\s*prompt/i,
      /admin\s*override/i,
      /\bexecute\b/i,
      /\beval\b/i,
    ];
    return instructionPatterns.some((p) => p.test(decoded));
  } catch {
    return false;
  }
}

const TRUSTED_SOURCE_TRUSTS = new Set<SourceTrust>([
  "trusted_user",
  "trusted_local",
]);

/**
 * Creates an InjectionDetector instance
 */
export function createInjectionDetector(
  customPatterns?: InjectionPattern[],
): InjectionDetector {
  return {
    check(content: string, source_trust: SourceTrust): InjectionCheckResult {
      const isTrusted = TRUSTED_SOURCE_TRUSTS.has(source_trust);
      const matched_patterns: string[] = [];
      let maxConfidence = 0;

      // Select patterns based on trust level
      const patterns = isTrusted
        ? CRITICAL_PATTERNS
        : [...CRITICAL_PATTERNS, ...STANDARD_PATTERNS, ...(customPatterns ?? [])];

      const confidenceThreshold = isTrusted ? 0.8 : 0;

      for (const pattern of patterns) {
        if (pattern.pattern.test(content)) {
          // Special handling for encoded instructions
          if (pattern.name === "encoded_instruction") {
            const b64Pattern = /(?:[A-Za-z0-9+/]{20,}={0,2})/g;
            let match;
            let found = false;
            while ((match = b64Pattern.exec(content)) !== null) {
              if (isBase64Instruction(match[0])) {
                found = true;
                break;
              }
            }
            if (!found) continue;
          }

          if (pattern.confidence >= confidenceThreshold) {
            matched_patterns.push(pattern.name);
            maxConfidence = Math.max(maxConfidence, pattern.confidence);
          }
        }
      }

      // Add custom patterns for untrusted sources
      if (!isTrusted && customPatterns) {
        for (const pattern of customPatterns) {
          if (
            !matched_patterns.includes(pattern.name) &&
            pattern.pattern.test(content)
          ) {
            matched_patterns.push(pattern.name);
            maxConfidence = Math.max(maxConfidence, pattern.confidence);
          }
        }
      }

      const detected = matched_patterns.length > 0;
      const taint_flags: TaintFlag[] = [];

      if (detected) {
        taint_flags.push("prompt_injection_suspected");
        if (!isTrusted) {
          taint_flags.push("untrusted_instruction");
        }
      }

      return Object.freeze({
        detected,
        confidence: detected ? maxConfidence : 0,
        matched_patterns,
        taint_flags,
      });
    },
  };
}
