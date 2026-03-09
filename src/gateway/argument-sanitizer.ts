import type {
  ArgumentSanitizer,
  SanitizationFinding,
  SanitizationResult,
  ToolCategoryName,
  ToolRiskLevel,
} from "./types.js";

// --- Pattern definition ---

interface SanitizationPattern {
  readonly name: string;
  readonly pattern: RegExp;
  readonly severity: ToolRiskLevel;
  readonly description: string;
  readonly categories: ReadonlySet<ToolCategoryName>;
}

// --- Built-in patterns ---

const PATTERNS: readonly SanitizationPattern[] = [
  // exec patterns
  {
    name: "shell_metachar",
    pattern: /[;|&`]|\$\(|>>?/,
    severity: "critical",
    description: "Shell metacharacter detected (command injection risk)",
    categories: new Set(["exec"]),
  },
  {
    name: "env_expansion",
    pattern: /\$\{?\w+\}?/,
    severity: "high",
    description: "Environment variable expansion detected",
    categories: new Set(["exec"]),
  },
  // fs patterns (write + read)
  {
    name: "path_traversal",
    pattern: /\.\.[/\\]/,
    severity: "critical",
    description: "Path traversal sequence detected",
    categories: new Set(["fs_write", "fs_read"]),
  },
  {
    name: "null_byte",
    pattern: /\0/,
    severity: "critical",
    description: "Null byte in path detected",
    categories: new Set(["fs_write", "fs_read"]),
  },
  {
    name: "absolute_path",
    pattern: /^\/(?:etc|proc|sys|dev|boot|root)\b|^[A-Za-z]:\\/,
    severity: "medium",
    description: "Sensitive absolute path detected",
    categories: new Set(["fs_write", "fs_read"]),
  },
  {
    name: "home_dir_expansion",
    pattern: /^~\//,
    severity: "medium",
    description: "Home directory expansion detected",
    categories: new Set(["fs_write", "fs_read"]),
  },
  // browser/send patterns
  {
    name: "internal_network_url",
    pattern:
      /(?:\/\/|@)(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|localhost|\[?::1\]?)/i,
    severity: "high",
    description: "Internal/private network URL detected (SSRF risk)",
    categories: new Set(["browser", "send"]),
  },
  {
    name: "dangerous_scheme",
    pattern: /^(?:javascript|data|vbscript):/i,
    severity: "critical",
    description: "Dangerous URL scheme detected",
    categories: new Set(["browser", "send"]),
  },
  {
    name: "insecure_scheme",
    pattern: /^http:\/\//i,
    severity: "medium",
    description: "Insecure HTTP scheme detected (use HTTPS)",
    categories: new Set(["browser", "send"]),
  },
];

// --- String extraction ---

function extractStrings(obj: unknown): string[] {
  const strings: string[] = [];

  function walk(value: unknown): void {
    if (typeof value === "string") {
      strings.push(value);
    } else if (Array.isArray(value)) {
      for (const item of value) {
        walk(item);
      }
    } else if (value !== null && typeof value === "object") {
      for (const key of Object.keys(value as Record<string, unknown>)) {
        walk((value as Record<string, unknown>)[key]);
      }
    }
  }

  walk(obj);
  return strings;
}

function truncate(value: string, maxLength = 100): string {
  if (value.length <= maxLength) return value;
  return value.slice(0, maxLength);
}

// --- Factory ---

export function createArgumentSanitizer(): ArgumentSanitizer {
  function sanitize(
    categoryName: ToolCategoryName,
    parameters: Record<string, unknown>,
  ): SanitizationResult {
    const findings: SanitizationFinding[] = [];
    const strings = extractStrings(parameters);

    // Get applicable patterns for this category
    const applicablePatterns = PATTERNS.filter((p) => p.categories.has(categoryName));

    for (const str of strings) {
      for (const pat of applicablePatterns) {
        if (pat.pattern.test(str)) {
          findings.push({
            pattern_name: pat.name,
            severity: pat.severity,
            matched_value: truncate(str),
            description: pat.description,
          });
        }
      }
    }

    const hasCritical = findings.some((f) => f.severity === "critical");

    return Object.freeze({
      safe: !hasCritical,
      findings,
    });
  }

  return { sanitize };
}
