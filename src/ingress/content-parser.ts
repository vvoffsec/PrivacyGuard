import { sha256Hash } from "../shared/crypto.js";
import { IngressParseError } from "./errors.js";
import type { ContentParser, ContentFormat, ParsedContent } from "./types.js";

/**
 * Detects content format from metadata or content inspection.
 */
function detectFormat(
  content: string,
  metadata?: Record<string, unknown>,
): ContentFormat {
  const rawMime = metadata?.mime_type;
  if (rawMime != null) {
    const mime = typeof rawMime === "string" ? rawMime : "";
    if (mime === "application/json") return "application/json";
    if (mime === "text/html") return "text/html";
    if (mime === "text/markdown") return "text/markdown";
    if (mime === "text/plain") return "text/plain";
    if (mime.startsWith("file/")) return "file/metadata";
  }

  // Auto-detect by content inspection
  const trimmed = content.trim();

  // Try JSON
  if (
    (trimmed.startsWith("{") && trimmed.endsWith("}")) ||
    (trimmed.startsWith("[") && trimmed.endsWith("]"))
  ) {
    try {
      JSON.parse(trimmed);
      return "application/json";
    } catch {
      // not valid JSON, continue
    }
  }

  // Check for HTML tags
  if (/<[a-z][\s\S]*>/i.test(trimmed)) {
    return "text/html";
  }

  return "text/plain";
}

/**
 * Normalizes text content:
 * - Trims leading/trailing whitespace
 * - Normalizes line endings to \n
 * - Collapses >3 consecutive blank lines to 2
 */
function normalizeText(content: string): string {
  let text = content.trim();
  text = text.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  text = text.replace(/\n{4,}/g, "\n\n\n");
  return text;
}

/**
 * Strips HTML tags from content, preserving text.
 */
function stripHtmlTags(html: string): string {
  // Remove HTML comments
  let text = html.replace(/<!--[\s\S]*?-->/g, "");
  // Remove script/style contents
  text = text.replace(/<(script|style)\b[^>]*>[\s\S]*?<\/\1>/gi, "");
  // Remove tags
  text = text.replace(/<[^>]+>/g, " ");
  // Collapse multiple spaces
  text = text.replace(/ {2,}/g, " ");
  return text.trim();
}

/**
 * Creates a ContentParser instance.
 */
export function createContentParser(): ContentParser {
  return {
    parse(content: string, metadata?: Record<string, unknown>): ParsedContent {
      if (content.length === 0) {
        throw new IngressParseError("Content must not be empty");
      }

      const format = detectFormat(content, metadata);
      let normalized_text: string;
      const resultMetadata: Record<string, unknown> = { ...metadata };

      switch (format) {
        case "text/html": {
          resultMetadata.raw_html = content;
          const stripped = stripHtmlTags(content);
          normalized_text = normalizeText(stripped);
          break;
        }
        case "application/json": {
          try {
            const parsed = JSON.parse(content.trim()) as unknown;
            resultMetadata.parsed_json = parsed;
            // Canonical re-serialization for stable hashing
            normalized_text = JSON.stringify(
              parsed,
              Object.keys(parsed as Record<string, unknown>).sort(),
            );
          } catch {
            // Fall back to treating as plain text if parse fails
            normalized_text = normalizeText(content);
          }
          break;
        }
        default:
          normalized_text = normalizeText(content);
      }

      const content_hash = sha256Hash(normalized_text);
      const byte_length = new TextEncoder().encode(content).length;

      return Object.freeze({
        format,
        normalized_text,
        content_hash,
        byte_length,
        metadata: Object.keys(resultMetadata).length > 0 ? resultMetadata : undefined,
      });
    },
  };
}
