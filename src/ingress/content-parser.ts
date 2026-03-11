import { sha256Hash } from "../shared/crypto.js";
import { IngressParseError } from "./errors.js";
import type { ContentParser, ContentFormat, ParsedContent } from "./types.js";
import { JSDOM } from "jsdom";

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
  // Use a DOM parser to robustly remove script/style elements and extract text
  const dom = new JSDOM(html);
  const { document } = dom.window;

  // Remove script and style elements entirely (including their contents)
  document.querySelectorAll("script,style").forEach((el) => el.remove());

  // Get the textual content of the remaining document
  let text = document.body ? document.body.textContent ?? "" : document.textContent ?? "";

  // Normalize whitespace similar to the previous implementation
  text = text.replace(/\s+/g, " ");
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
