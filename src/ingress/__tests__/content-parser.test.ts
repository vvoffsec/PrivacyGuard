import { describe, it, expect } from "vitest";
import { createContentParser } from "../content-parser.js";
import { IngressParseError } from "../errors.js";

describe("createContentParser", () => {
  const parser = createContentParser();

  describe("format detection", () => {
    it("detects text/plain by default", () => {
      const result = parser.parse("Hello, world!");
      expect(result.format).toBe("text/plain");
    });

    it("detects application/json from content", () => {
      const result = parser.parse('{"key": "value"}');
      expect(result.format).toBe("application/json");
    });

    it("detects JSON arrays", () => {
      const result = parser.parse('[1, 2, 3]');
      expect(result.format).toBe("application/json");
    });

    it("detects text/html from content", () => {
      const result = parser.parse("<p>Hello</p>");
      expect(result.format).toBe("text/html");
    });

    it("uses metadata mime_type when provided", () => {
      const result = parser.parse("plain text", {
        mime_type: "text/markdown",
      });
      expect(result.format).toBe("text/markdown");
    });

    it("uses metadata mime_type for application/json", () => {
      const result = parser.parse("not json", {
        mime_type: "application/json",
      });
      expect(result.format).toBe("application/json");
    });

    it("does not detect invalid JSON as application/json", () => {
      const result = parser.parse("{not valid json}");
      expect(result.format).toBe("text/plain");
    });
  });

  describe("text normalization", () => {
    it("trims leading and trailing whitespace", () => {
      const result = parser.parse("  hello  ");
      expect(result.normalized_text).toBe("hello");
    });

    it("normalizes CRLF to LF", () => {
      const result = parser.parse("line1\r\nline2\r\nline3");
      expect(result.normalized_text).toBe("line1\nline2\nline3");
    });

    it("normalizes CR to LF", () => {
      const result = parser.parse("line1\rline2");
      expect(result.normalized_text).toBe("line1\nline2");
    });

    it("collapses >3 consecutive blank lines to 2", () => {
      const result = parser.parse("a\n\n\n\n\nb");
      expect(result.normalized_text).toBe("a\n\n\nb");
    });
  });

  describe("HTML handling", () => {
    it("strips HTML tags and preserves text", () => {
      const result = parser.parse("<p>Hello <b>world</b></p>");
      expect(result.normalized_text).toContain("Hello");
      expect(result.normalized_text).toContain("world");
      expect(result.normalized_text).not.toContain("<p>");
    });

    it("preserves raw HTML in metadata", () => {
      const html = "<p>Hello</p>";
      const result = parser.parse(html);
      expect(result.metadata?.raw_html).toBe(html);
    });

    it("removes HTML comments", () => {
      const result = parser.parse("<p>visible</p><!-- hidden -->");
      expect(result.normalized_text).not.toContain("hidden");
    });
  });

  describe("JSON handling", () => {
    it("canonically re-serializes JSON for stable hashing", () => {
      const result1 = parser.parse('{"b": 2, "a": 1}');
      const result2 = parser.parse('{"a": 1, "b": 2}');
      expect(result1.content_hash).toBe(result2.content_hash);
    });

    it("stores parsed JSON in metadata", () => {
      const result = parser.parse('{"key": "value"}');
      expect(result.metadata?.parsed_json).toEqual({ key: "value" });
    });
  });

  describe("hashing", () => {
    it("produces sha256: prefixed hash", () => {
      const result = parser.parse("test content");
      expect(result.content_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
    });

    it("produces consistent hashes for same content", () => {
      const result1 = parser.parse("same content");
      const result2 = parser.parse("same content");
      expect(result1.content_hash).toBe(result2.content_hash);
    });

    it("produces different hashes for different content", () => {
      const result1 = parser.parse("content A");
      const result2 = parser.parse("content B");
      expect(result1.content_hash).not.toBe(result2.content_hash);
    });
  });

  describe("byte length", () => {
    it("calculates correct byte length for ASCII", () => {
      const result = parser.parse("hello");
      expect(result.byte_length).toBe(5);
    });

    it("calculates correct byte length for multi-byte chars", () => {
      const result = parser.parse("héllo");
      expect(result.byte_length).toBeGreaterThan(5);
    });
  });

  describe("error handling", () => {
    it("throws IngressParseError for empty content", () => {
      expect(() => parser.parse("")).toThrow(IngressParseError);
    });
  });
});
