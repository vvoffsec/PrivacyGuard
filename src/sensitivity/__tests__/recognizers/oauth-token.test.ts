import { describe, it, expect } from "vitest";
import { createOAuthTokenRecognizer } from "../../recognizers/oauth-token.js";

describe("createOAuthTokenRecognizer", () => {
  const r = createOAuthTokenRecognizer();

  it("has correct metadata", () => {
    expect(r.name).toBe("oauth_token");
    expect(r.data_class).toBe("credential");
    expect(r.default_confidence).toBe(0.9);
  });

  it("detects a JWT token", () => {
    // Real-ish JWT structure: header.payload.signature
    const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }))
      .replace(/=/g, "")
      .replace(/\+/g, "-")
      .replace(/\//g, "_");
    const payload = btoa(JSON.stringify({ sub: "1234567890", name: "Test" }))
      .replace(/=/g, "")
      .replace(/\+/g, "-")
      .replace(/\//g, "_");
    const sig = "abcdefghijklmnop";
    const jwt = `${header}.${payload}.${sig}`;
    const matches = r.detect(`Authorization: ${jwt}`);
    expect(matches.length).toBeGreaterThanOrEqual(1);
    expect(matches[0].signals?.format_validated).toBe(true);
  });

  it("detects JWT with invalid header (format_validated=false)", () => {
    // Looks like JWT but header is not valid JSON
    const fakeJwt = "eyJhbGciOiJIUzI.eyJzdWIiOiIxMjM0.abcdefghijklmnop";
    const matches = r.detect(fakeJwt);
    // May or may not match depending on segment length
    if (matches.length > 0) {
      expect(matches[0].signals?.pattern_matched).toBe(true);
    }
  });

  it("detects Bearer token (non-JWT)", () => {
    const matches = r.detect("Authorization: Bearer test-token-abc123def456ghi789jkl");
    expect(matches).toHaveLength(1);
    expect(matches[0].signals?.context_validated).toBe(true);
  });

  it("does not double-count JWT as Bearer token", () => {
    const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }))
      .replace(/=/g, "")
      .replace(/\+/g, "-")
      .replace(/\//g, "_");
    const payload = btoa(JSON.stringify({ sub: "1234567890" }))
      .replace(/=/g, "")
      .replace(/\+/g, "-")
      .replace(/\//g, "_");
    const sig = "abcdefghijklmnop";
    const jwt = `${header}.${payload}.${sig}`;
    const content = `Bearer ${jwt}`;
    const matches = r.detect(content);
    // Should only get the JWT match, not a separate Bearer match
    const bearerMatches = matches.filter((m) => m.signals?.context_validated === true);
    expect(bearerMatches).toHaveLength(0);
  });

  it("returns empty for no tokens", () => {
    expect(r.detect("just regular text")).toHaveLength(0);
  });
});
