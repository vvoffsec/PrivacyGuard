import { describe, it, expect } from "vitest";
import { createRevocationRegistry } from "../revocation.js";

describe("createRevocationRegistry", () => {
  it("starts with size 0", () => {
    const registry = createRevocationRegistry();
    expect(registry.size).toBe(0);
  });

  it("revoke adds a token and increases size", () => {
    const registry = createRevocationRegistry();
    registry.revoke("token-1");
    expect(registry.size).toBe(1);
    expect(registry.isRevoked("token-1")).toBe(true);
  });

  it("isRevoked returns false for non-revoked token", () => {
    const registry = createRevocationRegistry();
    expect(registry.isRevoked("unknown-token")).toBe(false);
  });

  it("revoke is idempotent", () => {
    const registry = createRevocationRegistry();
    registry.revoke("token-1");
    registry.revoke("token-1");
    expect(registry.size).toBe(1);
  });

  it("tracks multiple tokens", () => {
    const registry = createRevocationRegistry();
    registry.revoke("token-1");
    registry.revoke("token-2");
    registry.revoke("token-3");
    expect(registry.size).toBe(3);
    expect(registry.isRevoked("token-1")).toBe(true);
    expect(registry.isRevoked("token-2")).toBe(true);
    expect(registry.isRevoked("token-3")).toBe(true);
  });

  it("revokeAll clears all tokens", () => {
    const registry = createRevocationRegistry();
    registry.revoke("token-1");
    registry.revoke("token-2");
    expect(registry.size).toBe(2);

    registry.revokeAll();
    expect(registry.size).toBe(0);
    expect(registry.isRevoked("token-1")).toBe(false);
    expect(registry.isRevoked("token-2")).toBe(false);
  });

  it("can revoke after revokeAll", () => {
    const registry = createRevocationRegistry();
    registry.revoke("token-1");
    registry.revokeAll();
    registry.revoke("token-2");
    expect(registry.size).toBe(1);
    expect(registry.isRevoked("token-1")).toBe(false);
    expect(registry.isRevoked("token-2")).toBe(true);
  });
});
