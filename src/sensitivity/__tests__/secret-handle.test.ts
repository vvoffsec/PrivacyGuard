import { describe, it, expect } from "vitest";
import { createSecretHandleRegistry } from "../secret-handle.js";

describe("createSecretHandleRegistry", () => {
  it("registers a secret handle", () => {
    const registry = createSecretHandleRegistry();
    const handle = registry.register(
      "api_key",
      "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
      "secret",
    );
    expect(handle.handle_id).toBe("secretref://api_key/abcdef12");
    expect(handle.entity_type).toBe("api_key");
    expect(handle.data_class).toBe("secret");
    expect(handle.value_hash).toBe(
      "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
    );
  });

  it("returns same handle for duplicate hash", () => {
    const registry = createSecretHandleRegistry();
    const hash =
      "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const h1 = registry.register("api_key", hash, "secret");
    const h2 = registry.register("api_key", hash, "secret");
    expect(h1).toBe(h2);
    expect(registry.size()).toBe(1);
  });

  it("looks up by handle_id", () => {
    const registry = createSecretHandleRegistry();
    const hash =
      "sha256:aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344";
    const handle = registry.register("password", hash, "credential");
    const found = registry.lookup(handle.handle_id);
    expect(found).toBe(handle);
  });

  it("looks up by hash", () => {
    const registry = createSecretHandleRegistry();
    const hash =
      "sha256:deadbeef12345678deadbeef12345678deadbeef12345678deadbeef12345678";
    const handle = registry.register("aws_access_key", hash, "credential");
    const found = registry.lookupByHash(hash);
    expect(found).toBe(handle);
  });

  it("returns undefined for unknown handle_id", () => {
    const registry = createSecretHandleRegistry();
    expect(registry.lookup("secretref://unknown/00000000")).toBeUndefined();
  });

  it("returns undefined for unknown hash", () => {
    const registry = createSecretHandleRegistry();
    expect(
      registry.lookupByHash(
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
      ),
    ).toBeUndefined();
  });

  it("tracks size correctly", () => {
    const registry = createSecretHandleRegistry();
    expect(registry.size()).toBe(0);
    registry.register(
      "a",
      "sha256:1111111111111111111111111111111111111111111111111111111111111111",
      "secret",
    );
    expect(registry.size()).toBe(1);
    registry.register(
      "b",
      "sha256:2222222222222222222222222222222222222222222222222222222222222222",
      "credential",
    );
    expect(registry.size()).toBe(2);
  });

  it("clears all entries", () => {
    const registry = createSecretHandleRegistry();
    registry.register(
      "a",
      "sha256:1111111111111111111111111111111111111111111111111111111111111111",
      "secret",
    );
    registry.register(
      "b",
      "sha256:2222222222222222222222222222222222222222222222222222222222222222",
      "credential",
    );
    registry.clear();
    expect(registry.size()).toBe(0);
  });

  it("generates correct handle_id format", () => {
    const registry = createSecretHandleRegistry();
    const handle = registry.register(
      "oauth_token",
      "sha256:ff00aa11bb22cc33dd44ee55ff00aa11bb22cc33dd44ee55ff00aa11bb22cc33",
      "credential",
    );
    expect(handle.handle_id).toMatch(/^secretref:\/\/[a-z_]+\/[0-9a-f]{8}$/);
  });
});
