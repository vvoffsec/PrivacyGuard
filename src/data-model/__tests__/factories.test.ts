import { describe, it, expect } from "vitest";
import { validate as uuidValidate, version as uuidVersion } from "uuid";
import {
  createUserEnvelope,
  createLocalFileEnvelope,
  createWebEnvelope,
  createEmailEnvelope,
  createToolOutputEnvelope,
  createMemoryEnvelope,
  createGeneratedEnvelope,
} from "../factories.js";

function expectValidUUIDv4(id: string) {
  expect(uuidValidate(id)).toBe(true);
  expect(uuidVersion(id)).toBe(4);
}

describe("createUserEnvelope", () => {
  it("creates a valid envelope with correct defaults", () => {
    const env = createUserEnvelope();
    expectValidUUIDv4(env.content_id);
    expect(env.source_type).toBe("user_input");
    expect(env.source_trust).toBe("trusted_user");
    expect(env.retention_class).toBe("session");
    expect(env.allowed_destinations).toEqual(["local_only", "approved_remote"]);
    expect(env.taint_flags).toEqual([]);
    expect(env.sensitivity).toEqual(["public"]);
  });
});

describe("createLocalFileEnvelope", () => {
  it("creates a valid envelope with correct defaults", () => {
    const env = createLocalFileEnvelope();
    expectValidUUIDv4(env.content_id);
    expect(env.source_type).toBe("local_file");
    expect(env.source_trust).toBe("trusted_local");
    expect(env.retention_class).toBe("session");
    expect(env.allowed_destinations).toEqual(["local_only", "approved_remote"]);
    expect(env.taint_flags).toEqual([]);
  });
});

describe("createWebEnvelope", () => {
  it("creates a valid envelope with untrusted defaults", () => {
    const env = createWebEnvelope();
    expectValidUUIDv4(env.content_id);
    expect(env.source_type).toBe("web_content");
    expect(env.source_trust).toBe("untrusted_external");
    expect(env.retention_class).toBe("ephemeral");
    expect(env.allowed_destinations).toEqual(["local_only"]);
    expect(env.taint_flags).toContain("untrusted_instruction");
  });
});

describe("createEmailEnvelope", () => {
  it("creates a valid envelope with untrusted defaults", () => {
    const env = createEmailEnvelope();
    expectValidUUIDv4(env.content_id);
    expect(env.source_type).toBe("email_content");
    expect(env.source_trust).toBe("untrusted_external");
    expect(env.retention_class).toBe("ephemeral");
    expect(env.allowed_destinations).toEqual(["local_only"]);
    expect(env.taint_flags).toContain("untrusted_instruction");
  });
});

describe("createToolOutputEnvelope", () => {
  it("creates a valid envelope with correct defaults", () => {
    const env = createToolOutputEnvelope();
    expectValidUUIDv4(env.content_id);
    expect(env.source_type).toBe("tool_output");
    expect(env.source_trust).toBe("untrusted_external");
    expect(env.retention_class).toBe("ephemeral");
    expect(env.allowed_destinations).toEqual(["local_only"]);
    expect(env.taint_flags).toEqual([]);
  });
});

describe("createMemoryEnvelope", () => {
  it("creates envelope with provided source_trust", () => {
    const env = createMemoryEnvelope("trusted_user");
    expectValidUUIDv4(env.content_id);
    expect(env.source_type).toBe("memory_content");
    expect(env.source_trust).toBe("trusted_user");
    expect(env.retention_class).toBe("session");
    expect(env.allowed_destinations).toEqual(["local_only"]);
    expect(env.taint_flags).toEqual([]);
  });

  it("accepts different trust levels", () => {
    const env = createMemoryEnvelope("untrusted_external");
    expect(env.source_trust).toBe("untrusted_external");
    // untrusted_external + session is allowed (only durable is rejected)
    expect(env.retention_class).toBe("session");
  });
});

describe("createGeneratedEnvelope", () => {
  it("creates a valid envelope with correct defaults", () => {
    const env = createGeneratedEnvelope();
    expectValidUUIDv4(env.content_id);
    expect(env.source_type).toBe("generated");
    expect(env.source_trust).toBe("generated_unverified");
    expect(env.retention_class).toBe("ephemeral");
    expect(env.allowed_destinations).toEqual(["local_only"]);
    expect(env.taint_flags).toEqual([]);
  });
});

describe("factory options", () => {
  it("allows overriding sensitivity", () => {
    const env = createUserEnvelope({
      sensitivity: ["pii"],
      taint_flags: ["contains_pii"],
    });
    expect(env.sensitivity).toEqual(["pii"]);
    expect(env.taint_flags).toContain("contains_pii");
  });

  it("allows adding purpose_tags", () => {
    const env = createUserEnvelope({ purpose_tags: ["user_request", "audit"] });
    expect(env.purpose_tags).toEqual(["user_request", "audit"]);
  });

  it("merges default taint_flags with provided ones", () => {
    const env = createWebEnvelope({
      taint_flags: ["prompt_injection_suspected"],
    });
    expect(env.taint_flags).toContain("untrusted_instruction");
    expect(env.taint_flags).toContain("prompt_injection_suspected");
  });

  it("each call generates a unique content_id", () => {
    const env1 = createUserEnvelope();
    const env2 = createUserEnvelope();
    expect(env1.content_id).not.toBe(env2.content_id);
  });
});
