import { describe, it, expect } from "vitest";
import {
  egressSecretDeny,
  execUntrustedApproval,
  memoryPromotionQuarantine,
} from "../default-policies.js";
import type { PolicyInput } from "../types.js";
import { parsePolicyInput } from "../types.js";

function makeInput(overrides: Record<string, unknown> = {}): PolicyInput {
  return parsePolicyInput({
    principal: { type: "agent", id: "agent-1" },
    request: { action: "read", purpose: [], task_id: "task-1" },
    resource: { type: "file", name: "test.txt" },
    data: { source_trust: [], sensitivity: [], taint_flags: [] },
    destination: { kind: "local", name: "stdout" },
    environment: { host_class: "workstation", policy_bundle: "default" },
    ...overrides,
  });
}

describe("pg.egress.secret.default", () => {
  it("has correct id and effect", () => {
    expect(egressSecretDeny.id).toBe("pg.egress.secret.default");
    expect(egressSecretDeny.effect).toBe("deny");
  });

  it("matches model.remote_prompt with secret sensitivity", () => {
    const input = makeInput({
      request: { action: "model.remote_prompt", purpose: [], task_id: "t1" },
      data: { sensitivity: ["secret"], source_trust: [], taint_flags: [] },
    });
    expect(egressSecretDeny.evaluate(input)).toBe(true);
  });

  it("matches http.send with secret sensitivity", () => {
    const input = makeInput({
      request: { action: "http.send", purpose: [], task_id: "t1" },
      data: { sensitivity: ["secret"], source_trust: [], taint_flags: [] },
    });
    expect(egressSecretDeny.evaluate(input)).toBe(true);
  });

  it("matches message.send with secret sensitivity", () => {
    const input = makeInput({
      request: { action: "message.send", purpose: [], task_id: "t1" },
      data: { sensitivity: ["secret"], source_trust: [], taint_flags: [] },
    });
    expect(egressSecretDeny.evaluate(input)).toBe(true);
  });

  it("matches upload.file with secret sensitivity", () => {
    const input = makeInput({
      request: { action: "upload.file", purpose: [], task_id: "t1" },
      data: { sensitivity: ["secret"], source_trust: [], taint_flags: [] },
    });
    expect(egressSecretDeny.evaluate(input)).toBe(true);
  });

  it("does not match egress action without secret sensitivity", () => {
    const input = makeInput({
      request: { action: "http.send", purpose: [], task_id: "t1" },
      data: { sensitivity: ["public"], source_trust: [], taint_flags: [] },
    });
    expect(egressSecretDeny.evaluate(input)).toBe(false);
  });

  it("does not match non-egress action with secret sensitivity", () => {
    const input = makeInput({
      request: { action: "file.read", purpose: [], task_id: "t1" },
      data: { sensitivity: ["secret"], source_trust: [], taint_flags: [] },
    });
    expect(egressSecretDeny.evaluate(input)).toBe(false);
  });

  it("does not match unrelated action", () => {
    const input = makeInput();
    expect(egressSecretDeny.evaluate(input)).toBe(false);
  });
});

describe("pg.exec.untrusted.content", () => {
  it("has correct id and effect", () => {
    expect(execUntrustedApproval.id).toBe("pg.exec.untrusted.content");
    expect(execUntrustedApproval.effect).toBe("require_approval");
  });

  it("matches tool.exec with untrusted_instruction taint", () => {
    const input = makeInput({
      request: { action: "tool.exec.shell", purpose: [], task_id: "t1" },
      data: { taint_flags: ["untrusted_instruction"], source_trust: [], sensitivity: [] },
    });
    expect(execUntrustedApproval.evaluate(input)).toBe(true);
  });

  it("matches tool.exec.browser with untrusted_instruction", () => {
    const input = makeInput({
      request: { action: "tool.exec.browser", purpose: [], task_id: "t1" },
      data: { taint_flags: ["untrusted_instruction"], source_trust: [], sensitivity: [] },
    });
    expect(execUntrustedApproval.evaluate(input)).toBe(true);
  });

  it("does not match tool.exec without untrusted_instruction", () => {
    const input = makeInput({
      request: { action: "tool.exec.shell", purpose: [], task_id: "t1" },
      data: { taint_flags: [], source_trust: [], sensitivity: [] },
    });
    expect(execUntrustedApproval.evaluate(input)).toBe(false);
  });

  it("does not match non-exec action with untrusted_instruction", () => {
    const input = makeInput({
      request: { action: "file.read", purpose: [], task_id: "t1" },
      data: { taint_flags: ["untrusted_instruction"], source_trust: [], sensitivity: [] },
    });
    expect(execUntrustedApproval.evaluate(input)).toBe(false);
  });

  it("does not match unrelated action", () => {
    const input = makeInput();
    expect(execUntrustedApproval.evaluate(input)).toBe(false);
  });
});

describe("pg.memory.promotion", () => {
  it("has correct id and effect", () => {
    expect(memoryPromotionQuarantine.id).toBe("pg.memory.promotion");
    expect(memoryPromotionQuarantine.effect).toBe("quarantine");
  });

  it("matches memory.write with durable purpose and untrusted_external source", () => {
    const input = makeInput({
      request: { action: "memory.write", purpose: ["durable"], task_id: "t1" },
      data: { source_trust: ["untrusted_external"], sensitivity: [], taint_flags: [] },
    });
    expect(memoryPromotionQuarantine.evaluate(input)).toBe(true);
  });

  it("does not match memory.write without durable purpose", () => {
    const input = makeInput({
      request: { action: "memory.write", purpose: ["ephemeral"], task_id: "t1" },
      data: { source_trust: ["untrusted_external"], sensitivity: [], taint_flags: [] },
    });
    expect(memoryPromotionQuarantine.evaluate(input)).toBe(false);
  });

  it("does not match memory.write with durable but trusted source", () => {
    const input = makeInput({
      request: { action: "memory.write", purpose: ["durable"], task_id: "t1" },
      data: { source_trust: ["trusted_user"], sensitivity: [], taint_flags: [] },
    });
    expect(memoryPromotionQuarantine.evaluate(input)).toBe(false);
  });

  it("does not match non-memory action", () => {
    const input = makeInput({
      request: { action: "file.read", purpose: ["durable"], task_id: "t1" },
      data: { source_trust: ["untrusted_external"], sensitivity: [], taint_flags: [] },
    });
    expect(memoryPromotionQuarantine.evaluate(input)).toBe(false);
  });

  it("does not match unrelated action", () => {
    const input = makeInput();
    expect(memoryPromotionQuarantine.evaluate(input)).toBe(false);
  });
});
