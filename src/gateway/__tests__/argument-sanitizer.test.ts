import { describe, it, expect } from "vitest";
import { createArgumentSanitizer } from "../argument-sanitizer.js";
import type { SanitizationResult, ToolCategoryName } from "../types.js";

describe("ArgumentSanitizer", () => {
  const sanitizer = createArgumentSanitizer();

  // Helper to call sanitize with a single string value
  function sanitizeString(category: ToolCategoryName, value: string): SanitizationResult {
    return sanitizer.sanitize(category, { arg: value });
  }

  // ─── exec category ───────────────────────────────────────────────

  describe("exec category", () => {
    it("clean command is safe with no findings", () => {
      const result = sanitizeString("exec", "ls -la /tmp");
      expect(result.safe).toBe(true);
      expect(result.findings).toHaveLength(0);
    });

    it("detects semicolon as shell_metachar", () => {
      const result = sanitizeString("exec", "echo hello; rm -rf /");
      expect(result.safe).toBe(false);
      const finding = result.findings.find((f) => f.pattern_name === "shell_metachar");
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("detects pipe as shell_metachar", () => {
      const result = sanitizeString("exec", "cat file | grep secret");
      expect(result.safe).toBe(false);
      expect(result.findings.some((f) => f.pattern_name === "shell_metachar")).toBe(true);
    });

    it("detects && as shell_metachar", () => {
      const result = sanitizeString("exec", "cmd1 && cmd2");
      expect(result.safe).toBe(false);
      expect(result.findings.some((f) => f.pattern_name === "shell_metachar")).toBe(true);
    });

    it("detects || as shell_metachar", () => {
      const result = sanitizeString("exec", "cmd1 || cmd2");
      expect(result.safe).toBe(false);
      expect(result.findings.some((f) => f.pattern_name === "shell_metachar")).toBe(true);
    });

    it("detects backtick as shell_metachar", () => {
      const result = sanitizeString("exec", "echo `whoami`");
      expect(result.safe).toBe(false);
      expect(result.findings.some((f) => f.pattern_name === "shell_metachar")).toBe(true);
    });

    it("detects $() as shell_metachar", () => {
      const result = sanitizeString("exec", "echo $(whoami)");
      expect(result.safe).toBe(false);
      expect(result.findings.some((f) => f.pattern_name === "shell_metachar")).toBe(true);
    });

    it("detects > redirect as shell_metachar", () => {
      const result = sanitizeString("exec", "echo data > /etc/passwd");
      expect(result.safe).toBe(false);
      expect(result.findings.some((f) => f.pattern_name === "shell_metachar")).toBe(true);
    });

    it("detects >> append redirect as shell_metachar", () => {
      const result = sanitizeString("exec", "echo data >> /tmp/log");
      expect(result.safe).toBe(false);
      expect(result.findings.some((f) => f.pattern_name === "shell_metachar")).toBe(true);
    });

    it("detects $VAR as env_expansion", () => {
      const result = sanitizeString("exec", "echo $HOME");
      const finding = result.findings.find((f) => f.pattern_name === "env_expansion");
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("high");
    });

    it("detects ${VAR} as env_expansion", () => {
      const result = sanitizeString("exec", "echo ${SECRET_KEY}");
      const finding = result.findings.find((f) => f.pattern_name === "env_expansion");
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("high");
    });

    it("env_expansion (high) alone keeps safe=true", () => {
      const result = sanitizeString("exec", "echo $HOME");
      // env_expansion is high, not critical, so safe should be true
      expect(result.safe).toBe(true);
      expect(result.findings.length).toBeGreaterThan(0);
    });

    it("detects both shell_metachar and env_expansion in same input", () => {
      const result = sanitizeString("exec", "echo $HOME; rm -rf /");
      const names = result.findings.map((f) => f.pattern_name);
      expect(names).toContain("shell_metachar");
      expect(names).toContain("env_expansion");
      expect(result.safe).toBe(false);
    });
  });

  // ─── fs_write category ───────────────────────────────────────────

  describe("fs_write category", () => {
    it("clean path is safe", () => {
      const result = sanitizeString("fs_write", "docs/readme.txt");
      expect(result.safe).toBe(true);
      expect(result.findings).toHaveLength(0);
    });

    it("detects ../ path traversal", () => {
      const result = sanitizeString("fs_write", "../../etc/passwd");
      expect(result.safe).toBe(false);
      const finding = result.findings.find((f) => f.pattern_name === "path_traversal");
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("detects ..\\ path traversal (Windows)", () => {
      const result = sanitizeString("fs_write", "..\\..\\windows\\system32");
      expect(result.safe).toBe(false);
      expect(result.findings.some((f) => f.pattern_name === "path_traversal")).toBe(true);
    });

    it("detects null byte in path", () => {
      const result = sanitizeString("fs_write", "file.txt\0.jpg");
      expect(result.safe).toBe(false);
      const finding = result.findings.find((f) => f.pattern_name === "null_byte");
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("detects /etc/passwd as absolute_path", () => {
      const result = sanitizeString("fs_write", "/etc/passwd");
      const finding = result.findings.find((f) => f.pattern_name === "absolute_path");
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("medium");
    });

    it("detects C:\\ drive as absolute_path", () => {
      const result = sanitizeString("fs_write", "C:\\Windows\\System32");
      const finding = result.findings.find((f) => f.pattern_name === "absolute_path");
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("medium");
    });

    it("absolute_path (medium) keeps safe=true", () => {
      const result = sanitizeString("fs_write", "/etc/passwd");
      expect(result.safe).toBe(true);
    });

    it("detects ~/ as home_dir_expansion", () => {
      const result = sanitizeString("fs_write", "~/.ssh/id_rsa");
      const finding = result.findings.find(
        (f) => f.pattern_name === "home_dir_expansion",
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("medium");
    });

    it("home_dir_expansion (medium) keeps safe=true", () => {
      const result = sanitizeString("fs_write", "~/.bashrc");
      expect(result.safe).toBe(true);
    });
  });

  // ─── fs_read category ────────────────────────────────────────────

  describe("fs_read category", () => {
    it("clean path is safe", () => {
      const result = sanitizeString("fs_read", "src/index.ts");
      expect(result.safe).toBe(true);
      expect(result.findings).toHaveLength(0);
    });

    it("detects path traversal", () => {
      const result = sanitizeString("fs_read", "../../../etc/shadow");
      expect(result.safe).toBe(false);
      expect(result.findings.some((f) => f.pattern_name === "path_traversal")).toBe(true);
    });

    it("detects null byte", () => {
      const result = sanitizeString("fs_read", "data\0bypass");
      expect(result.safe).toBe(false);
      expect(result.findings.some((f) => f.pattern_name === "null_byte")).toBe(true);
    });

    it("detects sensitive absolute paths", () => {
      const result = sanitizeString("fs_read", "/proc/self/environ");
      expect(result.findings.some((f) => f.pattern_name === "absolute_path")).toBe(true);
    });

    it("detects home dir expansion", () => {
      const result = sanitizeString("fs_read", "~/.aws/credentials");
      expect(result.findings.some((f) => f.pattern_name === "home_dir_expansion")).toBe(
        true,
      );
    });
  });

  // ─── browser category ────────────────────────────────────────────

  describe("browser category", () => {
    it("clean HTTPS URL is safe", () => {
      const result = sanitizeString("browser", "https://example.com/page");
      expect(result.safe).toBe(true);
      expect(result.findings).toHaveLength(0);
    });

    it("detects 127.x.x.x as internal_network_url", () => {
      const result = sanitizeString("browser", "https://127.0.0.1/admin");
      const finding = result.findings.find(
        (f) => f.pattern_name === "internal_network_url",
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("high");
    });

    it("detects 10.x.x.x as internal_network_url", () => {
      const result = sanitizeString("browser", "https://10.0.0.5/secret");
      expect(result.findings.some((f) => f.pattern_name === "internal_network_url")).toBe(
        true,
      );
    });

    it("detects 192.168.x.x as internal_network_url", () => {
      const result = sanitizeString("browser", "https://192.168.1.1/router");
      expect(result.findings.some((f) => f.pattern_name === "internal_network_url")).toBe(
        true,
      );
    });

    it("detects localhost as internal_network_url", () => {
      const result = sanitizeString("browser", "http://localhost:8080/api");
      expect(result.findings.some((f) => f.pattern_name === "internal_network_url")).toBe(
        true,
      );
    });

    it("detects ::1 as internal_network_url", () => {
      const result = sanitizeString("browser", "http://[::1]:3000/");
      expect(result.findings.some((f) => f.pattern_name === "internal_network_url")).toBe(
        true,
      );
    });

    it("internal_network_url (high) keeps safe=true", () => {
      const result = sanitizeString("browser", "https://127.0.0.1/admin");
      expect(result.safe).toBe(true);
    });

    it("detects javascript: as dangerous_scheme", () => {
      const result = sanitizeString("browser", "javascript:alert(1)");
      expect(result.safe).toBe(false);
      const finding = result.findings.find((f) => f.pattern_name === "dangerous_scheme");
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("detects data: as dangerous_scheme", () => {
      const result = sanitizeString(
        "browser",
        "data:text/html,<script>alert(1)</script>",
      );
      expect(result.safe).toBe(false);
      expect(result.findings.some((f) => f.pattern_name === "dangerous_scheme")).toBe(
        true,
      );
    });

    it("detects http: as insecure_scheme", () => {
      const result = sanitizeString("browser", "http://example.com/api");
      const finding = result.findings.find((f) => f.pattern_name === "insecure_scheme");
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("medium");
    });

    it("insecure_scheme (medium) keeps safe=true", () => {
      const result = sanitizeString("browser", "http://example.com/page");
      expect(result.safe).toBe(true);
    });
  });

  // ─── send category ───────────────────────────────────────────────

  describe("send category", () => {
    it("clean HTTPS URL is safe", () => {
      const result = sanitizeString("send", "https://api.example.com/hook");
      expect(result.safe).toBe(true);
      expect(result.findings).toHaveLength(0);
    });

    it("detects internal network URL", () => {
      const result = sanitizeString("send", "https://192.168.0.1/internal");
      expect(result.findings.some((f) => f.pattern_name === "internal_network_url")).toBe(
        true,
      );
    });

    it("detects dangerous scheme", () => {
      const result = sanitizeString("send", "javascript:void(0)");
      expect(result.safe).toBe(false);
      expect(result.findings.some((f) => f.pattern_name === "dangerous_scheme")).toBe(
        true,
      );
    });

    it("detects insecure HTTP", () => {
      const result = sanitizeString("send", "http://webhook.example.com");
      expect(result.findings.some((f) => f.pattern_name === "insecure_scheme")).toBe(
        true,
      );
    });
  });

  // ─── Cross-cutting: category isolation ────────────────────────────

  describe("category isolation", () => {
    it("exec patterns do not trigger on fs_read", () => {
      const result = sanitizeString("fs_read", "echo hello; rm -rf /");
      expect(result.findings.some((f) => f.pattern_name === "shell_metachar")).toBe(
        false,
      );
      expect(result.findings.some((f) => f.pattern_name === "env_expansion")).toBe(false);
    });

    it("fs patterns do not trigger on exec", () => {
      const result = sanitizeString("exec", "../../etc/passwd");
      expect(result.findings.some((f) => f.pattern_name === "path_traversal")).toBe(
        false,
      );
      expect(result.findings.some((f) => f.pattern_name === "absolute_path")).toBe(false);
    });

    it("browser patterns do not trigger on exec", () => {
      const result = sanitizeString("exec", "javascript:alert(1)");
      expect(result.findings.some((f) => f.pattern_name === "dangerous_scheme")).toBe(
        false,
      );
      expect(result.findings.some((f) => f.pattern_name === "internal_network_url")).toBe(
        false,
      );
    });

    it("exec patterns do not trigger on browser", () => {
      const result = sanitizeString("browser", "echo $HOME; cat /etc/passwd");
      expect(result.findings.some((f) => f.pattern_name === "shell_metachar")).toBe(
        false,
      );
      expect(result.findings.some((f) => f.pattern_name === "env_expansion")).toBe(false);
    });

    it("fs patterns do not trigger on browser", () => {
      const result = sanitizeString("browser", "../../etc/passwd");
      expect(result.findings.some((f) => f.pattern_name === "path_traversal")).toBe(
        false,
      );
    });
  });

  // ─── Cross-cutting: nested values, truncation, accumulation ──────

  describe("nested parameter extraction", () => {
    it("checks nested object values", () => {
      const result = sanitizer.sanitize("exec", {
        command: { inner: { deep: "echo hello; rm -rf /" } },
      });
      expect(result.safe).toBe(false);
      expect(result.findings.some((f) => f.pattern_name === "shell_metachar")).toBe(true);
    });

    it("checks values inside arrays", () => {
      const result = sanitizer.sanitize("exec", {
        args: ["safe", "echo `whoami`"],
      });
      expect(result.safe).toBe(false);
      expect(result.findings.some((f) => f.pattern_name === "shell_metachar")).toBe(true);
    });

    it("checks deeply nested array-of-objects", () => {
      const result = sanitizer.sanitize("fs_write", {
        files: [{ path: "../../secret" }],
      });
      expect(result.safe).toBe(false);
      expect(result.findings.some((f) => f.pattern_name === "path_traversal")).toBe(true);
    });
  });

  describe("matched value truncation", () => {
    it("truncates matched values to 100 characters", () => {
      const longValue = ";" + "A".repeat(200);
      const result = sanitizeString("exec", longValue);
      expect(result.findings.length).toBeGreaterThan(0);
      for (const finding of result.findings) {
        expect(finding.matched_value.length).toBeLessThanOrEqual(100);
      }
    });

    it("preserves short matched values intact", () => {
      const shortValue = "echo; hello";
      const result = sanitizeString("exec", shortValue);
      const finding = result.findings.find((f) => f.pattern_name === "shell_metachar");
      expect(finding).toBeDefined();
      expect(finding?.matched_value).toBe(shortValue);
    });
  });

  describe("safe flag semantics", () => {
    it("safe=false only when critical findings are present", () => {
      // medium finding only → safe
      const mediumResult = sanitizeString("fs_read", "/etc/passwd");
      expect(mediumResult.findings.some((f) => f.severity === "medium")).toBe(true);
      expect(mediumResult.findings.some((f) => f.severity === "critical")).toBe(false);
      expect(mediumResult.safe).toBe(true);

      // high finding only → safe
      const highResult = sanitizeString("exec", "echo $PATH");
      expect(highResult.findings.some((f) => f.severity === "high")).toBe(true);
      expect(highResult.findings.some((f) => f.severity === "critical")).toBe(false);
      expect(highResult.safe).toBe(true);

      // critical finding → unsafe
      const criticalResult = sanitizeString("exec", "cmd; rm -rf /");
      expect(criticalResult.findings.some((f) => f.severity === "critical")).toBe(true);
      expect(criticalResult.safe).toBe(false);
    });
  });

  describe("multiple findings accumulation", () => {
    it("accumulates findings from multiple parameter values", () => {
      const result = sanitizer.sanitize("exec", {
        cmd: "echo; whoami",
        extra: "cat | grep",
      });
      // Both values should generate shell_metachar findings
      expect(
        result.findings.filter((f) => f.pattern_name === "shell_metachar").length,
      ).toBe(2);
    });

    it("accumulates findings from different patterns on same value", () => {
      // This value matches shell_metachar (;) and env_expansion ($HOME)
      const result = sanitizeString("exec", "echo $HOME; rm -rf /");
      const names = new Set(result.findings.map((f) => f.pattern_name));
      expect(names.has("shell_metachar")).toBe(true);
      expect(names.has("env_expansion")).toBe(true);
      expect(result.findings.length).toBeGreaterThanOrEqual(2);
    });

    it("accumulates fs findings for path traversal + null byte", () => {
      const result = sanitizeString("fs_write", "../../file\0.txt");
      const names = new Set(result.findings.map((f) => f.pattern_name));
      expect(names.has("path_traversal")).toBe(true);
      expect(names.has("null_byte")).toBe(true);
    });
  });

  // ─── Result object immutability ──────────────────────────────────

  describe("result immutability", () => {
    it("returns a frozen result object", () => {
      const result = sanitizeString("exec", "echo hello");
      expect(Object.isFrozen(result)).toBe(true);
    });
  });
});
