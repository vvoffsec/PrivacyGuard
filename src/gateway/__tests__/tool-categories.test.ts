import { describe, it, expect } from "vitest";
import {
  createToolCategoryClassifier,
  getBuiltInCategory,
  getAllCategories,
} from "../tool-categories.js";
import type { ToolCategoryName } from "../types.js";

// ---------------------------------------------------------------------------
// Built-in categories
// ---------------------------------------------------------------------------

describe("Built-in categories", () => {
  it("should define exactly 7 categories", () => {
    const cats = getAllCategories();
    expect(cats.size).toBe(7);
  });

  it.each([
    ["exec", "critical", "require_approval", "Command/script execution"],
    ["fs_write", "high", "require_approval", "File system write operations"],
    ["fs_read", "low", "allow", "File system read operations"],
    ["browser", "high", "require_approval", "Browser/HTTP interactions"],
    ["send", "critical", "require_approval", "Outbound message/data sending"],
    ["package", "high", "require_approval", "Package installation/management"],
    ["config", "high", "require_approval", "Configuration modification"],
  ] as const)(
    "should have category '%s' with risk=%s, posture=%s",
    (name, risk_level, default_posture, description) => {
      const cat = getBuiltInCategory(name);
      expect(cat).toEqual({ name, risk_level, default_posture, description });
    },
  );
});

// ---------------------------------------------------------------------------
// getBuiltInCategory / getAllCategories
// ---------------------------------------------------------------------------

describe("getBuiltInCategory()", () => {
  it("should return the category object for a valid name", () => {
    const cat = getBuiltInCategory("exec");
    expect(cat.name).toBe("exec");
    expect(cat.risk_level).toBe("critical");
  });

  it("should return undefined for an invalid name", () => {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-argument, @typescript-eslint/no-explicit-any
    const cat = getBuiltInCategory("nonexistent" as any);
    expect(cat).toBeUndefined();
  });
});

describe("getAllCategories()", () => {
  it("should return a ReadonlyMap", () => {
    const cats = getAllCategories();
    expect(cats).toBeInstanceOf(Map);
  });

  it("should contain all 7 expected category names", () => {
    const cats = getAllCategories();
    const names = [...cats.keys()];
    expect(names).toEqual(
      expect.arrayContaining([
        "exec",
        "fs_write",
        "fs_read",
        "browser",
        "send",
        "package",
        "config",
      ]),
    );
  });
});

// ---------------------------------------------------------------------------
// Exact match classification
// ---------------------------------------------------------------------------

describe("Exact match classification", () => {
  const classifier = createToolCategoryClassifier();

  it.each([
    ["shell_exec", "exec"],
    ["run_command", "exec"],
    ["execute_script", "exec"],
    ["exec", "exec"],
    ["spawn_process", "exec"],
    ["write_file", "fs_write"],
    ["create_file", "fs_write"],
    ["delete_file", "fs_write"],
    ["read_file", "fs_read"],
    ["list_directory", "fs_read"],
    ["stat_file", "fs_read"],
    ["browse_url", "browser"],
    ["fetch_url", "browser"],
    ["http_request", "browser"],
    ["send_email", "send"],
    ["send_message", "send"],
    ["post_webhook", "send"],
    ["upload_file", "send"],
    ["install_package", "package"],
    ["npm_install", "package"],
    ["pip_install", "package"],
    ["set_config", "config"],
    ["update_config", "config"],
    ["modify_env", "config"],
    ["set_env", "config"],
  ] as const)("should classify '%s' as '%s'", (toolName, expectedCategory) => {
    const result = classifier.classify(toolName);
    expect(result).toBeDefined();
    expect(result?.name).toBe(expectedCategory);
  });
});

// ---------------------------------------------------------------------------
// Prefix fallback matching
// ---------------------------------------------------------------------------

describe("Prefix fallback matching", () => {
  const classifier = createToolCategoryClassifier();

  it.each([
    ["shell_something", "exec"],
    ["exec_arbitrary", "exec"],
    ["run_tests", "exec"],
    ["write_logs", "fs_write"],
    ["delete_temp", "fs_write"],
    ["create_backup", "fs_write"],
    ["read_logs", "fs_read"],
    ["list_users", "fs_read"],
    ["browse_web", "browser"],
    ["fetch_data", "browser"],
    ["http_get", "browser"],
    ["send_notification", "send"],
    ["post_data", "send"],
    ["upload_image", "send"],
    ["install_tool", "package"],
    ["npm_run", "package"],
    ["pip_freeze", "package"],
    ["config_update", "config"],
    ["set_value", "config"],
  ] as const)("should classify '%s' via prefix as '%s'", (toolName, expectedCategory) => {
    const result = classifier.classify(toolName);
    expect(result).toBeDefined();
    expect(result?.name).toBe(expectedCategory);
  });
});

// ---------------------------------------------------------------------------
// Unknown tools
// ---------------------------------------------------------------------------

describe("Unknown tools", () => {
  const classifier = createToolCategoryClassifier();

  it("should return undefined for a completely unknown tool name", () => {
    expect(classifier.classify("foobar_unknown")).toBeUndefined();
  });

  it("should return undefined for an empty-ish tool name", () => {
    expect(classifier.classify("xyz")).toBeUndefined();
  });

  it("should return undefined for a tool name with no matching prefix", () => {
    expect(classifier.classify("analyze_data")).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Custom mappings override defaults
// ---------------------------------------------------------------------------

describe("Custom mappings", () => {
  it("should override a default exact mapping", () => {
    const custom = new Map<string, ToolCategoryName>([
      ["read_file", "fs_write"], // override: read_file now treated as write
    ]);
    const classifier = createToolCategoryClassifier(custom);
    const result = classifier.classify("read_file");
    expect(result).toBeDefined();
    expect(result?.name).toBe("fs_write");
  });

  it("should add a completely new exact mapping", () => {
    const custom = new Map<string, ToolCategoryName>([["my_custom_tool", "exec"]]);
    const classifier = createToolCategoryClassifier(custom);
    const result = classifier.classify("my_custom_tool");
    expect(result).toBeDefined();
    expect(result?.name).toBe("exec");
  });

  it("should not affect other default mappings", () => {
    const custom = new Map<string, ToolCategoryName>([["my_custom_tool", "exec"]]);
    const classifier = createToolCategoryClassifier(custom);
    expect(classifier.classify("write_file")?.name).toBe("fs_write");
    expect(classifier.classify("browse_url")?.name).toBe("browser");
  });
});

// ---------------------------------------------------------------------------
// registerMapping()
// ---------------------------------------------------------------------------

describe("registerMapping()", () => {
  it("should add a new mapping that is subsequently classified", () => {
    const classifier = createToolCategoryClassifier();
    expect(classifier.classify("brand_new_tool")).toBeUndefined();

    classifier.registerMapping("brand_new_tool", "send");
    const result = classifier.classify("brand_new_tool");
    expect(result).toBeDefined();
    expect(result?.name).toBe("send");
  });

  it("should override an existing exact mapping", () => {
    const classifier = createToolCategoryClassifier();
    expect(classifier.classify("shell_exec")?.name).toBe("exec");

    classifier.registerMapping("shell_exec", "config");
    expect(classifier.classify("shell_exec")?.name).toBe("config");
  });

  it("should normalize the tool name to lowercase", () => {
    const classifier = createToolCategoryClassifier();
    classifier.registerMapping("MY_TOOL", "browser");
    expect(classifier.classify("my_tool")?.name).toBe("browser");
  });
});

// ---------------------------------------------------------------------------
// Case-insensitive classification
// ---------------------------------------------------------------------------

describe("Case-insensitive classification", () => {
  const classifier = createToolCategoryClassifier();

  it("should classify uppercase tool names correctly", () => {
    const result = classifier.classify("SHELL_EXEC");
    expect(result).toBeDefined();
    expect(result?.name).toBe("exec");
  });

  it("should classify mixed-case tool names correctly", () => {
    const result = classifier.classify("Write_File");
    expect(result).toBeDefined();
    expect(result?.name).toBe("fs_write");
  });

  it("should apply prefix matching case-insensitively", () => {
    const result = classifier.classify("SEND_Notification");
    expect(result).toBeDefined();
    expect(result?.name).toBe("send");
  });
});
