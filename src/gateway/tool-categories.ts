import type { ToolCategory, ToolCategoryClassifier, ToolCategoryName } from "./types.js";

// --- Built-in category definitions ---

const BUILT_IN_CATEGORIES: ReadonlyMap<ToolCategoryName, ToolCategory> = new Map([
  [
    "exec",
    {
      name: "exec",
      risk_level: "critical",
      default_posture: "require_approval",
      description: "Command/script execution",
    },
  ],
  [
    "fs_write",
    {
      name: "fs_write",
      risk_level: "high",
      default_posture: "require_approval",
      description: "File system write operations",
    },
  ],
  [
    "fs_read",
    {
      name: "fs_read",
      risk_level: "low",
      default_posture: "allow",
      description: "File system read operations",
    },
  ],
  [
    "browser",
    {
      name: "browser",
      risk_level: "high",
      default_posture: "require_approval",
      description: "Browser/HTTP interactions",
    },
  ],
  [
    "send",
    {
      name: "send",
      risk_level: "critical",
      default_posture: "require_approval",
      description: "Outbound message/data sending",
    },
  ],
  [
    "package",
    {
      name: "package",
      risk_level: "high",
      default_posture: "require_approval",
      description: "Package installation/management",
    },
  ],
  [
    "config",
    {
      name: "config",
      risk_level: "high",
      default_posture: "require_approval",
      description: "Configuration modification",
    },
  ],
]);

// --- Default tool-name → category mappings ---

const DEFAULT_EXACT_MAPPINGS: ReadonlyMap<string, ToolCategoryName> = new Map([
  // exec
  ["shell_exec", "exec"],
  ["run_command", "exec"],
  ["execute_script", "exec"],
  ["exec", "exec"],
  ["spawn_process", "exec"],
  // fs_write
  ["write_file", "fs_write"],
  ["create_file", "fs_write"],
  ["delete_file", "fs_write"],
  ["rename_file", "fs_write"],
  ["move_file", "fs_write"],
  ["mkdir", "fs_write"],
  ["rmdir", "fs_write"],
  // fs_read
  ["read_file", "fs_read"],
  ["list_directory", "fs_read"],
  ["stat_file", "fs_read"],
  ["glob_files", "fs_read"],
  // browser
  ["browse_url", "browser"],
  ["fetch_url", "browser"],
  ["http_request", "browser"],
  ["navigate", "browser"],
  // send
  ["send_email", "send"],
  ["send_message", "send"],
  ["post_webhook", "send"],
  ["upload_file", "send"],
  // package
  ["install_package", "package"],
  ["npm_install", "package"],
  ["pip_install", "package"],
  ["update_package", "package"],
  // config
  ["set_config", "config"],
  ["update_config", "config"],
  ["modify_env", "config"],
  ["set_env", "config"],
]);

// --- Default prefix → category mappings (longest prefix wins) ---

const DEFAULT_PREFIX_MAPPINGS: readonly [string, ToolCategoryName][] = [
  ["shell_", "exec"],
  ["exec_", "exec"],
  ["run_", "exec"],
  ["write_", "fs_write"],
  ["delete_", "fs_write"],
  ["create_", "fs_write"],
  ["read_", "fs_read"],
  ["list_", "fs_read"],
  ["browse_", "browser"],
  ["fetch_", "browser"],
  ["http_", "browser"],
  ["send_", "send"],
  ["post_", "send"],
  ["upload_", "send"],
  ["install_", "package"],
  ["npm_", "package"],
  ["pip_", "package"],
  ["config_", "config"],
  ["set_", "config"],
];

export function createToolCategoryClassifier(
  customMappings?: ReadonlyMap<string, ToolCategoryName>,
): ToolCategoryClassifier {
  const exactMappings = new Map<string, ToolCategoryName>(DEFAULT_EXACT_MAPPINGS);

  // Apply custom mappings on top of defaults
  if (customMappings) {
    for (const [tool, category] of customMappings) {
      exactMappings.set(tool, category);
    }
  }

  // Sort prefix mappings by length descending for longest-prefix-wins
  const sortedPrefixes = [...DEFAULT_PREFIX_MAPPINGS].sort(
    (a, b) => b[0].length - a[0].length,
  );

  function classify(toolName: string): ToolCategory | undefined {
    const normalized = toolName.toLowerCase();

    // 1. Exact match
    const exactCategory = exactMappings.get(normalized);
    if (exactCategory !== undefined) {
      return BUILT_IN_CATEGORIES.get(exactCategory);
    }

    // 2. Prefix match (longest wins)
    for (const [prefix, categoryName] of sortedPrefixes) {
      if (normalized.startsWith(prefix)) {
        return BUILT_IN_CATEGORIES.get(categoryName);
      }
    }

    return undefined;
  }

  function registerMapping(toolName: string, categoryName: ToolCategoryName): void {
    exactMappings.set(toolName.toLowerCase(), categoryName);
  }

  return { classify, registerMapping };
}

export function getBuiltInCategory(name: ToolCategoryName): ToolCategory {
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  return BUILT_IN_CATEGORIES.get(name)!;
}

export function getAllCategories(): ReadonlyMap<ToolCategoryName, ToolCategory> {
  return BUILT_IN_CATEGORIES;
}
