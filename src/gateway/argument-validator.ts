import { z } from "zod";
import type {
  ArgumentValidator,
  ArgumentValidationResult,
  ToolCategoryName,
} from "./types.js";

// --- Per-category argument schemas ---

const execArgsSchema = z
  .object({
    command: z.string().min(1),
    args: z.array(z.string()).optional(),
    cwd: z.string().optional(),
    env: z.record(z.string(), z.string()).optional(),
  })
  .loose();

const fsWriteArgsSchema = z
  .object({
    path: z.string().min(1),
    content: z.string().optional(),
    mode: z.enum(["create", "overwrite", "append", "delete"]).optional(),
  })
  .loose();

const fsReadArgsSchema = z
  .object({
    path: z.string().min(1),
    encoding: z.string().optional(),
  })
  .loose();

const browserArgsSchema = z
  .object({
    url: z.string().optional(),
    action: z.string().optional(),
    data: z.record(z.string(), z.unknown()).optional(),
  })
  .loose();

const sendArgsSchema = z
  .object({
    destination: z.string().min(1),
    payload: z.unknown().optional(),
    method: z.string().optional(),
  })
  .loose();

const packageArgsSchema = z
  .object({
    package_name: z.string().min(1),
    version: z.string().optional(),
    registry: z.string().optional(),
  })
  .loose();

const configArgsSchema = z
  .object({
    key: z.string().min(1),
    value: z.unknown(),
    scope: z.string().optional(),
  })
  .loose();

function getSchemaForCategory(name: ToolCategoryName): z.ZodType | undefined {
  switch (name) {
    case "exec":
      return execArgsSchema;
    case "fs_write":
      return fsWriteArgsSchema;
    case "fs_read":
      return fsReadArgsSchema;
    case "browser":
      return browserArgsSchema;
    case "send":
      return sendArgsSchema;
    case "package":
      return packageArgsSchema;
    case "config":
      return configArgsSchema;
    default:
      return undefined;
  }
}

export function createArgumentValidator(): ArgumentValidator {
  function validate(
    categoryName: ToolCategoryName,
    parameters: Record<string, unknown>,
  ): ArgumentValidationResult {
    const schema = getSchemaForCategory(categoryName);
    if (!schema) {
      return Object.freeze({
        valid: false,
        errors: [`No argument schema for category "${categoryName}"`],
      });
    }

    const result = schema.safeParse(parameters);
    if (result.success) {
      return Object.freeze({ valid: true, errors: [] });
    }

    const errors = result.error.issues.map(
      (issue) => `${issue.path.join(".")}: ${issue.message}`,
    );
    return Object.freeze({ valid: false, errors });
  }

  return { validate };
}
