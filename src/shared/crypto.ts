import { createHash } from "node:crypto";

/**
 * Returns a self-describing SHA-256 hash of the input value.
 * Format: `sha256:<hex>` to support future algorithm rotation.
 */
export function sha256Hash(value: string): string {
  const hex = createHash("sha256").update(value, "utf8").digest("hex");
  return `sha256:${hex}`;
}
