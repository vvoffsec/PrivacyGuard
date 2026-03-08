import { createHmac, timingSafeEqual } from "node:crypto";
import type { CapabilityToken } from "./types.js";

export interface SigningKeyProvider {
  getKey(): string;
}

export function createStaticKeyProvider(key: string): SigningKeyProvider {
  if (!key) {
    throw new Error("Signing key must not be empty");
  }
  return { getKey: () => key };
}

/**
 * Recursively sort object keys for deterministic JSON serialization.
 * Arrays preserve order; primitives pass through.
 */
function canonicalize(value: unknown): unknown {
  if (value === null || value === undefined) {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }
  if (typeof value === "object") {
    const sorted: Record<string, unknown> = {};
    const keys = Object.keys(value as Record<string, unknown>).sort();
    for (const key of keys) {
      sorted[key] = canonicalize((value as Record<string, unknown>)[key]);
    }
    return sorted;
  }
  return value;
}

/**
 * Compute the fields to sign — everything except `signature`.
 */
function signingPayload(token: CapabilityToken | Omit<CapabilityToken, "signature">): string {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { signature: _sig, ...rest } = token as Record<string, unknown>;
  return JSON.stringify(canonicalize(rest));
}

export function computeTokenSignature(
  token: Omit<CapabilityToken, "signature">,
  keyProvider: SigningKeyProvider,
): string {
  const payload = signingPayload(token);
  const hex = createHmac("sha256", keyProvider.getKey())
    .update(payload, "utf8")
    .digest("hex");
  return `hmac-sha256:${hex}`;
}

export function verifyTokenSignature(
  token: CapabilityToken,
  keyProvider: SigningKeyProvider,
): boolean {
  const expected = computeTokenSignature(token, keyProvider);
  // Timing-safe comparison
  const a = Buffer.from(expected, "utf8");
  const b = Buffer.from(token.signature, "utf8");
  if (a.length !== b.length) {
    return false;
  }
  return timingSafeEqual(a, b);
}
