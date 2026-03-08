import { CapabilityTokenSchema, type TokenValidationResult } from "./types.js";
import { verifyTokenSignature, type SigningKeyProvider } from "./signing.js";
import type { TokenRevocationRegistry } from "./revocation.js";

export interface TokenValidator {
  validate(token: unknown): TokenValidationResult;
}

export function createTokenValidator(
  keyProvider: SigningKeyProvider,
  revocationRegistry: TokenRevocationRegistry,
): TokenValidator {
  return {
    validate(token: unknown): TokenValidationResult {
      // Schema validation
      const parseResult = CapabilityTokenSchema.safeParse(token);
      if (!parseResult.success) {
        return Object.freeze({
          valid: false,
          token_id: undefined,
          failure_reason: "validation_error" as const,
          failure_message: `Schema validation failed: ${parseResult.error.issues.length} issue(s)`,
        });
      }

      const parsed = parseResult.data;

      // Signature check (before revocation to prevent probing)
      if (!verifyTokenSignature(parsed, keyProvider)) {
        return Object.freeze({
          valid: false,
          token_id: parsed.token_id,
          failure_reason: "invalid_signature" as const,
          failure_message: "Token signature does not match",
        });
      }

      // Revocation check
      if (revocationRegistry.isRevoked(parsed.token_id)) {
        return Object.freeze({
          valid: false,
          token_id: parsed.token_id,
          failure_reason: "revoked" as const,
          failure_message: "Token has been revoked",
        });
      }

      // Expiry check
      if (new Date(parsed.expires_at) <= new Date()) {
        return Object.freeze({
          valid: false,
          token_id: parsed.token_id,
          failure_reason: "expired" as const,
          failure_message: `Token expired at ${parsed.expires_at}`,
        });
      }

      // If all checks pass
      return Object.freeze({
        valid: true,
        token_id: parsed.token_id,
      });
    },
  };
}
