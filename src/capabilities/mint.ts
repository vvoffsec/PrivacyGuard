import { v4 as uuidv4 } from "uuid";
import type { PolicyDecision } from "../pdp/index.js";
import { TokenMintError } from "./errors.js";
import { computeTokenSignature, type SigningKeyProvider } from "./signing.js";
import { parseMintTokenRequest, type CapabilityToken } from "./types.js";

export interface TokenMinter {
  mint(request: unknown, decision: PolicyDecision): CapabilityToken;
}

export function createTokenMinter(keyProvider: SigningKeyProvider): TokenMinter {
  return {
    mint(request: unknown, decision: PolicyDecision): CapabilityToken {
      const parsed = parseMintTokenRequest(request);

      if (decision.decision !== "allow" && decision.decision !== "allow_with_minimization") {
        throw new TokenMintError(
          `Cannot mint token: PDP decision is "${decision.decision}" (requires "allow" or "allow_with_minimization")`,
        );
      }

      const tokenId = uuidv4();
      const issuedAt = new Date().toISOString();
      const expiresAt = new Date(Date.now() + parsed.ttl * 1000).toISOString();

      const unsigned = {
        token_id: tokenId,
        agent_id: parsed.agent_id,
        task_id: parsed.task_id,
        purpose_tags: parsed.purpose_tags,
        working_set_hash: parsed.working_set_hash,
        allowed_tools: parsed.allowed_tools,
        max_data_class: parsed.max_data_class,
        allowed_destinations: parsed.allowed_destinations,
        memory_tier: parsed.memory_tier,
        approval_state: parsed.approval_state,
        ttl: parsed.ttl,
        issued_at: issuedAt,
        expires_at: expiresAt,
        revoked: false,
        source_decision_id: decision.decision_id,
      };

      const signature = computeTokenSignature(unsigned, keyProvider);

      return Object.freeze({
        ...unsigned,
        signature,
      }) as CapabilityToken;
    },
  };
}
