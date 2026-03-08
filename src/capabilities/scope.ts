import { isAtLeast } from "../data-model/index.js";
import { MEMORY_TIER_ORDER, type CapabilityToken, type ScopeCheckRequest, type ScopeCheckResult } from "./types.js";

export function checkScope(token: CapabilityToken, request: ScopeCheckRequest): ScopeCheckResult {
  const denialReasons: string[] = [];

  // Tool check
  if (request.tool !== undefined) {
    if (token.allowed_tools.length > 0 && !token.allowed_tools.includes(request.tool)) {
      denialReasons.push(`Tool "${request.tool}" is not in allowed_tools`);
    }
  }

  // Destination check
  if (request.destination !== undefined) {
    if (
      token.allowed_destinations.length > 0 &&
      !token.allowed_destinations.includes(request.destination)
    ) {
      denialReasons.push(`Destination "${request.destination}" is not in allowed_destinations`);
    }
  }

  // Data class check — request data_class must not exceed token's max
  if (request.data_class !== undefined) {
    if (!isAtLeast(token.max_data_class, request.data_class)) {
      denialReasons.push(
        `Data class "${request.data_class}" exceeds max_data_class "${token.max_data_class}"`,
      );
    }
  }

  // Memory tier check — requested tier must not exceed token's tier
  if (request.memory_tier !== undefined) {
    if (MEMORY_TIER_ORDER[request.memory_tier] > MEMORY_TIER_ORDER[token.memory_tier]) {
      denialReasons.push(
        `Memory tier "${request.memory_tier}" exceeds allowed tier "${token.memory_tier}"`,
      );
    }
  }

  return Object.freeze({
    allowed: denialReasons.length === 0,
    denial_reasons: denialReasons,
  });
}
