import type { ApprovalStore, ApprovalRecord } from "./types.js";
import { parseApprovalRecord } from "./types.js";
import { ApprovalValidationError } from "./errors.js";

/**
 * Creates an in-memory ApprovalStore with TTL-based expiry.
 */
export function createApprovalStore(): ApprovalStore {
  // Primary index: scope_hash → record (for scope-based lookup)
  const byScope = new Map<string, ApprovalRecord>();
  // Secondary index: approval_id → record (for revocation)
  const byId = new Map<string, ApprovalRecord>();

  function isExpired(record: ApprovalRecord): boolean {
    if (!record.expires_at) return false;
    return new Date(record.expires_at).getTime() <= Date.now();
  }

  function markExpired(record: ApprovalRecord): ApprovalRecord {
    const expired = parseApprovalRecord({
      ...record,
      status: "expired",
    });
    byScope.set(record.scope_hash, expired);
    byId.set(record.approval_id, expired);
    return expired;
  }

  return {
    put(record: ApprovalRecord): void {
      const validated = parseApprovalRecord(record);
      if (!validated.scope_hash) {
        throw new ApprovalValidationError("ApprovalRecord must have a scope_hash", {
          stage: "store",
        });
      }
      byScope.set(validated.scope_hash, validated);
      byId.set(validated.approval_id, validated);
    },

    findByScope(scopeHash: string): ApprovalRecord | undefined {
      const record = byScope.get(scopeHash);
      if (!record) return undefined;

      // Auto-mark expired records
      if (record.status === "granted" && isExpired(record)) {
        return markExpired(record);
      }

      // Only return active granted approvals
      if (record.status === "granted") {
        return record;
      }

      return record;
    },

    revoke(approvalId: string): boolean {
      const record = byId.get(approvalId);
      if (!record) return false;

      const revoked = parseApprovalRecord({
        ...record,
        status: "revoked",
      });
      byScope.set(record.scope_hash, revoked);
      byId.set(record.approval_id, revoked);
      return true;
    },

    count(): number {
      return byId.size;
    },
  };
}
