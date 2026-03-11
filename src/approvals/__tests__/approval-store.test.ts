import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createApprovalStore } from "../approval-store.js";
import type { ApprovalRecord, ApprovalStore } from "../types.js";

// --- Test helpers ---

function makeRecord(overrides: Partial<ApprovalRecord> = {}): ApprovalRecord {
  return {
    approval_id: "550e8400-e29b-41d4-a716-446655440000",
    decision_id: "660e8400-e29b-41d4-a716-446655440000",
    actor_id: "user-1",
    scope: {
      action: "file.write",
      purpose: ["backup"],
      destination: "s3-bucket",
      data_class: "confidential",
    },
    scope_hash: "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
    reason: "Approved for backup task",
    status: "granted",
    created_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 300_000).toISOString(),
    ...overrides,
  } as ApprovalRecord;
}

describe("createApprovalStore", () => {
  let store: ApprovalStore;

  beforeEach(() => {
    store = createApprovalStore();
  });

  // --- put ---

  describe("put", () => {
    it("stores a valid approval record", () => {
      store.put(makeRecord());
      expect(store.count()).toBe(1);
    });

    it("replaces existing record for same scope_hash", () => {
      const record1 = makeRecord({ reason: "first" });
      const record2 = makeRecord({
        approval_id: "770e8400-e29b-41d4-a716-446655440000",
        reason: "second",
      });
      store.put(record1);
      store.put(record2);
      // Two records in byId (different approval_ids), one in byScope
      expect(store.count()).toBe(2);
      const found = store.findByScope(record2.scope_hash);
      expect(found?.reason).toBe("second");
    });

    it("throws for invalid record", () => {
      expect(() => {
        store.put({ invalid: true } as unknown as ApprovalRecord);
      }).toThrow();
    });
  });

  // --- findByScope ---

  describe("findByScope", () => {
    it("returns undefined for unknown scope_hash", () => {
      expect(
        store.findByScope(
          "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        ),
      ).toBeUndefined();
    });

    it("returns granted record for matching scope_hash", () => {
      const record = makeRecord();
      store.put(record);
      const found = store.findByScope(record.scope_hash);
      expect(found).toBeDefined();
      expect(found?.status).toBe("granted");
    });

    it("returns denied record (for re-prompt prevention)", () => {
      const record = makeRecord({ status: "denied" });
      store.put(record);
      const found = store.findByScope(record.scope_hash);
      expect(found?.status).toBe("denied");
    });

    it("returns revoked record", () => {
      const record = makeRecord();
      store.put(record);
      store.revoke(record.approval_id);
      const found = store.findByScope(record.scope_hash);
      expect(found?.status).toBe("revoked");
    });
  });

  // --- TTL expiry ---

  describe("TTL expiry", () => {
    beforeEach(() => {
      vi.useFakeTimers();
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it("auto-marks expired records on findByScope", () => {
      const now = Date.now();
      vi.setSystemTime(now);

      const record = makeRecord({
        expires_at: new Date(now + 1000).toISOString(), // expires in 1 second
      });
      store.put(record);

      // Advance past expiry
      vi.setSystemTime(now + 2000);

      const found = store.findByScope(record.scope_hash);
      expect(found?.status).toBe("expired");
    });

    it("returns granted record that has not expired", () => {
      const now = Date.now();
      vi.setSystemTime(now);

      const record = makeRecord({
        expires_at: new Date(now + 300_000).toISOString(),
      });
      store.put(record);

      // Advance, but not past expiry
      vi.setSystemTime(now + 100_000);

      const found = store.findByScope(record.scope_hash);
      expect(found?.status).toBe("granted");
    });

    it("handles record without expires_at (never expires)", () => {
      const record = makeRecord({ expires_at: undefined });
      store.put(record);

      const found = store.findByScope(record.scope_hash);
      expect(found?.status).toBe("granted");
    });
  });

  // --- revoke ---

  describe("revoke", () => {
    it("sets status to revoked", () => {
      const record = makeRecord();
      store.put(record);
      const result = store.revoke(record.approval_id);
      expect(result).toBe(true);
      const found = store.findByScope(record.scope_hash);
      expect(found?.status).toBe("revoked");
    });

    it("returns false for unknown approval_id", () => {
      const result = store.revoke("550e8400-e29b-41d4-a716-446655440000");
      expect(result).toBe(false);
    });

    it("can revoke an already granted approval", () => {
      const record = makeRecord({ status: "granted" });
      store.put(record);
      store.revoke(record.approval_id);
      const found = store.findByScope(record.scope_hash);
      expect(found?.status).toBe("revoked");
    });
  });

  // --- count ---

  describe("count", () => {
    it("returns 0 for empty store", () => {
      expect(store.count()).toBe(0);
    });

    it("counts all records including expired and revoked", () => {
      store.put(makeRecord());
      store.put(
        makeRecord({
          approval_id: "110e8400-e29b-41d4-a716-446655440000",
          scope_hash:
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
          status: "denied",
        }),
      );
      expect(store.count()).toBe(2);
    });
  });

  // --- Frozen records ---

  describe("frozen records", () => {
    it("returns frozen records from findByScope", () => {
      store.put(makeRecord());
      const found = store.findByScope(
        "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
      );
      expect(found).toBeDefined();
      expect(Object.isFrozen(found)).toBe(true);
    });
  });
});
