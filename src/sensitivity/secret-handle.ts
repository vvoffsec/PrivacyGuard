import type { DataClass } from "../data-model/data-class.js";
import type { SecretHandle, SecretHandleRegistry } from "./types.js";

/**
 * Creates a secret handle registry that tracks secret/credential entities
 * without storing raw values. Only stores hashes + metadata.
 */
export function createSecretHandleRegistry(): SecretHandleRegistry {
  const byId = new Map<string, SecretHandle>();
  const byHash = new Map<string, SecretHandle>();

  return {
    register(
      entity_type: string,
      value_hash: string,
      data_class: DataClass,
    ): SecretHandle {
      // Check if already registered by hash
      const existing = byHash.get(value_hash);
      if (existing) return existing;

      // Extract first 8 hex chars from hash (after "sha256:" prefix)
      const hashHex = value_hash.replace(/^sha256:/, "").substring(0, 8);
      const handle_id = `secretref://${entity_type}/${hashHex}`;

      const handle: SecretHandle = {
        handle_id,
        entity_type,
        value_hash,
        data_class,
      };

      byId.set(handle_id, handle);
      byHash.set(value_hash, handle);

      return handle;
    },

    lookup(handle_id: string): SecretHandle | undefined {
      return byId.get(handle_id);
    },

    lookupByHash(value_hash: string): SecretHandle | undefined {
      return byHash.get(value_hash);
    },

    size(): number {
      return byId.size;
    },

    clear(): void {
      byId.clear();
      byHash.clear();
    },
  };
}
