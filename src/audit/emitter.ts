import type { AuditEvent } from "./types.js";
import { parseAuditEvent } from "./types.js";
import type { AuditStore } from "./store.js";
import type { AuditQueryFilter } from "./query.js";

export interface AuditEmitter {
  emit(event: AuditEvent): void;
  query(filter: AuditQueryFilter): readonly AuditEvent[];
  count(): number;
}

export class DefaultAuditEmitter implements AuditEmitter {
  private readonly store: AuditStore;

  constructor(store: AuditStore) {
    this.store = store;
  }

  emit(event: AuditEvent): void {
    // Re-validate for defense-in-depth; errors propagate (fail-closed)
    const validated = parseAuditEvent(event);
    this.store.append(validated);
  }

  query(filter: AuditQueryFilter): readonly AuditEvent[] {
    return this.store.query(filter);
  }

  count(): number {
    return this.store.count();
  }
}

export class NoOpAuditEmitter implements AuditEmitter {
  emit(_event: AuditEvent): void {
    // silent no-op
  }

  query(_filter: AuditQueryFilter): readonly AuditEvent[] {
    return Object.freeze([]);
  }

  count(): number {
    return 0;
  }
}
