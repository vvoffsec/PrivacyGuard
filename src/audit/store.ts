import type { AuditEvent } from "./types.js";
import { parseAuditEvent } from "./types.js";
import type { AuditQueryFilter } from "./query.js";
import { executeQuery } from "./query.js";

export interface AuditStore {
  append(event: AuditEvent): void;
  count(): number;
  all(): readonly AuditEvent[];
  query(filter: AuditQueryFilter): readonly AuditEvent[];
}

export class InMemoryAuditStore implements AuditStore {
  private readonly events: AuditEvent[] = [];

  append(event: AuditEvent): void {
    // Re-validate for defense-in-depth
    const validated = parseAuditEvent(event);
    this.events.push(validated);
  }

  count(): number {
    return this.events.length;
  }

  all(): readonly AuditEvent[] {
    return Object.freeze([...this.events]);
  }

  query(filter: AuditQueryFilter): readonly AuditEvent[] {
    return executeQuery(this.events, filter);
  }
}
