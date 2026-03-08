import type { AuditEvent, EventType } from "./types.js";

export interface AuditQueryFilter {
  event_type?: EventType;
  decision_id?: string;
  actor_id?: string;
  agent_id?: string;
  correlation_id?: string;
  time_from?: string; // inclusive
  time_to?: string; // exclusive
  limit?: number;
}

/**
 * Execute a query against an array of audit events.
 * Filters use AND semantics. Returns a frozen array of matching events.
 */
export function executeQuery(
  events: readonly AuditEvent[],
  filter: AuditQueryFilter,
): readonly AuditEvent[] {
  let results = events.filter((event) => {
    if (filter.event_type && event.event_type !== filter.event_type) return false;

    if (filter.correlation_id && event.correlation_id !== filter.correlation_id)
      return false;

    if (filter.decision_id) {
      const hasDecisionId =
        "decision_id" in event && event.decision_id === filter.decision_id;
      if (!hasDecisionId) return false;
    }

    if (filter.actor_id) {
      if (!("actor_id" in event) || event.actor_id !== filter.actor_id) return false;
    }

    if (filter.agent_id) {
      if (!("agent_id" in event) || event.agent_id !== filter.agent_id) return false;
    }

    if (filter.time_from && event.timestamp < filter.time_from) return false;
    if (filter.time_to && event.timestamp >= filter.time_to) return false;

    return true;
  });

  if (filter.limit !== undefined && filter.limit > 0) {
    results = results.slice(0, filter.limit);
  }

  return Object.freeze([...results]);
}
