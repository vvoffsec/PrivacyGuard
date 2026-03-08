import { v4 as uuidv4 } from "uuid";
import type {
  EventType,
  DecisionEvent,
  ApprovalEvent,
  ToolEvent,
  MemoryEvent,
  EgressEvent,
  IntegrityEvent,
} from "./types.js";
import { parseAuditEvent } from "./types.js";

interface BaseOptions {
  correlation_id?: string;
}

function buildBaseFields(event_type: EventType, opts: BaseOptions) {
  return {
    event_id: uuidv4(),
    event_type,
    timestamp: new Date().toISOString(),
    ...(opts.correlation_id ? { correlation_id: opts.correlation_id } : {}),
  };
}

export function createDecisionEvent(
  input: Omit<
    DecisionEvent,
    "event_id" | "event_type" | "timestamp" | "correlation_id" | "input_hashes"
  > &
    BaseOptions & { input_hashes?: string[] },
): DecisionEvent {
  const { correlation_id, ...fields } = input;
  return parseAuditEvent({
    ...buildBaseFields("decision", { correlation_id }),
    ...fields,
  }) as DecisionEvent;
}

export function createApprovalEvent(
  input: Omit<ApprovalEvent, "event_id" | "event_type" | "timestamp" | "correlation_id"> &
    BaseOptions,
): ApprovalEvent {
  const { correlation_id, ...fields } = input;
  return parseAuditEvent({
    ...buildBaseFields("approval", { correlation_id }),
    ...fields,
  }) as ApprovalEvent;
}

export function createToolEvent(
  input: Omit<ToolEvent, "event_id" | "event_type" | "timestamp" | "correlation_id"> &
    BaseOptions,
): ToolEvent {
  const { correlation_id, ...fields } = input;
  return parseAuditEvent({
    ...buildBaseFields("tool", { correlation_id }),
    ...fields,
  }) as ToolEvent;
}

export function createMemoryEvent(
  input: Omit<MemoryEvent, "event_id" | "event_type" | "timestamp" | "correlation_id"> &
    BaseOptions,
): MemoryEvent {
  const { correlation_id, ...fields } = input;
  return parseAuditEvent({
    ...buildBaseFields("memory", { correlation_id }),
    ...fields,
  }) as MemoryEvent;
}

export function createEgressEvent(
  input: Omit<
    EgressEvent,
    "event_id" | "event_type" | "timestamp" | "correlation_id" | "classes_detected"
  > &
    BaseOptions & { classes_detected?: string[] },
): EgressEvent {
  const { correlation_id, ...fields } = input;
  return parseAuditEvent({
    ...buildBaseFields("egress", { correlation_id }),
    ...fields,
  }) as EgressEvent;
}

export function createIntegrityEvent(
  input: Omit<
    IntegrityEvent,
    "event_id" | "event_type" | "timestamp" | "correlation_id"
  > &
    BaseOptions,
): IntegrityEvent {
  const { correlation_id, ...fields } = input;
  return parseAuditEvent({
    ...buildBaseFields("integrity", { correlation_id }),
    ...fields,
  }) as IntegrityEvent;
}
