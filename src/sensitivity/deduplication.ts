import type { EntityWithClass } from "./types.js";

/**
 * Deduplicates entities with overlapping spans, keeping the higher-confidence match.
 * Entities are sorted by span start, then by span length (longest first).
 */
export function deduplicateEntities(entities: EntityWithClass[]): EntityWithClass[] {
  if (entities.length <= 1) return entities;

  const sorted = [...entities].sort((a, b) => {
    if (a.span.start !== b.span.start) return a.span.start - b.span.start;
    return b.span.end - b.span.start - (a.span.end - a.span.start);
  });

  const result: EntityWithClass[] = [];
  for (const entity of sorted) {
    const overlapIdx = result.findIndex(
      (existing) =>
        entity.span.start < existing.span.end && entity.span.end > existing.span.start,
    );
    if (overlapIdx < 0) {
      result.push(entity);
    } else if (entity.confidence > result[overlapIdx].confidence) {
      result[overlapIdx] = entity;
    }
  }
  return result;
}
