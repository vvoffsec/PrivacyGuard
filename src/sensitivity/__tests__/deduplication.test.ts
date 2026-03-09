import { describe, it, expect } from "vitest";
import { deduplicateEntities } from "../deduplication.js";
import type { EntityWithClass } from "../types.js";

function makeEntity(
  type: string,
  start: number,
  end: number,
  confidence: number,
  dataClass: "pii" | "secret" | "internal" = "pii",
): EntityWithClass {
  return {
    type,
    value_hash: `sha256:${"0".repeat(64)}`,
    confidence,
    span: { start, end },
    _data_class: dataClass,
  };
}

describe("deduplicateEntities", () => {
  it("returns empty for empty input", () => {
    expect(deduplicateEntities([])).toEqual([]);
  });

  it("returns single entity unchanged", () => {
    const e = [makeEntity("email", 0, 10, 0.9)];
    expect(deduplicateEntities(e)).toHaveLength(1);
  });

  it("keeps non-overlapping entities", () => {
    const entities = [makeEntity("email", 0, 10, 0.9), makeEntity("phone", 20, 30, 0.7)];
    expect(deduplicateEntities(entities)).toHaveLength(2);
  });

  it("removes overlapping entity with lower confidence", () => {
    const entities = [makeEntity("low", 0, 10, 0.3), makeEntity("high", 0, 10, 0.9)];
    const result = deduplicateEntities(entities);
    expect(result).toHaveLength(1);
    expect(result[0].confidence).toBe(0.9);
  });

  it("handles partial overlap", () => {
    const entities = [makeEntity("a", 0, 10, 0.5), makeEntity("b", 5, 15, 0.8)];
    const result = deduplicateEntities(entities);
    expect(result).toHaveLength(1);
    expect(result[0].confidence).toBe(0.8);
  });

  it("handles adjacent non-overlapping entities", () => {
    const entities = [makeEntity("a", 0, 10, 0.5), makeEntity("b", 10, 20, 0.8)];
    expect(deduplicateEntities(entities)).toHaveLength(2);
  });

  it("handles multiple overlapping groups", () => {
    const entities = [
      makeEntity("a", 0, 5, 0.3),
      makeEntity("b", 0, 5, 0.9),
      makeEntity("c", 10, 15, 0.4),
      makeEntity("d", 10, 15, 0.8),
    ];
    const result = deduplicateEntities(entities);
    expect(result).toHaveLength(2);
    expect(result[0].confidence).toBe(0.9);
    expect(result[1].confidence).toBe(0.8);
  });
});
