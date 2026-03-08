import type { DecisionStore, StoredDecision } from "./interfaces.js";

export function createInMemoryDecisionStore(maxEntries = 10000): DecisionStore {
  const store = new Map<string, StoredDecision>();

  return Object.freeze({
    get(id: string): StoredDecision | undefined {
      return store.get(id);
    },

    put(decision: StoredDecision): void {
      // LRU eviction: delete oldest entry if at capacity
      if (store.size >= maxEntries && !store.has(decision.decision_id)) {
        const oldest = store.keys().next();
        if (!oldest.done) {
          store.delete(oldest.value);
        }
      }
      store.set(decision.decision_id, Object.freeze({ ...decision }));
    },
  });
}
