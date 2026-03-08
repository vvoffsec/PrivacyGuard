import { z } from "zod";

export const DataClassSchema = z.enum([
  "public",
  "internal",
  "confidential",
  "restricted",
  "pii",
  "secret",
  "credential",
]);

export type DataClass = z.infer<typeof DataClassSchema>;

const DATA_CLASS_ORDER: Record<DataClass, number> = {
  public: 0,
  internal: 1,
  confidential: 2,
  restricted: 3,
  pii: 4,
  secret: 5,
  credential: 5,
};

/**
 * Returns the highest-sensitivity data class from an array.
 * Defaults to "public" if the array is empty.
 */
export function highestDataClass(classes: DataClass[]): DataClass {
  if (classes.length === 0) return "public";

  let highest: DataClass = classes[0];
  for (let i = 1; i < classes.length; i++) {
    if (DATA_CLASS_ORDER[classes[i]] > DATA_CLASS_ORDER[highest]) {
      highest = classes[i];
    }
  }
  return highest;
}

/**
 * Returns true if `candidate` is at least as sensitive as `threshold`.
 */
export function isAtLeast(candidate: DataClass, threshold: DataClass): boolean {
  return DATA_CLASS_ORDER[candidate] >= DATA_CLASS_ORDER[threshold];
}
