import { z } from "zod";

export const EntitySpanSchema = z
  .object({
    start: z.number().int().nonnegative(),
    end: z.number().int().positive(),
  })
  .refine((span) => span.end > span.start, {
    message: "EntitySpan.end must be greater than EntitySpan.start",
  });

export type EntitySpan = z.infer<typeof EntitySpanSchema>;

export const DetectedEntitySchema = z.object({
  type: z.string().min(1),
  value_hash: z.string().regex(/^sha256:[0-9a-f]{64}$/, {
    message: "value_hash must match format sha256:<64 hex chars>",
  }),
  confidence: z.number().min(0).max(1),
  span: EntitySpanSchema,
});

export type DetectedEntity = z.infer<typeof DetectedEntitySchema>;
