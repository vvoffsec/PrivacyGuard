import { v4 as uuidv4 } from "uuid";
import { parseEnvelope } from "../data-model/envelope.js";
import type { ContentEnvelope } from "../data-model/envelope.js";
import type { z } from "zod";
import type { TaintFlagSchema, DestinationSchema } from "../data-model/envelope.js";
import type { DataClass } from "../data-model/data-class.js";
import type { PolicyInput } from "../pdp/types.js";
import type { EnvelopeAssembler, EnvelopeAssemblerInput } from "./types.js";

type TaintFlag = z.infer<typeof TaintFlagSchema>;
type Destination = z.infer<typeof DestinationSchema>;

/**
 * De-duplicate an array of strings preserving order
 */
function dedupe<T extends string>(arr: T[]): T[] {
  return [...new Set(arr)];
}

/**
 * Creates an EnvelopeAssembler instance
 */
export function createEnvelopeAssembler(): EnvelopeAssembler {
  return {
    assemble(input: EnvelopeAssemblerInput): {
      envelope: ContentEnvelope;
      policy_input: PolicyInput;
    } {
      const { source_type, trust, sensitivity, injection } = input;

      // Derive sensitivity array: use detected data classes, default to ["public"]
      const sensitivityClasses: DataClass[] =
        sensitivity.data_classes.length > 0 ? [...sensitivity.data_classes] : ["public"];

      // Union taint flags from trust defaults + sensitivity + injection (de-duped)
      const taint_flags: TaintFlag[] = dedupe([
        ...trust.default_taint_flags,
        ...sensitivity.taint_flags,
        ...injection.taint_flags,
      ]);

      // Determine allowed destinations based on trust
      const allowed_destinations: Destination[] =
        trust.source_trust === "untrusted_external"
          ? ["local_only"]
          : ["local_only", "approved_remote"];

      // Build envelope data
      const envelopeData = {
        content_id: uuidv4(),
        source_type,
        source_trust: trust.source_trust,
        retention_class: trust.retention_class,
        sensitivity: sensitivityClasses,
        entities: [...sensitivity.entities],
        allowed_destinations,
        purpose_tags: [] as string[],
        taint_flags,
        created_at: new Date().toISOString(),
      };

      // Validate through parseEnvelope (enforces cross-field rules)
      const envelope = parseEnvelope(envelopeData);

      // Build PolicyInput
      const policy_input: PolicyInput = Object.freeze({
        principal: { type: "agent" as const, id: "system" },
        request: {
          action: "ingress.evaluate",
          purpose: [],
          task_id: "ingress",
        },
        resource: { type: "content", name: source_type },
        data: {
          source_trust: [trust.source_trust],
          sensitivity: sensitivityClasses,
          taint_flags,
        },
        destination: { kind: "local", name: "working_set" },
        environment: { host_class: "workstation", policy_bundle: "default" },
      });

      return { envelope, policy_input };
    },
  };
}
