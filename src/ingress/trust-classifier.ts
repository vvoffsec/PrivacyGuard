import type { z } from "zod";
import type {
  SourceTypeSchema,
  SourceTrustSchema,
  TaintFlagSchema,
  RetentionClassSchema,
} from "../data-model/envelope.js";
import type { TrustClassifier, TrustClassification } from "./types.js";

type SourceType = z.infer<typeof SourceTypeSchema>;
type SourceTrust = z.infer<typeof SourceTrustSchema>;
type TaintFlag = z.infer<typeof TaintFlagSchema>;
type RetentionClass = z.infer<typeof RetentionClassSchema>;

interface TrustDefaults {
  source_trust: SourceTrust;
  default_taint_flags: TaintFlag[];
  retention_class: RetentionClass;
}

const DEFAULT_TRUST_MAP: Record<SourceType, TrustDefaults> = {
  user_input: {
    source_trust: "trusted_user",
    default_taint_flags: [],
    retention_class: "session",
  },
  local_file: {
    source_trust: "trusted_local",
    default_taint_flags: [],
    retention_class: "session",
  },
  web_content: {
    source_trust: "untrusted_external",
    default_taint_flags: ["untrusted_instruction"],
    retention_class: "ephemeral",
  },
  email_content: {
    source_trust: "untrusted_external",
    default_taint_flags: ["untrusted_instruction"],
    retention_class: "ephemeral",
  },
  tool_output: {
    source_trust: "untrusted_external",
    default_taint_flags: [],
    retention_class: "ephemeral",
  },
  memory_content: {
    source_trust: "trusted_local", // placeholder, will use provided
    default_taint_flags: [],
    retention_class: "session",
  },
  generated: {
    source_trust: "generated_unverified",
    default_taint_flags: [],
    retention_class: "ephemeral",
  },
};

/**
 * Trust level ordering: higher number = more trusted.
 * Trust escalation prevention: caller trust is only accepted if ≤ default.
 */
const TRUST_ORDER: Record<SourceTrust, number> = {
  untrusted_external: 0,
  generated_unverified: 1,
  trusted_local: 2,
  trusted_user: 3,
};

/**
 * Creates a TrustClassifier instance.
 */
export function createTrustClassifier(): TrustClassifier {
  return {
    classify(
      source_type: SourceType,
      source_trust?: SourceTrust,
    ): TrustClassification {
      const defaults = DEFAULT_TRUST_MAP[source_type];

      let effective_trust: SourceTrust;

      if (source_type === "memory_content") {
        // memory_content is pass-through: use provided trust or fall back to trusted_local
        effective_trust = source_trust ?? "trusted_local";
      } else if (source_trust !== undefined) {
        // Trust escalation prevention: only accept if equal or more restrictive
        const defaultLevel = TRUST_ORDER[defaults.source_trust];
        const callerLevel = TRUST_ORDER[source_trust];
        effective_trust =
          callerLevel <= defaultLevel ? source_trust : defaults.source_trust;
      } else {
        effective_trust = defaults.source_trust;
      }

      return Object.freeze({
        source_trust: effective_trust,
        default_taint_flags: [...defaults.default_taint_flags],
        retention_class: defaults.retention_class,
      });
    },
  };
}
