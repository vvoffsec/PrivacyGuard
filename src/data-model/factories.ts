import { v4 as uuidv4 } from "uuid";
import type { ContentEnvelope } from "./envelope.js";
import { parseEnvelope, type SourceTrustSchema } from "./envelope.js";
import type { z } from "zod";

type SourceTrust = z.infer<typeof SourceTrustSchema>;

interface FactoryOptions {
  sensitivity?: ContentEnvelope["sensitivity"];
  entities?: ContentEnvelope["entities"];
  purpose_tags?: ContentEnvelope["purpose_tags"];
  taint_flags?: ContentEnvelope["taint_flags"];
}

function buildEnvelope(
  source_type: ContentEnvelope["source_type"],
  source_trust: ContentEnvelope["source_trust"],
  retention_class: ContentEnvelope["retention_class"],
  allowed_destinations: ContentEnvelope["allowed_destinations"],
  default_taint_flags: ContentEnvelope["taint_flags"],
  opts: FactoryOptions = {},
): ContentEnvelope {
  return parseEnvelope({
    content_id: uuidv4(),
    source_type,
    source_trust,
    retention_class,
    sensitivity: opts.sensitivity ?? ["public"],
    entities: opts.entities ?? [],
    allowed_destinations,
    purpose_tags: opts.purpose_tags ?? [],
    taint_flags: [
      ...new Set([...default_taint_flags, ...(opts.taint_flags ?? [])]),
    ],
    created_at: new Date().toISOString(),
  });
}

export function createUserEnvelope(opts?: FactoryOptions): ContentEnvelope {
  return buildEnvelope(
    "user_input",
    "trusted_user",
    "session",
    ["local_only", "approved_remote"],
    [],
    opts,
  );
}

export function createLocalFileEnvelope(opts?: FactoryOptions): ContentEnvelope {
  return buildEnvelope(
    "local_file",
    "trusted_local",
    "session",
    ["local_only", "approved_remote"],
    [],
    opts,
  );
}

export function createWebEnvelope(opts?: FactoryOptions): ContentEnvelope {
  return buildEnvelope(
    "web_content",
    "untrusted_external",
    "ephemeral",
    ["local_only"],
    ["untrusted_instruction"],
    opts,
  );
}

export function createEmailEnvelope(opts?: FactoryOptions): ContentEnvelope {
  return buildEnvelope(
    "email_content",
    "untrusted_external",
    "ephemeral",
    ["local_only"],
    ["untrusted_instruction"],
    opts,
  );
}

export function createToolOutputEnvelope(opts?: FactoryOptions): ContentEnvelope {
  return buildEnvelope(
    "tool_output",
    "untrusted_external",
    "ephemeral",
    ["local_only"],
    [],
    opts,
  );
}

export function createMemoryEnvelope(
  source_trust: SourceTrust,
  opts?: FactoryOptions,
): ContentEnvelope {
  return buildEnvelope(
    "memory_content",
    source_trust,
    "session",
    ["local_only"],
    [],
    opts,
  );
}

export function createGeneratedEnvelope(opts?: FactoryOptions): ContentEnvelope {
  return buildEnvelope(
    "generated",
    "generated_unverified",
    "ephemeral",
    ["local_only"],
    [],
    opts,
  );
}
