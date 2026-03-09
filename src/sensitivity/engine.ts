import { sha256Hash } from "../shared/crypto.js";
import type { DataClass } from "../data-model/data-class.js";
import type { DetectedEntity } from "../data-model/entity.js";
import type { z } from "zod";
import type { TaintFlagSchema } from "../data-model/envelope.js";
import { computeConfidence } from "./confidence.js";
import { deduplicateEntities } from "./deduplication.js";
import { createSecretHandleRegistry } from "./secret-handle.js";
import {
  createEmailRecognizer,
  createPhoneRecognizer,
  createSSNRecognizer,
  createCreditCardRecognizer,
  createApiKeyRecognizer,
  createAwsKeyRecognizer,
  createHighEntropyRecognizer,
  createIPv4Recognizer,
  createOAuthTokenRecognizer,
  createPasswordRecognizer,
} from "./recognizers/index.js";
import { SensitivityDetectionError } from "./errors.js";
import type {
  SensitivityEngine,
  SensitivityEngineConfig,
  SensitivityResult,
  PatternRecognizer,
  EntityWithClass,
  SecretHandle,
} from "./types.js";

type TaintFlag = z.infer<typeof TaintFlagSchema>;

function defaultRecognizers(entropyThreshold: number): PatternRecognizer[] {
  return [
    createEmailRecognizer(),
    createPhoneRecognizer(),
    createSSNRecognizer(),
    createCreditCardRecognizer(),
    createApiKeyRecognizer(),
    createAwsKeyRecognizer(),
    createHighEntropyRecognizer(entropyThreshold),
    createIPv4Recognizer(),
    createOAuthTokenRecognizer(),
    createPasswordRecognizer(),
  ];
}

/**
 * Creates a SensitivityEngine with configurable recognizers,
 * confidence scoring, deduplication, and secret handle generation.
 */
export function createSensitivityEngine(
  config?: SensitivityEngineConfig,
): SensitivityEngine {
  const entropyThreshold = config?.entropy_threshold ?? 4.5;
  const generateHandles = config?.generate_secret_handles ?? true;

  let recognizers: PatternRecognizer[];
  if (config?.recognizers) {
    recognizers = config.recognizers;
  } else {
    recognizers = defaultRecognizers(entropyThreshold);
    if (config?.additional_recognizers) {
      recognizers = [...recognizers, ...config.additional_recognizers];
    }
  }

  return {
    scan(content: string): SensitivityResult {
      const rawEntities: EntityWithClass[] = [];

      for (const recognizer of recognizers) {
        let matches;
        try {
          matches = recognizer.detect(content);
        } catch (error) {
          throw new SensitivityDetectionError(`Recognizer "${recognizer.name}" failed`, {
            recognizer: recognizer.name,
            stage: "detection",
            cause: error instanceof Error ? error.message : String(error),
          });
        }

        for (const match of matches) {
          const confidence = computeConfidence(
            recognizer.default_confidence,
            match.signals,
          );
          rawEntities.push({
            type: recognizer.name,
            value_hash: sha256Hash(match.value),
            confidence,
            span: match.span,
            _data_class: recognizer.data_class,
          });
        }
      }

      const deduplicated = deduplicateEntities(rawEntities);

      // Collect data classes
      const dataClassSet = new Set<DataClass>();
      for (const entity of deduplicated) {
        dataClassSet.add(entity._data_class);
      }
      const data_classes = [...dataClassSet];

      // Compute taint flags
      const taint_flags: TaintFlag[] = [];
      const hasPii = deduplicated.some((e) => e._data_class === "pii");
      const hasSecret = deduplicated.some(
        (e) => e._data_class === "secret" || e._data_class === "credential",
      );
      if (hasPii) taint_flags.push("contains_pii");
      if (hasSecret) taint_flags.push("contains_secret");

      // Strip _data_class from entities
      const entities: DetectedEntity[] = deduplicated.map(
        ({ _data_class: _, ...rest }) => rest,
      );

      // Generate secret handles
      let secret_handles: SecretHandle[] | undefined;
      if (generateHandles) {
        const registry = createSecretHandleRegistry();
        for (const entity of deduplicated) {
          if (entity._data_class === "secret" || entity._data_class === "credential") {
            registry.register(entity.type, entity.value_hash, entity._data_class);
          }
        }
        if (registry.size() > 0) {
          secret_handles = [];
          for (const entity of deduplicated) {
            const handle = registry.lookupByHash(entity.value_hash);
            if (handle) {
              secret_handles.push(handle);
            }
          }
        }
      }

      return Object.freeze({
        entities,
        data_classes,
        taint_flags,
        ...(secret_handles ? { secret_handles } : {}),
      });
    },
  };
}
