import { IngressPipelineError } from "./errors.js";
import { createContentParser } from "./content-parser.js";
import { createTrustClassifier } from "./trust-classifier.js";
import { createPatternSensitivityEngine } from "./sensitivity-engine.js";
import { createInjectionDetector } from "./injection-detector.js";
import { createEnvelopeAssembler } from "./envelope-assembler.js";
import type {
  IngressPipeline,
  IngressPipelineConfig,
  IngressPipelineResult,
} from "./types.js";

/**
 * Creates an IngressPipeline with a given configuration
 */
export function createIngressPipeline(
  config: IngressPipelineConfig,
): IngressPipeline {
  const {
    contentParser,
    trustClassifier,
    sensitivityEngine,
    injectionDetector,
    envelopeAssembler,
  } = config;

  return {
    evaluate(input, _context): IngressPipelineResult {
      // Parse
      let parsed;
      try {
        parsed = contentParser.parse(input.content, input.metadata);
      } catch (error) {
        throw new IngressPipelineError(
          "Content parsing failed",
          error instanceof Error ? error : new Error(String(error)),
          { stage: "parse" },
        );
      }

      // Classify trust
      let trust;
      try {
        trust = trustClassifier.classify(input.source_type, input.source_trust);
      } catch (error) {
        throw new IngressPipelineError(
          "Trust classification failed",
          error instanceof Error ? error : new Error(String(error)),
          { stage: "classify", content_hash: parsed.content_hash },
        );
      }

      // Sensitivity scan
      let sensitivity;
      try {
        sensitivity = sensitivityEngine.scan(parsed.normalized_text);
      } catch (error) {
        throw new IngressPipelineError(
          "Sensitivity scan failed",
          error instanceof Error ? error : new Error(String(error)),
          {
            stage: "sensitivity",
            content_hash: parsed.content_hash,
            source_type: input.source_type,
          },
        );
      }

      // Injection detection
      let injection;
      try {
        injection = injectionDetector.check(
          parsed.normalized_text,
          trust.source_trust,
        );
      } catch (error) {
        throw new IngressPipelineError(
          "Injection detection failed",
          error instanceof Error ? error : new Error(String(error)),
          {
            stage: "injection",
            content_hash: parsed.content_hash,
            source_type: input.source_type,
          },
        );
      }

      // Assemble envelope
      let assembled;
      try {
        assembled = envelopeAssembler.assemble({
          content: input.content,
          source_type: input.source_type,
          parsed,
          trust,
          sensitivity,
          injection,
          metadata: input.metadata,
        });
      } catch (error) {
        throw new IngressPipelineError(
          "Envelope assembly failed",
          error instanceof Error ? error : new Error(String(error)),
          {
            stage: "assemble",
            content_hash: parsed.content_hash,
            source_type: input.source_type,
          },
        );
      }

      return Object.freeze({
        envelope: assembled.envelope,
        policy_input: assembled.policy_input,
        parsed,
        sensitivity,
        injection,
      });
    },
  };
}

/**
 * Creates an IngressPipeline with default configuration
 */
export function createDefaultIngressPipeline(): IngressPipeline {
  return createIngressPipeline({
    contentParser: createContentParser(),
    trustClassifier: createTrustClassifier(),
    sensitivityEngine: createPatternSensitivityEngine(),
    injectionDetector: createInjectionDetector(),
    envelopeAssembler: createEnvelopeAssembler(),
  });
}
