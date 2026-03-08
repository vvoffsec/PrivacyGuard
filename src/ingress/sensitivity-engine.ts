import { sha256Hash } from "../shared/crypto.js";
import type { DataClass } from "../data-model/data-class.js";
import type { DetectedEntity } from "../data-model/entity.js";
import type { z } from "zod";
import type { TaintFlagSchema } from "../data-model/envelope.js";
import type {
  SensitivityEngine,
  SensitivityResult,
  PatternRecognizer,
} from "./types.js";

type TaintFlag = z.infer<typeof TaintFlagSchema>;

interface Match {
  value: string;
  span: { start: number; end: number };
}

// --- Built-in Pattern Recognizers ---

function execAll(pattern: RegExp, content: string): RegExpExecArray[] {
  const matches: RegExpExecArray[] = [];
  let m;
  while ((m = pattern.exec(content)) !== null) {
    matches.push(m);
  }
  return matches;
}

function createEmailRecognizer(): PatternRecognizer {
  return {
    name: "email",
    data_class: "pii",
    default_confidence: 0.9,
    detect(content: string) {
      return execAll(
        /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
        content,
      ).map((m) => ({
        value: m[0],
        span: { start: m.index, end: m.index + m[0].length },
      }));
    },
  };
}

function createPhoneRecognizer(): PatternRecognizer {
  return {
    name: "phone",
    data_class: "pii",
    default_confidence: 0.7,
    detect(content: string) {
      const results: Match[] = [];
      for (const m of execAll(
        /(?:\+1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b/g,
        content,
      )) {
        const digits = m[0].replace(/\D/g, "");
        if (digits.length >= 10 && digits.length <= 11) {
          results.push({
            value: m[0],
            span: { start: m.index, end: m.index + m[0].length },
          });
        }
      }
      return results;
    },
  };
}

function createSSNRecognizer(): PatternRecognizer {
  return {
    name: "ssn",
    data_class: "pii",
    default_confidence: 0.85,
    detect(content: string) {
      const results: Match[] = [];
      for (const m of execAll(/\b\d{3}-\d{2}-\d{4}\b/g, content)) {
        const area = parseInt(m[0].substring(0, 3), 10);
        if (area !== 0 && area !== 666 && area < 900) {
          results.push({
            value: m[0],
            span: { start: m.index, end: m.index + m[0].length },
          });
        }
      }
      return results;
    },
  };
}

function luhnCheck(digits: string): boolean {
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = parseInt(digits[i], 10);
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

function createCreditCardRecognizer(): PatternRecognizer {
  return {
    name: "credit_card",
    data_class: "pii",
    default_confidence: 0.9,
    detect(content: string) {
      const results: Match[] = [];
      for (const m of execAll(/\b(?:\d[ -]*?){13,19}\b/g, content)) {
        const digits = m[0].replace(/\D/g, "");
        if (digits.length >= 13 && digits.length <= 19 && luhnCheck(digits)) {
          results.push({
            value: m[0],
            span: { start: m.index, end: m.index + m[0].length },
          });
        }
      }
      return results;
    },
  };
}

function createApiKeyRecognizer(): PatternRecognizer {
  return {
    name: "api_key",
    data_class: "secret",
    default_confidence: 0.8,
    detect(content: string) {
      return execAll(
        /\b(?:api[_-]?key|token|secret|password|passwd|api[_-]?secret)\s*[=:]\s*["']?([a-zA-Z0-9_\-./+=]{8,})["']?/gi,
        content,
      ).map((m) => ({
        value: m[0],
        span: { start: m.index, end: m.index + m[0].length },
      }));
    },
  };
}

function createAwsKeyRecognizer(): PatternRecognizer {
  return {
    name: "aws_access_key",
    data_class: "credential",
    default_confidence: 0.95,
    detect(content: string) {
      return execAll(/\bAKIA[0-9A-Z]{16}\b/g, content).map((m) => ({
        value: m[0],
        span: { start: m.index, end: m.index + m[0].length },
      }));
    },
  };
}

function shannonEntropy(str: string): number {
  const freq = new Map<string, number>();
  for (const ch of str) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }
  const len = str.length;
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function createHighEntropyRecognizer(): PatternRecognizer {
  return {
    name: "high_entropy_string",
    data_class: "secret",
    default_confidence: 0.6,
    detect(content: string) {
      const results: Match[] = [];
      for (const m of execAll(
        /\b(?:key|token|secret|password|passwd|api_key|apikey|auth|credential|private_key)\s*[=:]\s*["']?([a-zA-Z0-9_\-./+=]{20,})["']?/gi,
        content,
      )) {
        const valueStr = m[1];
        if (valueStr && shannonEntropy(valueStr) > 4.5) {
          results.push({
            value: m[0],
            span: { start: m.index, end: m.index + m[0].length },
          });
        }
      }
      return results;
    },
  };
}

function createIPv4Recognizer(): PatternRecognizer {
  return {
    name: "ipv4",
    data_class: "internal",
    default_confidence: 0.5,
    detect(content: string) {
      return execAll(
        /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
        content,
      ).map((m) => ({
        value: m[0],
        span: { start: m.index, end: m.index + m[0].length },
      }));
    },
  };
}

// --- Pattern Sensitivity Engine ---

interface PatternSensitivityEngineConfig {
  readonly recognizers?: PatternRecognizer[];
}

type EntityWithClass = DetectedEntity & { _data_class: DataClass };

function deduplicateEntities(entities: EntityWithClass[]): EntityWithClass[] {
  if (entities.length <= 1) return entities;

  const sorted = [...entities].sort((a, b) => {
    if (a.span.start !== b.span.start) return a.span.start - b.span.start;
    return b.span.end - b.span.start - (a.span.end - a.span.start);
  });

  const result: EntityWithClass[] = [];
  for (const entity of sorted) {
    const overlapIdx = result.findIndex(
      (existing) =>
        entity.span.start < existing.span.end &&
        entity.span.end > existing.span.start,
    );
    if (overlapIdx < 0) {
      result.push(entity);
    } else if (entity.confidence > result[overlapIdx].confidence) {
      result[overlapIdx] = entity;
    }
  }
  return result;
}

export function createPatternSensitivityEngine(
  config?: PatternSensitivityEngineConfig,
): SensitivityEngine {
  const recognizers: PatternRecognizer[] = config?.recognizers ?? [
    createEmailRecognizer(),
    createPhoneRecognizer(),
    createSSNRecognizer(),
    createCreditCardRecognizer(),
    createApiKeyRecognizer(),
    createAwsKeyRecognizer(),
    createHighEntropyRecognizer(),
    createIPv4Recognizer(),
  ];

  return {
    scan(content: string): SensitivityResult {
      const rawEntities: EntityWithClass[] = [];

      for (const recognizer of recognizers) {
        const matches = recognizer.detect(content);
        for (const match of matches) {
          rawEntities.push({
            type: recognizer.name,
            value_hash: sha256Hash(match.value),
            confidence: recognizer.default_confidence,
            span: match.span,
            _data_class: recognizer.data_class,
          });
        }
      }

      const deduplicated = deduplicateEntities(rawEntities);

      const dataClassSet = new Set<DataClass>();
      for (const entity of deduplicated) {
        dataClassSet.add(entity._data_class);
      }
      const data_classes = [...dataClassSet];

      const taint_flags: TaintFlag[] = [];
      const hasPii = deduplicated.some((e) => e._data_class === "pii");
      const hasSecret = deduplicated.some(
        (e) => e._data_class === "secret" || e._data_class === "credential",
      );
      if (hasPii) taint_flags.push("contains_pii");
      if (hasSecret) taint_flags.push("contains_secret");

      const entities: DetectedEntity[] = deduplicated.map(
        ({ _data_class: _, ...rest }) => rest,
      );

      return Object.freeze({
        entities,
        data_classes,
        taint_flags,
      });
    },
  };
}
