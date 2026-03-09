<div align="center">

# PrivacyGuard

**Zero-trust security, privacy, and DLP control plane for AI agent subagents**

[![TypeScript](https://img.shields.io/badge/TypeScript-5.8-3178c6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D20-339933?logo=node.js&logoColor=white)](https://nodejs.org/)
[![Zod](https://img.shields.io/badge/Zod-4-3068b7?logo=zod&logoColor=white)](https://zod.dev/)
[![Vitest](https://img.shields.io/badge/Vitest-4-6E9F18?logo=vitest&logoColor=white)](https://vitest.dev/)
[![License](https://img.shields.io/badge/License-TBD-888888)](#license)

---

*Every subagent launch, tool call, memory write, remote model call, and outbound send must route through PrivacyGuard.*

</div>

## Overview

PrivacyGuard is a **mandatory** security, privacy, and DLP control plane for [OpenClaw](https://github.com/openclaw/openclaw) subagents. It sits between the user and all downstream execution surfaces — subagents, tools, memory, remote destinations — to enforce:

- **Zero-trust mediation** — no implicit trust, every action verified
- **Policy-as-code** — deterministic, auditable decisions via OPA/Cedar
- **DLP at every boundary** — PII/secret detection, redaction, and masking
- **Signed audit trails** — tamper-evident logs for every decision

## Architecture

Seven components form the control plane:

```
┌─────────────────────────────────────────────────────────────────────┐
│                        PrivacyGuard Control Plane                   │
│                                                                     │
│  ┌──────────────┐    ┌──────────────┐    ┌────────────────────────┐ │
│  │   Ingress    │ ─> │  Sensitivity │ -> │  Policy Decision Point │ │
│  │   Inspector  │    │  & Trust     │    │  (PDP)                 │ │
│  └──────────────┘    │  Engine      │    └──────────┬─────────────┘ │
│                      └──────────────┘               │               │
│                                           ┌─────────┼─────────┐     │
│                                           ▼         ▼         ▼     │
│                                   ┌──────────┐ ┌───────┐ ┌───────┐  │
│                                   │ Approval │ │ Tool  │ │ Memory│  │
│                                   │ Orch.    │ │ Gate  │ │ Guard │  │
│                                   └──────────┘ └───────┘ └───────┘  │
│                                          │         │         │      │
│                                          └─────────┼─────────┘      │
│                                                    ▼                │
│                                          ┌──────────────────┐       │
│                                          │  Egress DLP &    │       │
│                                          │  Audit           │       │
│                                          └──────────────────┘       │
└─────────────────────────────────────────────────────────────────────┘
```

| # | Component | Role |
|---|-----------|------|
| 1 | **Ingress Inspector** | Parse inbound content, classify trust/source, detect prompt injection |
| 2 | **Sensitivity & Trust Engine** | PII/secret detection, confidence scores, trust labels, data classes |
| 3 | **Policy Decision Point** | Evaluate allow/deny/redact/approve decisions via policy-as-code |
| 4 | **Approval Orchestrator** | User-facing prompts for high-risk flows, purpose-bound approvals |
| 5 | **Tool Gateway** | Scoped capability tokens, tool mediation, exec/fs/browser gating |
| 6 | **Memory Guard** | Ephemeral/quarantined/trusted memory tiers, promotion rules |
| 7 | **Egress DLP & Audit** | Outbound scanning, transforms (mask/tokenize/redact), signed audit events |

## Trust Zones

```mermaid
graph LR
    A["Zone A<br/>User / Local<br/><i>trusted intent</i>"]
    B["Zone B<br/>External Content<br/><i>untrusted, tainted</i>"]
    C["Zone C<br/>PrivacyGuard<br/><i>policy plane</i>"]
    D["Zone D<br/>Subagent Exec<br/><i>capability-bound</i>"]
    E["Zone E<br/>Local Tools / OS<br/><i>high-risk, mediated</i>"]
    F["Zone F<br/>Remote Destinations<br/><i>egress boundary</i>"]

    A -->|mediated| C
    B -->|tainted| C
    C -->|scoped token| D
    C -->|gated| E
    C -->|DLP enforced| F

    style C fill:#2d6a4f,color:#fff,stroke:#1b4332
    style B fill:#9d0208,color:#fff,stroke:#6a040f
    style F fill:#e85d04,color:#fff,stroke:#dc2f02
```

## Content Envelope

The `ContentEnvelope` is the canonical metadata wrapper for **all** content flowing through the system:

```typescript
interface ContentEnvelope {
  content_id:           string;           // UUIDv4
  source_type:          SourceType;       // user_input | local_file | web_content | ...
  source_trust:         SourceTrust;      // trusted_user | untrusted_external | ...
  sensitivity:          DataClass[];      // public < internal < confidential < restricted < pii < secret
  entities:             DetectedEntity[]; // PII/secret entities found in content
  retention_class:      RetentionClass;   // ephemeral | session | durable | quarantined
  allowed_destinations: Destination[];    // local_only | approved_remote | any_remote
  purpose_tags:         PurposeTag[];     // user_request | agent_task | audit | ...
  taint_flags:          TaintFlag[];      // contains_pii | contains_secret | prompt_injection_suspected
  provenance_ref?:      string;           // URL to provenance attestation
  created_at:           string;           // ISO 8601 datetime
}
```

Cross-field invariants are enforced at parse time — for example, `pii` sensitivity **requires** `contains_pii` taint, and `untrusted_external` content **cannot** have `durable` retention.

## Policy Effects

Every policy decision produces one of:

| Effect | Meaning |
|--------|---------|
| `allow` | Proceed with no restrictions |
| `allow_with_minimization` | Proceed, but strip/redact unnecessary sensitive data |
| `require_approval` | Block until user explicitly approves with purpose binding |
| `quarantine` | Isolate content for review; do not use in active flows |
| `deny` | Hard block with human-readable explanation and policy ID |

## Implementation Roadmap

```mermaid
gantt
    title PrivacyGuard Implementation Phases
    dateFormat YYYY-MM-DD
    axisFormat %b %Y

    section Phase 0 - Skeleton
    01 Data Model & Envelope        :done, p01, 2026-03-07, 1d
    02 Policy Decision Point        :done, p02, after p01, 1d
    03 Capability Tokens            :done, p03, after p01, 1d
    04 API Surface & Contracts      :done, p04, after p01, 1d
    05 Audit Event System           :done, p05, after p01, 1d

    section Phase 1 - MVP
    06 Ingress Inspector            :done, p06, after p02, 1d
    07 Sensitivity & Trust Engine   :done, p07, after p06, 1d
    08 Tool Gateway                 :done, p08, after p07, 1d
    09 Approval Orchestrator        :p09, after p08, 5d
    10 Egress DLP Gateway           :p10, after p08, 5d
    11 Safe Telemetry & Logging     :p11, after p05, 5d

    section Phase 2 - Memory
    12 Memory Guard                 :p12, after p02, 5d

    section Phase 3 - Provenance
    13 Provenance & Integrity       :p13, after p05, 5d
    14 Workload Identity            :p14, after p03, 5d

    section Phase 4 - Enterprise
    15 Enterprise & Deployment      :p15, after p12, 7d
```

### Progress

| Phase | Components | Status |
|-------|-----------|--------|
| **Phase 0** — Skeleton | 01 Data Model, 02 PDP, 03 Cap Tokens, 04 API Surface, 05 Audit Events | **5/5** |
| **Phase 1** — MVP Controls | 06 Ingress, 07 Sensitivity, 08 Tool Gateway, 09 Approvals, 10 Egress DLP, 11 Telemetry | **3/6** |
| **Phase 2** — Trust-Aware Memory | 12 Memory Guard | 0/1 |
| **Phase 3** — Provenance & Identity | 13 Provenance, 14 Workload Identity | 0/2 |
| **Phase 4** — Enterprise | 15 Enterprise & Deployment | 0/1 |
| **Cross-cutting** | 16 Test Strategy & Threat Modeling | Ongoing |

## Dependency Graph

```
01 Data Model ──┬──▶ 02 PDP ──────┬──▶ 06 Ingress Inspector
                │                 ├──▶ 08 Tool Gateway
                │                 ├──▶ 10 Egress DLP
                │                 └──▶ 12 Memory Guard
                ├──▶ 03 Cap Tokens ──▶ 08 Tool Gateway
                ├──▶ 04 API Surface (parallel with 02, 03)
                └──▶ 05 Audit Events (parallel with 02, 03)

07 Sensitivity Engine ──▶ 06 Ingress Inspector
                      ──▶ 10 Egress DLP

09 Approval Orchestrator ──▶ 02 PDP
                         ──▶ 08 Tool Gateway

11 Safe Telemetry ──▶ 05 Audit Events
13 Provenance ──▶ 05 Audit Events, 02 PDP
14 Workload Identity ──▶ 03 Cap Tokens
15 Enterprise ──▶ All Phase 0–3 components
16 Test Strategy ──▶ Runs in parallel from Phase 0 onward
```

## Quick Start

```bash
# Clone
git clone https://github.com/vvoffsec/PrivacyGuard.git
cd PrivacyGuard

# Install dependencies
npm install

# Run all checks (typecheck → lint → test → audit)
npm run check
```

### Development Commands

| Command | Description |
|---------|-------------|
| `npm run check` | Run all checks in sequence |
| `npm run typecheck` | TypeScript type checking (`tsc --noEmit`) |
| `npm run lint` | ESLint with strict type-checked rules |
| `npm run test` | Run all unit tests (Vitest) |
| `npm run format` | Auto-format with Prettier |
| `npm run audit:deps` | Check for dependency vulnerabilities |

## Tech Stack

| Category | Technology |
|----------|-----------|
| Language | TypeScript (ESM, ES2022, NodeNext) |
| Validation | Zod v4 — runtime validation + static type inference |
| Testing | Vitest v4 — native ESM, fast feedback |
| Linting | ESLint v10 + typescript-eslint (strictTypeChecked) |
| Formatting | Prettier |
| IDs | uuid v13 (UUIDv4) |

### Planned additions

| Category | Technology |
|----------|-----------|
| Authorization | OPA or Cedar-backed PDP |
| PII/Secret Detection | Pattern + checksum + entropy pipeline (Presidio-class) |
| Pseudonymization | Deterministic tokenization / FPE |
| Workload Identity | SPIFFE/SPIRE |
| Provenance | Signed bundles + in-toto / SLSA attestations |
| Observability | OpenTelemetry with source-side redaction |

## Non-Functional Targets

- **P95 PDP decision** < 100ms (text-only, normal local load)
- **P95 ingress classification** < 250ms (up to 64 KB text)
- **Fail closed** on PrivacyGuard failure (preserve last-known-good policy bundle)
- **Zero raw secrets** in routine logs (automatic secret-leak tests every release)
- **Every deny/redact/approval** returns human-readable explanation + policy ID

## Project Structure

```
PrivacyGuard/
├── docs/
│   ├── plans/
│   │   ├── 00-master-plan.md          # Master index + dependency graph
│   │   ├── 01-data-model-and-envelope.md
│   │   ├── 02-policy-decision-point.md
│   │   ├── ...                        # 03 through 16
│   │   └── 16-test-strategy-and-threat-modeling.md
│   └── PrivacyGuard_Technical_Architecture_Spec.pdf
├── src/
│   ├── data-model/                    # Plan 01 — ContentEnvelope
│   │   ├── __tests__/                 # 52 unit tests
│   │   ├── data-class.ts              # Data classification hierarchy
│   │   ├── entity.ts                  # Detected entity schema
│   │   ├── envelope.ts                # ContentEnvelope schema + parse/update
│   │   ├── errors.ts                  # Validation & consistency errors
│   │   ├── factories.ts              # Envelope factory helpers
│   │   ├── serialization.ts          # JSON serialization + integrity hashing
│   │   └── index.ts                   # Public API barrel
│   ├── pdp/                           # Plan 02 — Policy Decision Point
│   │   ├── __tests__/                 # 97 unit tests
│   │   ├── types.ts                   # PolicyInput, PolicyEffect, PolicyDecision schemas
│   │   ├── errors.ts                  # Validation, bundle, evaluation errors
│   │   ├── policy-rule.ts             # PolicyRule interface + factory
│   │   ├── policy-bundle.ts           # PolicyBundle type + factory
│   │   ├── default-policies.ts        # 3 mandatory default policies
│   │   ├── engine.ts                  # PolicyEngine interface (pluggable backend)
│   │   ├── local-engine.ts            # InProcessPolicyEngine (first backend)
│   │   ├── pdp.ts                     # createPDP facade (validate → evaluate → fail-closed)
│   │   └── index.ts                   # Public API barrel
│   ├── capabilities/                  # Plan 03 — Capability Tokens
│   │   ├── __tests__/                 # 84 unit tests
│   │   ├── types.ts                   # CapabilityToken, ScopeCheckRequest schemas
│   │   ├── errors.ts                  # Mint, validation errors
│   │   ├── mint.ts                    # Token minting from policy decisions
│   │   ├── signing.ts                 # HMAC signing + key providers
│   │   ├── validate.ts               # Token validation pipeline
│   │   ├── revocation.ts             # Token revocation registry
│   │   ├── scope.ts                   # Scope checking (tools, data classes, destinations)
│   │   └── index.ts                   # Public API barrel
│   ├── api/                           # Plan 04 — API Surface & Contracts
│   │   ├── __tests__/                 # 133 unit tests
│   │   ├── types.ts                   # Request/response schemas (ingress, tool, memory, explain)
│   │   ├── errors.ts                  # API validation + handler errors
│   │   ├── transport.ts               # In-process transport + routing
│   │   ├── result.ts                  # ApiResult type (success/error)
│   │   ├── interfaces.ts             # AuditEmitter, DecisionStore, CapabilityStore interfaces
│   │   ├── decision-store.ts          # In-memory decision store
│   │   ├── handlers/                  # Route handlers (ingress, tool-auth, memory, explain)
│   │   └── index.ts                   # Public API barrel
│   ├── audit/                         # Plan 05 — Audit Event System
│   │   ├── __tests__/                 # 104 unit tests
│   │   ├── types.ts                   # 6 event schemas (decision, approval, tool, memory, egress, integrity)
│   │   ├── errors.ts                  # Audit validation + consistency errors
│   │   ├── factories.ts              # Event factory functions
│   │   ├── emitter.ts                 # DefaultAuditEmitter + NoOpAuditEmitter
│   │   ├── store.ts                   # InMemoryAuditStore
│   │   ├── query.ts                   # Event querying + filtering
│   │   ├── serialization.ts          # JSON serialization + integrity verification
│   │   └── index.ts                   # Public API barrel
│   ├── ingress/                       # Plan 06 — Ingress Inspector
│   │   ├── __tests__/                 # 145 unit tests
│   │   ├── types.ts                   # Pipeline stage interfaces + Zod schemas
│   │   ├── errors.ts                  # Parse, classification, pipeline errors
│   │   ├── content-parser.ts          # Format detection, normalization, hashing
│   │   ├── trust-classifier.ts        # Source→trust mapping, escalation prevention
│   │   ├── sensitivity-engine.ts      # 8 pattern recognizers (email, phone, SSN, CC, keys, etc.)
│   │   ├── injection-detector.ts      # 7 prompt injection pattern categories
│   │   ├── envelope-assembler.ts      # ContentEnvelope + PolicyInput assembly
│   │   ├── pipeline.ts               # Orchestrated pipeline (fail-closed)
│   │   └── index.ts                   # Public API barrel
│   ├── sensitivity/                   # Plan 07 — Sensitivity & Trust Engine
│   │   ├── __tests__/                 # 200 unit tests
│   │   ├── types.ts                   # Recognition results, engine config schemas
│   │   ├── errors.ts                  # Recognition + engine errors
│   │   ├── recognizers/               # 11 pattern recognizers (email, phone, SSN, CC, API keys, etc.)
│   │   ├── entropy.ts                # Shannon entropy calculation
│   │   ├── confidence.ts             # Confidence scoring + aggregation
│   │   ├── secret-handle.ts          # Opaque secret handles (never log raw values)
│   │   ├── deduplication.ts          # Entity deduplication across recognizers
│   │   ├── engine.ts                  # Configurable SensitivityEngine facade
│   │   └── index.ts                   # Public API barrel
│   ├── gateway/                       # Plan 08 — Tool Gateway
│   │   ├── __tests__/                 # 277 unit tests
│   │   ├── types.ts                   # Tool request/response schemas, risk tiers
│   │   ├── errors.ts                  # Gateway validation + sanitization errors
│   │   ├── tool-categories.ts        # Risk-tier classification for tools
│   │   ├── argument-validator.ts     # Argument type + constraint validation
│   │   ├── argument-sanitizer.ts     # Injection + traversal sanitization
│   │   ├── gateway.ts                # ToolGateway facade (classify → validate → sanitize → gate)
│   │   └── index.ts                   # Public API barrel
│   └── shared/
│       └── crypto.ts                  # SHA-256 hashing utility
├── CLAUDE.md
├── eslint.config.mjs
├── package.json
├── tsconfig.json
└── vitest.config.ts
```

## License

TBD
