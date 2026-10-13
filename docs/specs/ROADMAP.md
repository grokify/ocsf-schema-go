# ROADMAP — ocsf-schema-go

Status legend: `planned` | `in_progress` | `done`. Phase status is derived from member RMI
statuses.

## Phase 1 — Core schema compiler and generated bindings

| RMI | Title | Status |
|-----|-------|--------|
| RMI-OCSFSCHEMAGO-001 | `schema` package: load OCSF source tree (dictionary, categories, objects, events, profiles) | done |
| RMI-OCSFSCHEMAGO-002 | `schema` package: compile — extends resolution, `$include` profiles, dictionary type join, class UIDs | done |
| RMI-OCSFSCHEMAGO-003 | `gen` package: naming, type mapping, struct + enum emission | done |
| RMI-OCSFSCHEMAGO-004 | `cmd/ocsfgen` CLI (Cobra) | done |
| RMI-OCSFSCHEMAGO-005 | Generated `ocsf` package for OCSF 1.10.0-dev with round-trip tests | done |

## Phase 2 — Fidelity and ergonomics

| RMI | Title | Status |
|-----|-------|--------|
| RMI-OCSFSCHEMAGO-006 | Constraint metadata (`at_least_one`, `just_one`) exposed on compiled schema and enforced by the `validate` package (semantic validator: required attrs, types, enums, constraints, UID consistency, profile-aware requirements) | done |
| RMI-OCSFSCHEMAGO-007 | Caption lookup tables: per-enum `*Captions` maps, `ClassNames`/`ClassCaptions`/`CategoryCaptions`, shared `SeverityID*`/`StatusID*` constants | done |
| RMI-OCSFSCHEMAGO-008 | Platform extensions (`win`, `linux`, `macos`): extension dictionaries, new classes/objects with `ext_uid×100000` class UIDs, patch definitions merged into core structs | done |
| RMI-OCSFSCHEMAGO-009 | Observable type registry: synthesized `observable.type_id` enum (mirroring the OCSF server) plus `ObservableTypeIDBy{Attribute,DictionaryType,Object}` maps | done |
| RMI-OCSFSCHEMAGO-012 | Class-UID registry: `NewEventByClassUID`, `UnmarshalEvent` dispatcher | done |
| RMI-OCSFSCHEMAGO-013 | Embedded compiled schema (`ocsf/ocsfdata`, indented JSON + `go:embed`) for runtime validation without a schema checkout | done |
| RMI-OCSFSCHEMAGO-014 | `recordintegrity` package: JCS canonicalization, content/chain fingerprints, attestation signing (ECDSA/RSA), verification with status taxonomy, chain-link verification | done |
| RMI-OCSFSCHEMAGO-015 | External extension roots (`LoadOptions.ExtensionDirs`, `--extension-dirs`) and the `ocsfext/integrity` extension adding `digital_signature.signature_value` (retire when upstream adds an official signature-bytes attribute) | done |

## Phase 3 — Release tracking

| RMI | Title | Status |
|-----|-------|--------|
| RMI-OCSFSCHEMAGO-010 | Pin generation to tagged OCSF releases; version-matrixed packages (e.g. `ocsf/v1_5`) | planned |
| RMI-OCSFSCHEMAGO-011 | CI job that diffs generated output against upstream main and opens PRs | planned |
| RMI-OCSFSCHEMAGO-016 | Post upstream feedback on ocsf-schema#1698 (signature bytes) after publishing; retire `ocsfext/integrity` when the official attribute lands (see `docs/upstream/signature-value-issue-1698.md`) | planned |
