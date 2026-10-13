# PRD — ocsf-schema-go

## Problem

The [Open Cybersecurity Schema Framework (OCSF)](https://github.com/ocsf/ocsf-schema) defines a
vendor-agnostic event taxonomy for security telemetry. The schema is authored in OCSF's own
JSON metaschema format (not standard JSON Schema): event classes and objects use `extends`
inheritance, `$include` profile mixins, and attribute types resolved from a shared
`dictionary.json`. Go programs that produce or consume OCSF events today must either
hand-write structs or depend on protobuf-generated bindings that don't marshal to
idiomatic OCSF JSON.

## Goals

1. **Generated Go structs** for every OCSF object and event class, marshaling directly to
   spec-compliant OCSF JSON (snake_case attribute names, correct optionality).
2. **Enum constants** for classification values (`class_uid`, `category_uid`, `activity_id`,
   `type_id`, `severity_id`, …) with captions preserved in doc comments.
3. **Schema-compilation library** (`schema` package) that loads an OCSF schema source tree
   and resolves inheritance, profiles, and dictionary types — usable independently of the
   code generator (e.g., for validators, doc tooling, mapping tools).
4. **Regenerable**: a `ocsfgen` CLI re-generates the bindings from any OCSF schema checkout,
   so the library can track upstream releases.

## Non-Goals (v0)

- OCSF platform extensions (`extensions/windows`, `linux`, `macos`).
- Runtime validation (constraints such as `at_least_one`, regex/range checks).
- The OCSF server "compiled schema" export format (`/export/schema`).

## Users

- Go services emitting OCSF events (SIEM pipelines, log producers).
- Go consumers parsing OCSF events (analytics, normalization, routing).
- Tooling authors needing programmatic access to the OCSF schema definition itself.
