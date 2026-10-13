# ocsf-schema-go

Go bindings and tooling for the
[Open Cybersecurity Schema Framework (OCSF)](https://github.com/ocsf/ocsf-schema).

The OCSF schema is authored in OCSF's own metaschema format — not standard JSON
Schema. Event classes and objects declare partial attribute maps whose types live in
a shared dictionary, inherit via `extends`, and mix in profile attributes via
`$include`. This module compiles that format and generates idiomatic Go from it.

## Packages

| Package | Purpose |
|---------|---------|
| `ocsf/events` | **Generated** structs for every OCSF event class, plus constants, caption maps, and the class-UID registry (`NewEventByClassUID`, `UnmarshalEvent`) |
| `ocsf/objects` | **Generated** structs for every OCSF object, plus observable type registries |
| `ocsf/ocsfdata` | **Generated** embedded compiled schema for runtime access with no OCSF checkout |
| `validate` | Semantic validator: required attributes (profile-aware), types, enums, constraints, UID consistency |
| `recordintegrity` | `record_integrity` profile crypto: JCS canonicalization, fingerprints, signing (ECDSA/RSA), verification, tamper-evident chains |
| `schema` | Loads and compiles an OCSF source tree (extends, `$include`, dictionary types, platform extensions) |
| `gen` / `cmd/ocsfgen` | Code generator and its CLI |
| `ocsfext/integrity` | Schema extension adding `digital_signature.signature_value` (interim; see [Upstream](upstream/signature-value-issue-1698.md)) |

Bindings are generated from OCSF **1.10.0-dev**, including the `win`, `linux`, and
`macos` platform extensions.

## Quick start

```go
import (
    "github.com/grokify/ocsf-schema-go/ocsf/events"
    "github.com/grokify/ocsf-schema-go/ocsf/ocsfdata"
    "github.com/grokify/ocsf-schema-go/validate"
)

// Typed events with generated constants
evt := events.Authentication{
    ClassUID:    events.ClassUIDAuthentication, // 3002
    CategoryUID: events.CategoryUIDIAM,
    ActivityID:  events.AuthenticationActivityIDLogon,
    // ...
}

// Dispatch unknown events by class_uid
decoded, err := events.UnmarshalEvent(data) // e.g. *events.Authentication

// Validate against the embedded compiled schema
v := validate.New(ocsfdata.MustSchema())
result := v.ValidateEvent(data)
```

See the repository [README](https://github.com/grokify/ocsf-schema-go) for full
usage, including signing and verifying events under the `record_integrity` profile.

## Related

[ocsf-lake](https://github.com/grokify/ocsf-lake) is the datastore/application layer
built on this module: storage, querying, ingest-time validation and attestation, and
integrity check orchestration.
