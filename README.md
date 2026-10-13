# ocsf-schema-go

[![Go Reference](https://pkg.go.dev/badge/github.com/grokify/ocsf-schema-go.svg)](https://pkg.go.dev/github.com/grokify/ocsf-schema-go)
[![License][license-svg]][license-url]

Go bindings and tooling for the [Open Cybersecurity Schema Framework (OCSF)](https://github.com/ocsf/ocsf-schema).

The OCSF schema is authored in OCSF's own metaschema format — not standard JSON Schema.
Event classes and objects declare partial attribute maps whose types live in a shared
dictionary, inherit from parents via `extends`, and mix in profile attributes via
`$include`. This module compiles that format and generates idiomatic Go structs from it.

## Packages

| Package | Purpose |
|---------|---------|
| `ocsf/events` | **Generated** structs for every OCSF event class; `ClassUID*`/`CategoryUID*`/enum constants with caption maps; class-UID registry (`NewEventByClassUID`, `UnmarshalEvent`, `ClassNames`, `ClassCaptions`) |
| `ocsf/objects` | **Generated** structs for every OCSF object (`User`, `Process`, `Metadata`, …) plus observable type registries |
| `ocsf/ocsfdata` | **Generated** embedded compiled schema (`go:embed`) for runtime schema access without an OCSF checkout |
| `validate` | Semantic OCSF validator: required attributes, types, enums, constraints, UID consistency — driven by the compiled schema, no JSON Schema files |
| `recordintegrity` | Cryptographic side of the OCSF `record_integrity` profile: JCS (RFC 8785) canonicalization, event fingerprints, attestation signing (ECDSA/RSA), signature/certificate verification, tamper-evident chain links |
| `ocsfext/integrity` | Schema extension adding `digital_signature.signature_value` (OCSF 1.10.0-dev has no attribute for the signature bytes; retired when upstream adds one) |
| `schema` | Loads and compiles an OCSF schema source tree (resolves `extends`, `$include`, dictionary types, platform extensions) |
| `gen` | Emits Go source from a compiled schema |
| `cmd/ocsfgen` | CLI wrapper: regenerate the bindings from any OCSF schema checkout |

Generated from OCSF schema version **1.10.0-dev** (see `events.SchemaVersion`), including
the `win`, `linux`, and `macos` platform extensions (e.g. `events.RegistryKeyActivity`,
class_uid 201001).

## Install

```bash
go get github.com/grokify/ocsf-schema-go
```

## Usage

### Producing an OCSF event

```go
import (
    "encoding/json"

    "github.com/grokify/ocsf-schema-go/ocsf/events"
    "github.com/grokify/ocsf-schema-go/ocsf/objects"
)

func main() {
    evt := events.Authentication{
        ActivityID:  events.AuthenticationActivityIDLogon,
        CategoryUID: events.CategoryUIDIAM,
        ClassUID:    events.ClassUIDAuthentication,
        SeverityID:  events.AuthenticationSeverityIDInformational,
        Time:        1757894400000,
        TypeUID:     int64(events.ClassUIDAuthentication)*100 + events.AuthenticationActivityIDLogon,
        Metadata: &objects.Metadata{
            Version: events.SchemaVersion,
            Product: &objects.Product{Name: "example", VendorName: "Example Corp"},
        },
        User: &objects.User{Name: "jdoe", TypeID: objects.UserTypeIDUser},
    }
    out, err := json.Marshal(evt)
    // ...
}
```

Attribute names marshal to OCSF snake_case (`activity_id`, `src_endpoint`, …).
Required attributes marshal unconditionally; recommended/optional attributes carry
`omitempty`. Booleans are `*bool` so an explicit `false` survives marshaling.

### Consuming an OCSF event

When you know the class, unmarshal directly; when you don't, dispatch on the
payload's `class_uid` via the generated registry:

```go
evt, err := events.UnmarshalEvent(data) // returns e.g. *events.Authentication
if err != nil { /* ... */ }
switch e := evt.(type) {
case *events.Authentication:
    if e.ActivityID == events.AuthenticationActivityIDLogoff { /* ... */ }
}
```

Caption lookups mirror the schema: `events.ClassCaptions[3002]` is
`"Authentication"`, `events.AuthenticationActivityIDCaptions[1]` is `"Logon"`, and the
shared `events.SeverityIDCaptions` map covers the severity values common to all classes
(useful for populating `*_name` sibling attributes).

### Validating events

The `validate` package checks payloads against the real schema semantics — required
attributes (profile-aware), scalar types, enum membership, nested objects,
`at_least_one`/`just_one` constraints, and `class_uid`/`category_uid`/`type_uid`
consistency. The embedded schema means no OCSF checkout is needed at runtime:

```go
import (
    "github.com/grokify/ocsf-schema-go/ocsf/ocsfdata"
    "github.com/grokify/ocsf-schema-go/validate"
)

v := validate.New(ocsfdata.MustSchema())
result := v.ValidateEvent(eventJSON)
if !result.Valid() {
    for _, issue := range result.Errors() {
        log.Println(issue) // error [missing_required] user: required attribute "user" is missing
    }
}
```

### Working with the schema itself

```go
import "github.com/grokify/ocsf-schema-go/schema"

s, err := schema.Load("/path/to/ocsf-schema")
if err != nil { /* ... */ }
c, err := s.Compile()
if err != nil { /* ... */ }

auth := c.Classes["authentication"]
// auth.ClassUID == 3002, auth.Attributes fully resolved with types,
// requirements, enums, and provenance (inherited vs profile vs local).
```

### Signing and verifying events (record_integrity)

The `recordintegrity` package implements the OCSF `record_integrity` profile: it
canonicalizes the event with JCS (RFC 8785), fingerprints it (SHA-256, excluding
`attestation_list`), signs the fingerprint with an ECDSA or RSA key, and records the
signer certificate's issuer, serial, and SHA-256 fingerprint so verifiers can locate
and trust the key. Chains sign transitively: `prev_event.fingerprint` covers the
previous event *including its attestations*.

```go
import ri "github.com/grokify/ocsf-schema-go/recordintegrity"

// Producer side: sign and chain.
prevRef, _ := ri.NewPrevEventRef(previousEventJSON)
signed, _, err := ri.SignAndAttach(eventJSON, ri.SignOptions{
    Signer:       privateKey, // crypto.Signer (ECDSA or RSA)
    Certificate:  signerCert,
    AuthorityUID: "signer.example.com",
    ChainUID:     "audit-log-2026-09",
    PrevEvent:    prevRef,
})

// Consumer side: verify content, signatures, certificate trust.
result := ri.Verify(signed, ri.VerifyOptions{
    Certificates:     []*x509.Certificate{signerCert},
    PinnedCertSHA256: []string{ri.CertSHA256(signerCert)}, // or Roots: certPool
})
// result.Status: verified | unsigned | fingerprint_mismatch | signature_invalid |
//                cert_untrusted | cert_expired | chain_broken | malformed
link := ri.VerifyLink(signed, previousEventJSON) // tamper-evident chain link
```

Signature bytes travel in `digital_signature.signature_value`, added by this module's
`ocsfext/integrity` schema extension because upstream OCSF 1.10.0-dev defines
signature metadata but no attribute for the signature itself.

### Building observables

The objects package carries the schema's observable annotations, e.g. for extracting
pivot values from events:

```go
objects.ObservableTypeIDByDictionaryType["ip_t"] // 2 ("IP Address")
objects.ObservableTypeIDByObject["fingerprint"]  // 30
objects.ObservableTypeIDCaptions[2]              // "IP Address"
```

## Regenerating the bindings

```bash
git clone https://github.com/ocsf/ocsf-schema /path/to/ocsf-schema
go run ./cmd/ocsfgen generate \
  --schema-dir /path/to/ocsf-schema \
  --out ocsf \
  --extension-dirs ocsfext/integrity
```

Platform extensions are included by default; use `--extensions win,linux` to select a
subset or `--extensions ""` for core-only bindings.

## Notes and limitations

- Object and event class names overlap in OCSF (e.g. `application`), which is why
  events and objects live in separate generated packages.
- Hidden abstract objects (`_entity`, `_resource`) are flattened into their children and
  not emitted. Abstract event classes (`base_event`, category bases) **are** emitted —
  OCSF permits them as generic events — but have no `ClassUID` constants.
- The validator does not check regex/range/max_len facets of dictionary types, and
  `type_name`-style sibling captions are not cross-checked; see
  `docs/specs/ROADMAP.md` for planned work (version-pinned generation, upstream diff CI).

## License

MIT — see [LICENSE](LICENSE).

 [license-svg]: https://img.shields.io/badge/license-MIT-blue.svg
 [license-url]: https://github.com/grokify/ocsf-schema-go/blob/main/LICENSE
