# TRD — ocsf-schema-go

## Package layout

```
schema/         Metaschema parsing + compilation (source of truth for semantics)
validate/       Semantic validator driven by a compiled schema
gen/            Go code generation from a compiled schema
cmd/ocsfgen/    Thin Cobra CLI over gen
ocsf/objects/   Generated object structs + observable registries (committed)
ocsf/events/    Generated event structs, constants, class-UID registry (committed)
ocsf/ocsfdata/  Generated embedded compiled schema (indented JSON + go:embed accessor)
```

## OCSF source format (input)

An OCSF schema checkout contains:

- `version.json` — schema semver.
- `categories.json` — category name → `{uid, caption, description}`.
- `dictionary.json` — ~1000 attribute definitions; each has a `type` that is either a
  scalar type key from `dictionary.json#/types/attributes` (`string_t`, `integer_t`,
  `long_t`, `timestamp_t`, `boolean_t`, `float_t`, `json_t`, plus string/int subtypes such
  as `ip_t`, `port_t`, `email_t`) **or** the `name` of an object. `is_array: true` marks
  array attributes. Untyped usages default per attribute name via the dictionary.
- `objects/*.json` — object definitions. `extends` names a parent object (`object` is the
  implicit empty root). Names beginning with `_` (`_entity`, `_resource`) are hidden
  (abstract): they exist only to be extended.
- `events/**/*.json` — event class definitions. `extends` chains terminate at
  `base_event`. A class with a top-level `uid` is concrete:
  `class_uid = category_uid × 1000 + uid`; category bases without `uid` are
  abstract. `base_event` has no `uid` either but is concrete: the OCSF schema server
  lists it as Base Event, `class_uid` 0 in category `other` (`category_uid` 0), for
  events that fit no other class. `type_uid = class_uid × 100 + activity_id`.
- `profiles/*.json` — attribute mixins pulled in via `"$include": [paths]` inside an
  `attributes` map (the only `$include` shape used in the repo).

Attribute entries inside objects/events/profiles are **partial overrides**: the dictionary
supplies `type`/`is_array`/caption, the local entry supplies/overrides `requirement`,
`description`, `enum`, `group`, `@deprecated`.

## `schema` package

- `Load(dir string) (*Schema, error)` — reads the tree into raw definitions.
- `(*Schema).Compile() (*CompiledSchema, error)` — produces flattened definitions:
  - Resolve `$include` profiles into the including entity's attribute map.
  - Walk `extends` chains (child overrides parent attribute-by-attribute; property-level
    merge: non-zero child fields win; a child enum is merged into the parent enum, the
    child winning on the same value, from the dictionary through each ancestor to the
    class, matching upstream server behavior, so classes keep `0` Unknown and `99` Other).
  - Join each attribute against the dictionary for `type`, `is_array`, default caption
    and description.
  - Compute `ClassUID` for concrete classes.
- Attribute maps parse via `map[string]json.RawMessage` to lift `$include` out before
  decoding `Attribute` values.
- Hidden objects (`_`-prefixed) are compiled (they are extension bases) but flagged
  `Hidden: true` so the generator can skip emitting them.

## `gen` package

- **Type mapping**: `boolean_t → *bool`; `integer_t` & int subtypes → `int`;
  `long_t`/`timestamp_t` → `int64`; `float_t → float64`; `json_t → any`;
  string family → `string`; object types → `*T` (or `[]T` when `is_array`); the generic
  `object` type → `map[string]any`. Scalar arrays → `[]elem`.
- **Optionality**: attributes with `requirement: required` marshal always, except
  attributes a profile mixes in (required only when the event declares the profile);
  all others get `,omitempty`. Booleans are `*bool` so `false` survives marshaling.
- **Naming**: snake_case → PascalCase with an initialism table (ID, UID, URL, IP, OS, TLS,
  DNS, HTTP, API, CVE, CVSS, …). Hidden-object names never surface. Enum constant names:
  `<Type><Field><Caption>` with caption sanitized to a Go identifier; collisions get the
  numeric value appended.
- **Enums**: emitted as untyped `int` constants grouped per attribute, plus a
  `ClassUID`/`CategoryUID` constant per concrete class/category.
- Output is `gofmt`-formatted via `go/format` before writing.

## `ocsf` package (generated)

- One file per event category (`events_iam.go`, …), `objects.go`, `constants.go`,
  `version.go` (`const SchemaVersion`).
- Every struct/field carries doc comments derived from captions/descriptions
  (HTML stripped).

## Platform extensions

`LoadWithExtensions(dir, names...)` ("all" or specific names) loads
`extensions/<dir>/`:

- `extension.json` supplies `{uid, name}`; extension classes get
  `class_uid = extension_uid × 100000 + category_uid × 1000 + uid`.
- Extension `dictionary.json` entries are additive; redefining a core entry
  errors.
- Files with `extends` but no `name` are **patches**: their attributes overlay
  the extended core definition, `$include` lists append (extension-relative
  paths are qualified at load time), and constraints replace.
- Extension provenance is recorded (`Definition.Extension`,
  `Attribute.Source = "extension:<name>"`).

## Observable enum synthesis

The source schema declares only `0`/`99` in `observable.type_id`; the full
enum is derived (as the OCSF server does) from `observable:` annotations on
dictionary types, dictionary attributes, objects, and object/class
attributes, first-writer-wins in that priority order. The generator also
emits `ObservableTypeIDByAttribute`, `ObservableTypeIDByDictionaryType`, and
`ObservableTypeIDByObject` maps into the objects package.

## `validate` package

`validate.New(compiledSchema, opts...)` builds a class-UID-indexed semantic
validator; `ValidateEvent` dispatches on the payload's `class_uid`,
`ValidateEventClass`/`ValidateObject` target a definition by name. Checks:

- required attributes (profile-sourced requirements apply only when
  `metadata.profiles` activates that profile);
- scalar type conformance by root dictionary type, arrays, nested objects
  (recursive);
- enum membership (skipped for `class_uid`/`category_uid`/`type_uid`, which
  get structural checks instead: class lookup, category match,
  `type_uid = class_uid×100 + activity_id`);
- `at_least_one` / `just_one` constraints;
- unknown attributes (warn by default, configurable) and deprecation
  warnings.

All findings are `Issue{Code, Path, Message, Warning}` on a `Result`; only
non-warning issues fail `Result.Valid()`.

## Generated registries (events package)

`NewEventByClassUID` (switch over `ClassUID*` constants), `UnmarshalEvent`
(probe `class_uid`, decode into the concrete struct), `ClassNames`,
`ClassCaptions`, `CategoryCaptions`, per-enum `<Prefix>Captions` maps, and
shared `SeverityID*`/`StatusID*` constants lifted from `base_event`.

## Embedded schema (`ocsf/ocsfdata`)

The generator serializes the entire `CompiledSchema` to indented JSON
(`schema.json`, ~5.5 MB, uncompressed so it stays scannable and
reviewable in diffs) with a `go:embed` accessor
(`Schema()`/`MustSchema()`, decoded once behind `sync.Once`).
`Attribute.Source` serializes as `_source` so profile/extension provenance
survives the round-trip — the validator's profile-aware requirement logic
depends on it. Runtime validation needs no OCSF checkout:
`validate.New(ocsfdata.MustSchema())`.

## Testing

- `schema`: fixture tree under `schema/testdata/minischema` exercising extends,
  `$include`, dictionary fallback, enum override, hidden objects; plus an opt-in test
  against a real checkout via `OCSF_SCHEMA_DIR`.
- `gen`: naming and type-mapping unit tests; golden-compile test (generated code for the
  fixture parses with `go/parser`).
- `ocsf`: round-trip marshal/unmarshal tests against hand-written OCSF JSON samples.
