# PLAN — ocsf-schema-go

Execution order for Phase 1 (see ROADMAP.md):

1. **Scaffold** — `go mod init github.com/grokify/ocsf-schema-go`, specs, repo hygiene.
2. **`schema` package** — raw types + `Load`, then `Compile` (extends → `$include` →
   dictionary join → UID computation). Fixture-driven tests first
   (`schema/testdata/minischema`), then an opt-in full-tree test gated on
   `OCSF_SCHEMA_DIR` pointing at a real `ocsf/ocsf-schema` checkout.
3. **`gen` package** — naming table, type mapping, template-free emission via
   `strings.Builder` + `go/format`. Unit tests for naming/type edge cases.
4. **`cmd/ocsfgen`** — Cobra CLI: `ocsfgen generate --schema-dir <path> --out <dir>
   --package ocsf`.
5. **Generate + verify** — run against the local OCSF checkout, commit output under
   `ocsf/`, add marshal/unmarshal round-trip tests, `golangci-lint run`, coverage badge.
6. **Docs + commits** — README, conventional topical commits (feat schema, feat gen,
   feat cli, feat generated bindings, test, docs, chore).

Key risks handled up front:

- `$include` inside attribute maps breaks naive decoding → decode attributes as
  `map[string]json.RawMessage`.
- Name collisions after case conversion (e.g. `_resource` vs `resource_details`) →
  hidden objects are never emitted; enum caption collisions get numeric suffixes.
- `omitempty` dropping meaningful `false` → booleans generate as `*bool`.
