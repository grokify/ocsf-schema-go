# Upstream: signature bytes on `digital_signature` (ocsf-schema #1698)

Status: **draft — not yet posted**. To be posted as a comment on
[ocsf/ocsf-schema#1698](https://github.com/ocsf/ocsf-schema/issues/1698) once this
repository is public, so the referenced implementation is verifiable.

## Background

OCSF's `record_integrity` profile
([ocsf/ocsf-schema#1661](https://github.com/ocsf/ocsf-schema/pull/1661)) lets an event
carry cryptographic attestations: an `attestation_list` whose entries hold the event
`fingerprint`, optional tamper-evident chain references (`prev_event`, `chain_uid`),
and a `signatures` array of `digital_signature` objects. However, `digital_signature`
records only signature *metadata* (algorithm, certificate reference, serialization
scheme, state) — it has **no attribute for the signature bytes themselves**, which
makes self-contained verification impossible. The gap was acknowledged in the #1661
review discussion and deferred to issue #1698, which proposes two candidate designs:

- **Option A** — add `value` plus `encoding`/`encoding_id` to `digital_signature`,
  mirroring the `fingerprint` object's pattern.
- **Option B** — introduce a wrapper `signature` object that holds the blob and
  contains `digital_signature` as a descriptor.

## Our position

This module implements the profile end to end (see the `recordintegrity` package and
the `ocsfext/integrity` schema extension, which patches `digital_signature` with a
`signature_value` attribute as an interim carrier). That experience supports
**Option A**: one additive field on `digital_signature` proved sufficient for
signing, verification, multi-signer attestations, and chain validation, with no need
for Option B's extra nesting. When an official attribute lands, the
`ocsfext/integrity` extension will be retired in its favor.

## Draft comment for #1698

```markdown
**+1 for Option A** (`value` + `encoding`/`encoding_id` on `digital_signature`), with
implementation experience to back it.

We've built a working record-integrity implementation in Go — canonicalization,
signing, verification, and tamper-evident chain walking over `prev_event` links —
against OCSF main. Since `digital_signature` has no field for the bytes today, we
carried them via a small schema extension that patches `digital_signature` with a
single attribute (`signature_value`, `bytestring_t`, requirement `recommended`),
which is effectively Option A minus the encoding enum. Observations from running it:

- **Option A was sufficient in practice.** One field on `digital_signature` composed
  cleanly with everything already in #1661: `attestation.signatures[]` handled
  multi-signer cases (producer + co-signer) unchanged, `serialization_id` told the
  verifier how to reproduce the signing input (we used JCS/RFC 8785 + SHA-256 over
  the event with `attestation_list` excluded), and per-signature `certificate`
  metadata (SHA-256 fingerprint, issuer + serial) was enough to select the
  verification key. End-to-end verification and hash-chain validation work with no
  additional nesting, which makes Option B's wrapper object feel like structure
  without a payoff.

- **Mirroring the `fingerprint` pattern (`value` + `encoding_id`) is the right
  call.** We hard-coded Base64 and still found ourselves wanting the explicit
  `encoding_id` for symmetry with `fingerprint` — verifiers already have that
  decode path.

- **`recommended` (not `required`) seems right** for the new attribute, since
  `digital_signature` retains its descriptor role for file/Authenticode signatures
  where the bytes legitimately live in the artifact.

One adjacent gap worth noting (possibly its own issue): fully self-contained
verification also needs the signer certificate to be obtainable. The `certificate`
object carries issuer/serial/validity/fingerprints but not the certificate itself,
so a consumer with no prior relationship to the producer still needs an out-of-band
cert store — echoing the PKCS#7 point raised in the #1661 review. A `data`/`pem`
attribute on `certificate` (or a defined external-reference convention) would close
that loop; happy to open a separate issue if useful.

If Option A lands, we'll drop our extension and align with the official attribute.
Happy to share the implementation once we publish it, or draft the schema PR for
Option A if that helps move this along.
```

## Post-landing checklist (when an official attribute exists)

1. Update `ocsfext/integrity` (or remove it) and regenerate the `ocsf/` bindings.
2. Rename `SignatureValue` usage in `recordintegrity` (sign + verify paths) to the
   official attribute; add `encoding_id` handling if Option A lands with the enum.
3. Regenerate `ocsf/ocsfdata` so the embedded schema and validator accept the
   official attribute.
4. Update ocsf-lake (`pkg/integrity`, `ocsflake sign`/`verify`) and both READMEs.
