# COSE message model

The structural core of `sdk/crypto/cose` is the `cose_layer` representation exposed through `cose_composer` and its component classes.

## Layer fields

A layer can carry:

- protected headers (`cose_protected`)
- unprotected headers (`cose_unprotected`)
- payload/ciphertext (`cose_binary`)
- tag/signature/single-item fields
- nested recipients (`cose_recipients`)
- unsent/context parameters (`cose_unsent`)

`cose_recipient` and the signature/countersignature types reuse the same layer-oriented representation, which allows nested COSE structures to be processed recursively.

## Why the split matters

COSE distinguishes encoded protected headers from directly represented unprotected headers. It also distinguishes the payload from the cryptographic result and represents recipient/key-distribution information separately. The hotplace model keeps these boundaries visible instead of reducing a message to a generic CBOR map.

## Composer role

`cose_composer` is the construction/access layer. It exposes the current layer and the individual COSE fields so callers can build messages before cryptographic processing.

`cbor_object_signing_encryption` consumes this model and performs the cryptographic operations. This separates message construction from the crypto backend.

## Related implementation

- `cose_data.*` — value and identifier representation.
- `cose_binary.*` — binary payload wrapper.
- `cose_protected.*` / `cose_unprotected.*` — header containers.
- `cose_recipient.*` / `cose_recipients.*` — recipient nesting.
- `cose_countersign.*` / `cose_countersigns.*` — countersignature nesting.
