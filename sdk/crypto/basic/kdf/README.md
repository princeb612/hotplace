## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# Readme

## 1. Role

### Key derivation functions

This directory implements key-derivation functions through the OpenSSL-backed crypto layer.

The source includes generic KDF support and implementations for AES-based KDF, Argon, PBKDF2, scrypt and TLS-related derivation.

These functions are consumed by higher-level cryptographic protocols rather than exposing a separate protocol implementation.

## 2. Model

The model, structure, or retained explanatory material is described where the existing source-tree notes provide evidence.

## 3. Important behavior and lifetime

Implementation behavior is documented only to the extent supported by the retained notes and source references.

## 4. Example from the source tests

See the referenced testcase source files for concrete examples. A source reference alone does not prove runtime execution.

## 5. Relationships

Related implementation modules and protocol boundaries are recorded here where identified.

## 6. References

Relevant source paths, sibling documentation, and standards references are retained here where available.
