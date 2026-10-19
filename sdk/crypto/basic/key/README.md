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

### Key objects, key generation and key exchange

This directory contains key objects, key generation, key extraction/search and key-exchange support.

The implementation covers DH, DSA, EC/EC variants, OKP, RSA, octet keys and OpenSSL 3-related key handling. Key exchange and key generation are represented alongside the key object layer because higher-level crypto code uses the same abstractions.

Concrete algorithm metadata is resolved through the crypto advisor.

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
