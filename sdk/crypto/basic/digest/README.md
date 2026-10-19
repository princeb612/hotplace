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

### Digest and transcript-hash primitives

This directory implements message-digest primitives and transcript-hash support.

It contains the generic hash/digest builders plus OpenSSL-backed implementations and the transcript-hash abstraction used by protocol code such as TLS.

The directory provides the primitive interface; algorithm identifiers and metadata are handled by `crypto/advisor`.

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
