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

### Digital signatures and MAC signing

This directory contains the signing and signature-verification layer.

The source provides generic signing builders and digest-sign support together with OpenSSL-backed implementations for DSA, ECDSA, EdDSA, HMAC, ML-DSA, RSA PKCS#1 v1.5, RSA-PSS and SLH-DSA.

It is the primitive signing layer used by protocol-specific code such as COSE, JOSE and certificate-related processing.

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
