## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# Digest And Mac

## 1. Role

This document identifies the module or reference topic represented by this file.

## 2. Model

The model, structure, or retained explanatory material is described where the existing source-tree notes provide evidence.

## 3. Important behavior and lifetime

Implementation behavior is documented only to the extent supported by the retained notes and source references.

## 4. Example from the source tests

### digest tested

### CMAC

  * AES-CBC-MAC

### HMAC

| alg         | DIGEST | HMAC |
| --          | --     | --   |
| md4         |    O   |  O   |
| md5         |    O   |  O   |
| sha1        |    O   |  O   |
| sha224      |    O   |  O   |
| sha384      |    O   |  O   |
| sha512      |    O   |  O   |
| sha3 224    |    O   |  O   |
| sha3 256    |    O   |  O   |
| sha3 384    |    O   |  O   |
| sha3 512    |    O   |  O   |
| shake128    |    O   |      |
| shake256    |    O   |      |
| blake2b 512 |    O   |  O   |
| blake2s 256 |    O   |  O   |
| ripemd160   |    O   |  O   |
| whirlpool   |    O   |  O   |

#### digest

| algorithm    | bits | dlen |
| --           | --   | --   |
| md5          |  128 |   16 |
| sha1         |  160 |   20 |
| sha2_224     |  224 |   28 |
| sha2_256     |  256 |   32 |
| sha2_384     |  384 |   48 |
| sha2_512     |  512 |   64 |
| sha2_512_224 |  224 |   28 |
| sha2_512_256 |  256 |   32 |
| sha3_224     |  224 |   28 |
| sha3_256     |  256 |   32 |
| sha3_384     |  384 |   48 |
| sha3_512     |  512 |   64 |

## 5. Relationships

Related implementation modules and protocol boundaries are recorded here where identified.

## 6. References

Relevant source paths, sibling documentation, and standards references are retained here where available.
