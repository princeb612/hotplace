## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# Cipher

## 1. Role

This document identifies the module or reference topic represented by this file.

## 2. Model

The model, structure, or retained explanatory material is described where the existing source-tree notes provide evidence.

## 3. Important behavior and lifetime

Implementation behavior is documented only to the extent supported by the retained notes and source references.

## 4. Example from the source tests

### cipher tested

| alg       | CBC | CFB | CFB1 | CFB8 | CTR | ECB | GCM | OFB | KEYWRAP |
| --        | --  | --  | --   | --   | --  | --  | --  | --  | --      |
| AES       |  O  |  O  |  O   |  O   |  O  |  O  |  O  |  O  |    O    |
| ARIA      |  O  |  O  |  O   |  O   |  O  |  O  |  O  |  O  |         |
| BF        |  O  |  O  |      |      |     |  O  |     |  O  |         |
| CAMELLIA  |  O  |  O  |  O   |  O   |  O  |  O  |     |  O  |         |
| CAST      |  O  |  O  |      |      |     |  O  |     |  O  |         |
| DES       |  O  |  O  |      |      |     |  O  |     |  O  |         |
| IDEA      |  O  |  O  |      |      |     |  O  |     |  O  |         |
| RC2       |  O  |  O  |      |      |     |  O  |     |  O  |         |
| RC5       |  O  |  O  |      |      |     |  O  |     |  O  |         |
| SEED      |  O  |  O  |      |      |     |  O  |     |  O  |         |
| SM4       |  O  |  O  |      |      |     |  O  |     |  O  |         |

#### block cipher

| algorithm   | key | iv |
| --          | --  | -- |
| AES128      | 16  | 16 |
| AES192      | 24  | 16 |
| AES256      | 32  | 16 |
| blowfish    | 16  |  8 |
| aria128     | 16  | 16 |
| aria192     | 24  | 16 |
| aria256     | 32  | 16 |
| camellia128 | 16  | 16 |
| camellia192 | 24  | 16 |
| camellia256 | 32  | 16 |
| chacha20    | 32  | 12 |

## 5. Relationships

Related implementation modules and protocol boundaries are recorded here where identified.

## 6. References

Relevant source paths, sibling documentation, and standards references are retained here where available.
