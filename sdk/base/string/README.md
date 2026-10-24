## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1107                    │
│ Source basis: Revision 1107                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & behavior│
└──────────────────────────────────────────────┘
```

# Base String

## 1. Role

`sdk/base/string` provides general-purpose string and bounded-buffer helpers used by SDK code. It contains scanning and line/token extraction, formatting and replacement, delimiter splitting, string wrapper types, and two distinct obfuscation facilities.

This is the general base layer. It is separate from `sdk/base/stream` (stream-oriented output and buffering) and `sdk/io/string` (I/O/protocol-facing string handling).

## 2. Data Model

### Component map

| Component | Main responsibility | Distinction |
|---|---|---|
| [String utilities](string.md) | `format`, `replace`, `scan`, `getline`, token helpers, and string wrappers | General string processing and bounded-buffer operations |
| [Split context](split.md) | Delimiter splitting with source-relative ranges | Exposes segments/ranges rather than acting as a general tokenizer framework |
| [String obfuscation](obfuscation.md) | Runtime `obfuscate_string` and output conversions | Runtime transformation path |
| [Compile-time obfuscation](constexpr-obfuscation.md) | `constexpr_obfuscate` facility | Separate compile-time experiment; requires C++14+ and is not part of the C++11 baseline |

The components share a string-oriented scope, but the two obfuscation facilities have different execution and language-standard requirements. They should not be treated as one interchangeable API.

The ownership distinction is part of the data contract: `split_context_t` retains a source copy and range indexes, while general bounded-buffer helpers operate on caller-supplied memory. Runtime and compile-time obfuscation have different language-standard requirements; neither is encryption.

## 3. Behavior Model

### Source-flow overview

```text
bounded input ─► scan / getline / tokenize ─► positions and extracted text
source string ─► split_begin ─► owned source + {begin, length} ranges
                                  ├─ split_get(index) ─► one materialized fragment
                                  └─ foreach(callback) ─► visit fragments

literal ─► constexpr_obfuscate (C++14+) ─► transformed compile-time representation
text ─────► obfuscate_string (runtime) ─► transformed object bytes ─► reconstruction on output
```

The string helpers do not all own their results in the same way. `split_context_t` retains its own source copy and indexes fragments by range, while the general bounded-buffer helpers operate on caller-supplied memory. Runtime and compile-time obfuscation are separate facilities with different language-standard requirements; neither is encryption.

String wrappers, bounded buffers, and split ranges may have different lifetime and ownership constraints. Check the individual declarations and implementation before retaining references into input buffers or assuming a returned segment owns its characters.

The compile-time obfuscation note is intentionally retained as an isolated C++14+ facility. It should not be interpreted as a change to hotplace's overall C++11 support target. Runtime obfuscation is a separate facility and should be reviewed according to its own conversion and output behavior.

String operations do not automatically provide protocol parsing or validation. For example, splitting text into segments does not establish whether those segments satisfy a URL, HTTP, or other protocol grammar; the higher-level consumer owns that interpretation.

## 5. Relationships

- `sdk/base/stream/` — stream formatting and buffered output, distinct from string algorithms.
- `sdk/io/string/` — URL, tokenization and platform character-conversion utilities used closer to I/O and protocol boundaries.
- [String testcase guide](../../../test/testcase/base/string/README.md) — source examples and verification notes. The principal test source is `testcase_string.cpp`; assertions and report-derived verification belong in the testcase document.

## 6. References

No external references are listed.
