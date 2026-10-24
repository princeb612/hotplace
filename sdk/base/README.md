## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & behavior│
└──────────────────────────────────────────────┘
```

# Base SDK

## 1. Role

`sdk/base` contains reusable low-level facilities shared by higher-level hotplace modules. Its scope includes value and byte representations, encoders, data structures and algorithms, in-memory streams and strings, operating-system-adjacent helpers, and the logging/test infrastructure used by the project's own test programs.

This is a foundation layer, not a protocol implementation. TLS, QUIC, ASN.1, HTTP, and other higher-level modules may use base primitives, but protocol rules, wire-message sequencing, and protocol-specific validation belong to those higher layers.

The directory is not one unified runtime framework. Its components have different responsibilities and ownership rules: a `variant`, an in-memory stream, a graph, a string helper, and a synchronization primitive should be understood through their own interfaces and implementations.

## 2. Data Model

### Directory map

```text
sdk/base
├── basic
│   ├── command line, customized printf/stream, memory dump
│   ├── function pipeline, variant, valist, CRC
├── encoding
│   └── Base16, Base64, Huffman coding
├── types and numeric values
│   └── binary, endian, IEEE 754, bignumber, decimal/rational floating point
├── unittest
│   └── testcase, logger, trace
├── nostd
│   └── containers, binary/value helpers, ranges/sets, traits/utilities
├── stream
│   └── ANSI/wide strings, binary stream, splitter
├── string
│   └── string helpers, compile-time/runtime obfuscation
├── system
│   └── time, process, redirection, directory, synchronization/thread helpers
├── data structures
│   └── AVL tree, B-tree, list, priority queue, vector
├── pattern
│   └── KMP, trie, suffix structures, Aho-Corasick, wildcard, regex
└── graph
    └── BFS, DFS, Dijkstra, topological sort, graph-structured stack
```

### How the directories divide responsibility

- `basic` contains general-purpose helpers such as `variant`, `valist`, `function_pipeline`, command-line handling, memory dumps, and CRC support. These utilities provide reusable representations or operations; they do not assign protocol meaning to their inputs.
- `encoding` contains byte/text encoding facilities such as Base16, Base64, and Huffman coding. These transform representations and are distinct from generic value containers in `basic`.
- `nostd` contains project-owned C++11-oriented STL-style utilities, including containers, byte/value helpers, range/set abstractions, traits, and conversion helpers. The name does not imply that every component is a drop-in replacement for a standard-library type.
- `stream` and `string` provide in-memory buffering, formatting, string manipulation, and obfuscation utilities. They should not be conflated with the external-I/O adapters under `sdk/io`.
- `system` contains time/date helpers, synchronization, process and standard-I/O redirection interfaces, directory helpers, thread-related utilities, and platform-sensitive implementations.
- Data structures, pattern matching, and graph algorithms are separate algorithm families. The graph-structured stack is a specialized consumer of graph-shaped storage for parser implementation, not a protocol-independent parser by itself.
- `unittest` supplies infrastructure for hotplace's own test programs. Its presence does not mean that every SDK consumer must adopt it as an application testing framework.
- Root-level headers define shared contracts and conventions: [shared types](types.md), [error codes](error.md), [callbacks](callback.md), [character-set compatibility](charset.md), [inline helpers](inline.md), [control-flow macros](syntax.md), and the abstract [stream interface](stream.md).
- Root-level [trace controls](trace.md) define event/option identifiers; they are distinct from the [system trace implementation](system/trace.md).
- The [C++14 entry point](c++14.md) is a narrow wrapper for the isolated compile-time string-obfuscation experiment, not a project-wide change in language baseline.

## 3. Behavior Model

### Representation and interpretation are separate

Base facilities store, transform, format, or organize data. Higher-level components decide what that data means in a protocol or application.

- `dump_memory` formats bytes for diagnostics; it does not validate a protocol message.
- `variant` represents values and supports conversions; it does not define the wire format or negotiation rules for a protocol.
- An encoding routine transforms an input representation into an output representation; it does not by itself establish that the input is semantically valid for a higher-level protocol.
- A graph algorithm computes traversal, ordering, or path results; the consuming parser or application determines how those results are interpreted.
- A base stream manages in-memory data; external I/O, buffering policy, and transport lifecycle are owned by the relevant adapter or higher layer.

These distinctions are useful when following an implementation call: identify the base operation, then identify the caller that gives the result protocol- or application-specific meaning.

### Lifetime and platform sensitivity

There is no single lifetime rule for all of `sdk/base`. The ownership contract must be checked at the specific type or function boundary. Value containers, stream buffers, graph nodes, and OS synchronization/process objects do not necessarily share the same ownership model.

Some facilities are ABI- or platform-sensitive. For example, `valist` reconstructs argument representations used by the project's formatting interface; native `va_list` layout is not portable across all compilers and ABIs. Synchronization, thread, console, process, and standard-I/O redirection code likewise requires attention to the target OS and compiler implementation.

### Language baseline

The project's general compatibility target is C++11. Isolated experiments, including compile-time string obfuscation, may use newer language features; those exceptions must not be interpreted as broad C++14-or-later support for the SDK.

### Verification boundary

Test source and execution reports answer different questions. Source code reveals what a testcase attempts to assert; a report records results for a particular run and environment. The existence of a testcase is not proof that it was executed, and a report without a matching source revision and environment should not be treated as evidence that the exact current tree passed on that platform.

## 4. Relationships

### Dependency direction

```text
             higher-level hotplace modules
        (protocols, parsers, crypto, applications)
                         │
                         ▼
                 reusable sdk/base
       ┌──────────┬───────────┬───────────┐
       │ values   │ algorithms│ in-memory │
       │ encoding │ data      │ streams   │
       │ types    │ structures│ helpers   │
       └──────────┴───────────┴───────────┘
                         │
                         ▼
             platform / standard library
```

This diagram shows the intended architectural direction, not a complete include graph. Individual dependencies and ownership relationships must be confirmed in the relevant source files.

### Concrete cross-module relationships

- `sdk/base/stream` provides in-memory stream and buffer operations; `sdk/io/stream` adapts stream behavior to external I/O. The two layers are related but not interchangeable.
- `sdk/base/unittest` uses logging and trace facilities to make the project's testcase execution and diagnostic output observable.
- `sdk/base/basic/variant.hpp` provides generic value representation used by facilities such as `valist`.
- `sdk/base/graph/gss.hpp` provides graph-shaped stack storage used by `sdk/io/parser/glr_parser.cpp`. The parser owns grammar and parsing semantics; the base graph component supplies a reusable storage mechanism.
- Pattern-matching facilities under `sdk/base/pattern` are consumed by higher-level string/parser paths where appropriate. Their individual documents describe algorithm-specific state and behavior rather than treating all matchers as one interchangeable engine.
- Source-level test coverage for this layer is organized under [`test/testcase/base/`](../../test/testcase/base/); testcase documentation owns detailed coverage and verification status so those claims do not need to be duplicated in every SDK module document.
- The [compile-time string-obfuscation](string/constexpr-obfuscation.md) and [big-number](system/bignumber.md) pages retain focused details that do not belong in a directory map. The [pattern overview](pattern/README.md) compares algorithm families and their selection criteria.

## 5. References

### Books

- *Data Structures and Algorithm Analysis in C++*
  - Binary search trees: §4.3, “The Search Tree ADT – Binary Search Trees”
  - Lists and vectors: Chapter 3, “Lists, Stacks, and Queues”
  - KMP: §12.3.3, “The Knuth-Morris-Pratt Algorithm”
  - Priority queues: Chapter 6, “Priority Queues (Heaps)”
- *Data Structures and Algorithms in C++*

### Standards and specifications

- [RFC 4648 — The Base16, Base32, and Base64 Data Encodings](https://www.rfc-editor.org/rfc/rfc4648)
- [IEEE 754](https://en.wikipedia.org/wiki/IEEE_754)

### Articles and online resources

- Dynamic `va_list` discussion: https://stackoverflow.com/questions/11695237/creating-va-list-dynamically-in-gcc-can-it-be-done
- Aho-Corasick:
  - https://www.javatpoint.com/aho-corasick-algorithm-for-pattern-searching-in-cpp
  - Failure links and output: https://daniel.lawrence.lu/blog/y2014m03d25/
- Dijkstra: https://en.wikipedia.org/wiki/Dijkstra%27s_algorithm
- Graph visualization: https://graphonline.ru/en/
- Pattern-matching overview: https://www.geeksforgeeks.org/
- Suffix tree:
  - https://www.geeksforgeeks.org/pattern-searching-using-trie-suffixes/
  - Ukkonen animation: https://brenden.github.io/ukkonen-animation/
  - https://programmerspatch.blogspot.com/2013/02/ukkonens-suffix-tree-algorithm.html
  - https://www.geeksforgeeks.org/ukkonens-suffix-tree-construction-part-1/
- Trie:
  - https://www.geeksforgeeks.org/trie-data-structure-in-cpp/
  - https://www.geeksforgeeks.org/auto-complete-feature-using-trie/
- Wildcard matching: https://www.geeksforgeeks.org/wildcard-pattern-matching/
- Big-number calculator: https://www.calculator.net/big-number-calculator.html
- IEEE 754 and floating-point:
  - https://en.wikipedia.org/wiki/Floating-point_arithmetic
  - https://en.wikipedia.org/wiki/Half-precision_floating-point_format
  - https://en.wikipedia.org/wiki/Single-precision_floating-point_format
  - Goldberg's floating-point article: https://docs.oracle.com/cd/E19957-01/806-3568/ncg_goldberg.html
  - Cambridge lecture slides: https://www.cl.cam.ac.uk/teaching/1011/FPComp/fpcomp10slides.pdf
  - https://www.youtube.com/watch?v=8afbTaA-gOQ
  - https://www.corsix.org/content/converting-fp32-to-fp16
  - https://blog.fpmurphy.com/2008/12/half-precision-floating-point-format_14.html
- IEEE 754 converters:
  - https://www.h-schmidt.net/FloatConverter/IEEE754.html
  - https://baseconvert.com/ieee-754-floating-point
  - https://www.omnicalculator.com/other/floating-point

## 6. Developer Notes

### C++ Standard and GCC notes retained from the original README

The following table is preserved as a historical maintainer note. It records the standard labels and approximate GCC versions from the original document; it is not a current compatibility guarantee and should be revalidated before being used as a support matrix.

| C++ label in original note | GCC version noted | Original reference |
|---|---:|---|
| c++0x | 4.3+ | — |
| c++11 | 4.7+ | https://en.cppreference.com/w/cpp/compiler_support/11 |
| c++1y | 4.8+ | — |
| c++14 | 5.1+ | https://en.cppreference.com/w/cpp/compiler_support/14 |
| c++1z | 6.1+ | — |
| c++17 | 7.1+ | https://en.cppreference.com/w/cpp/compiler_support/17 |
| c++2a | 8.1+ | — |
| c++20 | 10.1+ | https://en.cppreference.com/w/cpp/compiler_support/20 |
| c++23 | 11.1+ | https://en.cppreference.com/w/cpp/compiler_support/23 |

Additional original reference: https://gcc.gnu.org/projects/cxx-status.html

The project-wide intention is C++11 compatibility. Newer-standard experiments should remain clearly isolated and should not be used to imply that the entire SDK has moved to a newer baseline.
