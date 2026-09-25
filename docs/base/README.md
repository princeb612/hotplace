# Base

## Context

`sdk/base` is the lowest common layer of the hotplace SDK. It does not represent one protocol or one cryptographic function. Its role is to provide the small, reusable mechanisms on which higher SDK layers can build.

The important relationship is:

```text
sdk/base
   │
   ├── data / representation
   ├── algorithms / pattern processing
   ├── runtime / platform
   ├── diagnostics / error
   └── verification support
          │
          ▼
        sdk/io
          │
          ▼
       sdk/crypto
          │
          ▼
        sdk/net
```

The build structure confirms this role: `sdk-io` depends on `sdk-base`, `sdk-crypto` depends on base and io, and `sdk-net` depends on base, io, and crypto.

Base should therefore be understood as a **foundation of reusable semantics and portability mechanisms**, rather than as a miscellaneous utility directory.

## History

The base layer has grown alongside the rest of hotplace. Early reusable facilities such as strings, streams, encoding, callbacks, errors, tracing, pattern matching, and system abstraction later became prerequisites for parser, cryptographic, and network work.

The historical record also shows repeated optimization and portability work in these areas. The resulting `nostd`, system abstractions, and compatibility-oriented code now provide a useful boundary for environments where newer language/library facilities cannot be assumed.

The source history should not be read as evidence that every base facility was designed as one unified subsystem from the beginning. The current structure is better understood as the accumulated common foundation that higher layers came to depend on.

## Conceptual

The central question for base is:

> **What functionality is sufficiently general that protocol, cryptography, parser, and application code should not have to implement it independently?**

A useful conceptual grouping is:

```text
sdk/base
├── Foundation
│   ├── types
│   ├── nostd
│   └── basic
│
├── Representation
│   ├── string
│   ├── stream
│   └── encoding
│
├── Algorithms
│   ├── pattern
│   └── graph
│
├── Runtime / Platform
│   ├── system
│   ├── callback
│   ├── error
│   └── trace
│
└── Verification support
    └── unittest
```

These are semantic groups, not a claim that the source directory layout must exactly match them.

### Foundation

The foundation layer provides basic types, controlled standard-library compatibility, and small general-purpose building blocks.

`nostd` is particularly important in hotplace because it is not merely a convenience wrapper around STL. It provides a controlled compatibility boundary for environments where newer C++ facilities cannot be assumed.

This fits the project's C++11-first portability goal:

```text
application code
      │
      ▼
hotplace abstraction
      │
      ├── modern implementation when available
      └── compatibility implementation when required
      │
      ▼
old compiler / old OS
```

### Representation

Base provides reusable representations such as strings, streams, and encodings.

The distinction between representation and protocol meaning is important:

```text
base
  = how data is represented / manipulated

payload
  = how protocol fields are laid out

protocol
  = what those fields mean
```

For example, Base64, radix64, Huffman-related facilities, stream buffers, and string handling can be reused by higher layers without knowing whether the data belongs to TLS, HTTP, ASN.1, or another protocol.

### Algorithms and pattern processing

The `pattern` and related algorithm facilities provide reusable mechanisms such as trie/Aho-Corasick/wildcard processing.

These become especially relevant to lexical analysis and parser work:

```text
input
  ↓
pattern matching
  ↓
lexical recognition
  ↓
parser
  ↓
semantic construction
```

The algorithm layer should therefore not be documented as a parser subsystem. It is a reusable substrate consumed by parser/lexer code.

### Runtime and platform

Base also absorbs differences that higher layers should not need to handle repeatedly:

```text
application
   │
   ▼
base runtime abstraction
   │
   ├── system
   ├── callback
   ├── error
   └── trace
   │
   ▼
platform / operating system
```

This is where portability becomes an architectural property rather than a collection of compiler flags.

### Error and diagnostics

Error, logging, tracing, and result/status facilities give higher layers a common way to report and propagate operational state.

The important distinction is:

```text
protocol error
    ≠
base error mechanism
```

Base supplies the mechanism for representing/reporting an error; TLS, ASN.1, HTTP, etc. give that mechanism domain-specific meaning.

This separation is one reason the error model can be reused across otherwise unrelated modules.

### Verification support

`unittest` belongs in base because test infrastructure is used throughout the repository.

Its role is not to define protocol tests. It provides the common assertion, test-case, reporting, and verification mechanics used by higher-level test suites.

## Structural

### Source organization

The source tree contains a broad set of small facilities rather than one large base subsystem.

The structural relationship is therefore:

```text
sdk/base
    │
    ├── common headers/types
    ├── string / stream
    ├── encoding
    ├── pattern / algorithm
    ├── system / runtime
    ├── callback
    ├── error / trace
    └── unittest
```

The exact source directories are implementation details; the stable architectural boundary is that these facilities can be consumed without depending on `sdk/crypto` or `sdk/net`.

### Base → IO

The build dependency is:

```text
sdk-base
    ↓
sdk-io
```

Conceptually:

```text
base
  ├── representation
  ├── runtime
  └── portability
          ↓
io
  ├── payload
  ├── file / socket / stream-related facilities
  └── I/O processing
```

The direction matters: base should not depend on protocol/network semantics supplied by IO.

### Base → Crypto

Crypto builds on common representations, runtime, and error mechanisms:

```text
base
   │
   ├── bytes / strings
   ├── stream / representation
   ├── runtime
   └── error
          │
          ▼
       crypto
```

Crypto then supplies domain-specific meaning such as keys, encryption, signatures, MACs, KDFs, and algorithm selection.

### Base → Parser

The parser path is another important consumer:

```text
base
  │
  ├── string / stream
  ├── pattern
  ├── syntax support
  └── runtime / error
        │
        ▼
      lexer
        │
        ▼
      parser
        │
        ▼
 semantic construction
```

The base layer therefore enables parser implementation without becoming an ASN.1-specific layer.

### Base → Network

Network code consumes the common runtime and representation facilities:

```text
base
  │
  ├── stream
  ├── callback
  ├── system
  ├── error
  └── trace
        │
        ▼
 network I/O / session / protocol
```

This allows the network layer to concentrate on session, transport, framing, and protocol semantics.

### C++11 / C++14 boundary

The source also contains standard-version-specific facilities.

The architectural point is not that C++11 and C++14 are two different SDKs. The intended direction is:

```text
same conceptual interface
          │
          ├── C++11-compatible implementation
          │
          └── C++14 implementation where available
```

This matches the broader project goal of keeping a portable interface while allowing implementation techniques to vary with compiler capability.

The exact standard-specific implementation should remain source documentation rather than being elevated into a separate conceptual layer unless the interface contract itself differs.

## Flow

A typical higher-level operation can be understood as:

```text
protocol / application request
          │
          ▼
   base representation
          │
          ├── string
          ├── stream
          ├── encoding
          └── basic types
          │
          ▼
     domain-specific layer
          │
          ├── payload
          ├── parser
          ├── crypto
          └── network
          │
          ▼
       result / error
          │
          ▼
     base diagnostics
```

For parser processing:

```text
input bytes/text
      ↓
base string / stream
      ↓
pattern / lexical support
      ↓
parser
      ↓
semantic object
```

For protocol encoding:

```text
application/domain object
      ↓
protocol field model
      ↓
payload
      ↓
base byte/stream representation
      ↓
wire data
```

For cryptographic processing:

```text
protocol data
      ↓
base representation
      ↓
crypto operation
      ↓
crypto result
      ↓
higher protocol
```

Base is therefore usually **inside the flow**, not the endpoint of the flow.

## Study & Verification

Base facilities are indirectly verified by the higher layers that depend on them, while reusable facilities also have their own tests where appropriate.

Useful verification relationships include:

```text
base facility
     ↓
direct unit test
     +
higher-level consumer
     ↓
integration behavior
```

For example, pattern-processing facilities can be consumed by lexical or text-processing code:

```text
pattern / matching facility
  ↓
lexical or text-processing code
  ↓
parser tests
```

or:

```text
stream
  ↓
network_stream
  ↓
HTTP / TLS / QUIC processing
```

or:

```text
encoding
  ↓
protocol/security representation
  ↓
test vector
```

This layered verification is important because a base component can be locally correct while a higher layer uses its contract incorrectly.

## Status

At Revision 1090:

- `sdk/base` is the common dependency root for the higher SDK layers.
- Its role is broader than a generic utility collection: it provides reusable representation, algorithm, runtime, portability, diagnostics, and verification mechanisms.
- `nostd` is a collection of project-local utilities outside the C++ standard library. Its use can also help isolate environment-dependent functionality, which is useful for hotplace's portability goals.
- Base representation facilities are reused by IO, parser, crypto, and network code.
- Pattern/algorithm facilities support parser/lexical processing without becoming parser-specific.
- Error/trace/runtime facilities provide common mechanisms while higher layers retain domain semantics.
- The C++11/C++14 distinction is best treated as an implementation/compatibility dimension rather than two unrelated architectural layers.

At this point, a file-by-file inventory of every base utility would add little to the architectural document. Individual facilities should be documented when a higher-level topic needs their specific contract.

## Related topics

- [Build](../build/README.md)
- [Payload](../io/payload/README.md)
- [Crypto](../crypto/README.md)
- [Parser](../io/parser/README.md)
- [Network Server](../network_server/README.md)
