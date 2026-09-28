### Digest and transcript-hash primitives

This directory implements message-digest primitives and transcript-hash support.

It contains the generic hash/digest builders plus OpenSSL-backed implementations and the transcript-hash abstraction used by protocol code such as TLS.

The directory provides the primitive interface; algorithm identifiers and metadata are handled by `crypto/advisor`.
