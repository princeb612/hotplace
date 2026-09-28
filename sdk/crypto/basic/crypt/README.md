### Encryption and AEAD primitives

This directory implements encryption primitives and AEAD support.

The source includes the generic encryption/AEAD abstractions and builders together with OpenSSL-backed cipher implementations. The implementation covers the cipher-oriented layer used by higher crypto protocols.

Algorithm-specific compatibility and lookup information is handled separately by the crypto advisor.
