### Key objects, key generation and key exchange

This directory contains key objects, key generation, key extraction/search and key-exchange support.

The implementation covers DH, DSA, EC/EC variants, OKP, RSA, octet keys and OpenSSL 3-related key handling. Key exchange and key generation are represented alongside the key object layer because higher-level crypto code uses the same abstractions.

Concrete algorithm metadata is resolved through the crypto advisor.
