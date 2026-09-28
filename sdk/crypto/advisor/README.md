### Cryptographic algorithm and parameter advisor

The crypto advisor provides the mapping layer between algorithm names/identifiers and the cryptographic implementations used by hotplace.

It contains advisor data for ciphers, digests, curves, keys, signatures, COSE/JOSE algorithms and integration with OpenSSL identifiers. The resource tables in this directory back the lookup functions exposed by `crypto_advisor`.

This is an algorithm/parameter lookup facility, not another cryptographic primitive implementation.
