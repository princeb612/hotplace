### Digital signatures and MAC signing

This directory contains the signing and signature-verification layer.

The source provides generic signing builders and digest-sign support together with OpenSSL-backed implementations for DSA, ECDSA, EdDSA, HMAC, ML-DSA, RSA PKCS#1 v1.5, RSA-PSS and SLH-DSA.

It is the primitive signing layer used by protocol-specific code such as COSE, JOSE and certificate-related processing.
