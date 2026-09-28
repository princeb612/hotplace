### Key derivation functions

This directory implements key-derivation functions through the OpenSSL-backed crypto layer.

The source includes generic KDF support and implementations for AES-based KDF, Argon, PBKDF2, scrypt and TLS-related derivation.

These functions are consumed by higher-level cryptographic protocols rather than exposing a separate protocol implementation.
