### Common I/O data and payload utilities

This directory provides common I/O-side data structures and utility functions used by higher-level protocol implementations.

The main pieces include `payload` and `payload_member` for structured binary/message data, OID string conversion, zlib compression helpers and common I/O types.

Protocol-specific encodings and parsers build on these primitives.
