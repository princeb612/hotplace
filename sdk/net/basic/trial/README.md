### Network socket and TLS/QUIC trial implementations

This directory contains the experimental/integration-oriented networking layer used to compose sockets, sessions and secure protocols.

It includes client/server socket adapters, producer/consumer socket flows, secure sockets and the TLS composer used for TLS/DTLS/QUIC handshake integration. The `trial_*` classes represent this higher-level integration path rather than the minimal socket wrappers under `naive`.
