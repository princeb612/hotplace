### TLS/DTLS/QUIC session support

This directory contains session-level machinery used by TLS, DTLS and QUIC.

The source includes TLS session handling, DTLS record arrangement/publishing, QUIC packet publishing/session/stream support and SSLKEYLOG import/export helpers. It sits above the protocol primitives and below higher-level socket/application flows.
