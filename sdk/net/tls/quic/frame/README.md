### QUIC frame implementation

This directory contains QUIC frame implementations.

The frame layer represents the individual QUIC transport/control frames and their encoding/decoding behavior. It is separated from packet assembly so frame semantics can be handled independently of packet protection and packet layout.
