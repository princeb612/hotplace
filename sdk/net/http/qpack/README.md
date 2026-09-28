### QPACK implementation

This directory implements QPACK, the HTTP/3 header compression format.

It contains the QPACK encoder and static/dynamic table handling, using the common HTTP header-compression abstractions. HTTP/3 framing and QUIC transport remain in their respective modules.
