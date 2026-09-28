### HTTP/2 frame and protocol implementation

This directory contains the HTTP/2 frame and protocol implementation.

The source defines the common frame abstraction, frame builder and individual HTTP/2 frame types such as DATA, HEADERS, CONTINUATION, GOAWAY, PING and other protocol frames.

Header compression itself is provided by the shared compression/HPACK layer.
