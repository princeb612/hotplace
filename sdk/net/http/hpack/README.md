### HPACK implementation

This directory implements HPACK, the HTTP/2 header compression format.

The source provides the HPACK encoder and the static/dynamic table handling built on the common HTTP compression infrastructure. Protocol framing remains under the HTTP/2 implementation.
