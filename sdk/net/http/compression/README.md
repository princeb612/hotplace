### HTTP header compression infrastructure

This directory contains the common HTTP header-compression infrastructure.

Dynamic/static tables and header-compression stream support are implemented here and are shared by the HPACK and QPACK implementations. The actual protocol-specific encoders live under `hpack` and `qpack`.
