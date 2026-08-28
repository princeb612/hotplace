## QUIC (Quick UDP Internet Connections) - published by Gemini

---

### 1. Overview and Key Features

* **Module Role**: A C++11 implementation module performing UDP-based reliable and low-latency transport layer operations in compliance with RFC 9000 (QUIC Transport Protocol) and RFC 9001 (QUIC TLS Securing) specifications.
* **Key Features**:
  * **QUIC Frame Parsing and Generation**: Implements unit-level builders/parsers for frames including ACK, STREAM, CRYPTO, PING, PADDING, RESET_STREAM, STOP_SENDING, NEW_CONNECTION_ID, NEW_TOKEN, and CONNECTION_CLOSE.
  * **QUIC Packet Layer Control**: Constructs packet structures and executes binary encoding/decoding for Initial, 0-RTT, Handshake, 1-RTT, Retry, and Version Negotiation packets.
  * **Session and Stream Management**: Manages unidirectional/bidirectional stream states and handles session lifecycles via `quic_session` and `quic_streams`.
  * **HTTP/3 Integration Layer**: Supports HTTP/3 stream frame processing (`quic_frame_http3_stream`).
  * **Packet Publishing & Header Protection**: Handles packet transmission/reception publishing and integrates TLS protection layers via `quic_packet_publisher`.

---

### 2. Core Classes and Module Structure

**QUIC Core Module Configuration**

```cpp
namespace hotplace {

// QUIC session and stream management
class quic_session;
class quic_streams;

// QUIC packet and builder
class quic_packet;
class quic_packet_builder;
class quic_packet_publisher;

// QUIC frame and builder
class quic_frame;
class quic_frame_builder;

// HTTP/3 mapping frame
class quic_frame_http3_stream;

}  // namespace hotplace

```

---

### 3. Core Operating Mechanism

* **Packet and Frame Builder Structure (`quic_packet_builder`, `quic_frame_builder`)**:
  * Assembles binary streams using the builder pattern for each packet type (Initial, Handshake, 1-RTT, etc.) and frame type.
* **TLS 1.3-Based Handshake Integration (`quic_packet_initial`, `quic_packet_handshake`)**:
  * Delivers TLS 1.3 handshake messages (`tls_extension_quic_transport_parameters`) via QUIC CRYPTO frames and integrates Header Protection and 1-RTT key derivation.
* **Stream Multiplexing (`quic_streams`)**:
  * Processes data across multiple independent streams in parallel within a single QUIC connection while managing flow control and RESET_STREAM / STOP_SENDING frames.

---

### 4. TODO List Tracker

| No. | Task Description | Priority | Status |
| --- | --- | --- | --- |
| **TODO-QUIC-01** | Add unit tests for Packet Number encoding/decoding (with Header Protection applied) in `quic_packet_1rtt` | High | Open |
| **TODO-QUIC-02** | Add ACK Range parsing validity checks and implement ack-eliciting logic when processing `quic_frame_ack` | High | Open |
| **TODO-QUIC-03** | Strengthen stream count limits (Max Streams) and flow control window monitoring in the `quic_streams` module | Medium | Open |
| **TODO-QUIC-04** | Supplement validation and exception handling logic for `quic_packet_retry` and `quic_packet_0rtt` packets | Medium | Open |
| **TODO-QUIC-05** | Establish the HTTP/3 QPACK header compression integration interface in `quic_frame_http3_stream` | Low | Open |
