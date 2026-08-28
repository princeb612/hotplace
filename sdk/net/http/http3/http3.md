## HTTP/3 Frame & Protocol - published by Gemini

---

### 1. Overview and Key Features

* **Module Role**: An HTTP/3 frame parsing, building, and type control module based on RFC 9114 specifications running over the QUIC protocol.
* **Key Features**:
  * **HTTP/3 Frame Serialization/Deserialization**: Handles DATA, HEADERS, CANCEL_PUSH, SETTINGS, PUSH_PROMISE, GOAWAY, MAX_PUSH_ID, PRIORITY_UPDATE, ORIGIN, and METADATA frames (`http3_frame*.cpp`).
  * **Variable-Length Integer (Varint)-Based Type & Length Processing**: Parses Variable-Length Integer frame types and lengths tailored to QUIC protocol characteristics (`http3_frame.cpp`).
  * **Frame Builder Operations**: Assembles HTTP/3 frames and generates byte streams using the builder pattern (`http3_frame_builder.cpp`, `http3_frame_builder.hpp`).
  * **Unknown Frame Handling**: Provides unknown frame encoding/decoding operations for compatibility with extended or non-standard defined frames (`http3_frame_unknown.cpp`, `http3_frame_unknown.hpp`).

---

### 2. Core Implementation Areas and Technical Elements

* **QUIC Varint and HTTP/3 Frame Header Parsing (`http3_frame.cpp`, `http3_frame_*.cpp`)**:
  * Decodes Variable-Length Integer bytes for HTTP/3 frame Type and Length fields.
  * Controls request stream transmission for DATA and HEADERS frames.
* **Control Stream & Extension Frames (`http3_frame_settings.cpp`, `http3_frame_priority_update.cpp`, `http3_frame_origin.cpp`)**:
  * Integrates state connections with the QPACK Encoder Stream and Control Stream while applying parameter updates.
  * Exchanges QPACK and QUIC session parameters via SETTINGS frames.
  * Processes RFC 9218-based PRIORITY_UPDATE frames alongside extension frames such as ORIGIN and METADATA.
* **Push Control & Termination Frames (`http3_frame_cancel_push.cpp`, `http3_frame_max_push_id.cpp`, `http3_frame_goaway.cpp`)**:
  * Handles CANCEL_PUSH and MAX_PUSH_ID frames for server push management.
  * Manages GOAWAY frames for graceful connection shutdown.

---

### 3. Core Operating Mechanism

* **Variable-Length Frame Parsing Flow (`http3_frame.cpp`, `http3_frame_builder.cpp`)**:
  * Reads incoming QUIC stream bytes -> Decodes Varint Type/Length -> Instantiates corresponding `http3_frame_*` object mapped to the Type and performs validation.
* **Control Stream Initialization & Settings Exchange (`http3_frame_settings.cpp`)**:
  * Opens a unidirectional Control Stream -> Serializes and transmits the SETTINGS frame -> Receives the peer's Control Stream and applies QPACK parameters.

---

### 4. TODO List Tracker

| No. | Task Description | Priority | Status |
| --- | --- | --- | --- |
| **TODO-H3-01** | Supplement input buffer boundary check exception handling during QUIC Varint decoding in `http3_frame.cpp`<br> | High | Open |
| **TODO-H3-02** | Verify QPACK Dynamic Table synchronization and handling of duplicate SETTINGS receipts on the Control Stream in `http3_frame_settings.cpp`<br> | High | Open |
| **TODO-H3-03** | Verify boundary validation for RFC 9218 Priority Element IDs in `http3_frame_priority_update.cpp`<br> | Medium | Open |
| **TODO-H3-04** | Verify stream ignore mechanisms upon receiving unsupported frames in `http3_frame_unknown.cpp`<br> | Medium | Open |
| **TODO-H3-05** | Review applying byte boundary checking logic for extended METADATA frames in `http3_frame_metadata.cpp`<br> | Low | Open |
