## HTTP/2 Frame & Session Pipeline - published by Gemini

---

### 1. Overview and Key Features

* **Module Role**: An HTTP/2 binary frame generation/parsing, session multiplexing, and server push control module based on RFC 7540 specifications.
* **Key Features**:
  * **HTTP/2 Frame Serialization/Deserialization**: Handles DATA, HEADERS, PRIORITY, RST_STREAM, SETTINGS, PUSH_PROMISE, PING, GOAWAY, WINDOW_UPDATE, CONTINUATION, and ALT_SVC frames (`http2_frame*.cpp`).
  * **Frame Builder Facade**: Assembles frame headers and byte payloads using the builder pattern (`http2_frame_builder.cpp`, `http2_frame_builder.hpp`).
  * **HTTP/2 Session & Stream Multiplexing**: Manages stream lifecycles and flow control over a single TCP connection (`http2_session.cpp`, `http2_session.hpp`).
  * **Server Push Control**: Integrates PUSH_PROMISE frames and handles sub-resource push pipelines (`http2_serverpush.cpp`, `http2_serverpush.hpp`).

---

### 2. Core Implementation Areas and Technical Elements

* **Binary Frame Header and Type-Specific Parsing (`http2_frame.cpp`, `http2_frame_*.cpp`)**:
  * Parses the 9-byte common frame header (Length, Type, Flags, Stream ID).
  * Decodes payloads per frame type and validates flag states (END_STREAM, END_HEADERS, ACK, etc.).
* **HTTP/2 Session Management (`http2_session.cpp`)**:
  * Validates the Connection Preface (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`) and initializes sessions.
  * Tracks multi-stream states, manages SETTINGS exchanges, and handles Stream Flow Control (WINDOW_UPDATE).
* **Server Push & Protocol Handling (`http2_serverpush.cpp`, `http2_protocol.cpp`)**:
  * Generates promised response streams based on client requests and encodes PUSH_PROMISE frames.

---

### 3. Core Operating Mechanism

* **Frame Parsing & Dispatch Flow (`http2_session.cpp`, `http2_frame_builder.cpp`)**:
  * Parses incoming byte stream -> Reads 9-byte Frame Header -> Creates corresponding `http2_frame_*` object based on Type -> Dispatches to `http2_session` steering pipeline.
  * Upon receiving HEADERS / CONTINUATION frames, forwards Header Block Fragments to the `hpack_encoder` and `hpack_dynamic_table` pipeline to perform decompression operations.
* **Stream Flow Control & Window Management (`http2_frame_window_update.cpp`)**:
  * Monitors receive window sizes at both stream and connection levels -> Transmits WINDOW_UPDATE frames as bytes are consumed.

---

### 4. TODO List Tracker

| No. | Task Description | Priority | Status |
| --- | --- | --- | --- |
| **TODO-H2-01** | Supplement GOAWAY processing upon Client Connection Preface validation failure in `http2_session.cpp`<br> | High | Open |
| **TODO-H2-02** | Strengthen protocol error handling when CONTINUATION frame interleaving occurs in `http2_frame_headers.cpp`<br> | High | Open |
| **TODO-H2-03** | Verify flow control window overflow conditions in `http2_frame_window_update.cpp`<br> | Medium | Open |
| **TODO-H2-04** | Verify compliance with Push Stream ID allocation rules (even-numbered Stream IDs) in `http2_serverpush.cpp`<br> | Medium | Open |
| **TODO-H2-05** | Review applying timeout handling timers for SETTINGS ACK receipts in `http2_frame_settings.cpp`<br> | Low | Open |
