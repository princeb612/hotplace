## Network Server Core Architecture & Session Control - published by Gemini

---

### 1. Overview and Key Features

* **Module Role**: Core module for network server infrastructure construction, TCP/IP socket connection listening, session lifecycle management, and protocol dispatching.
* **Key Features**:
  * **Network Server Core**: Handles socket binding, port binding, client connection accepting, and server configuration application (`network_server.cpp`, `network_server.hpp`, `server_conf.cpp`).
  * **Session & Connection Manager**: Manages session creation, maintenance, cleanup, and overall client connection tracking (`network_session.cpp`, `network_session.hpp`, `network_session_manager.cpp`).
  * **Protocol Parsing & Stream Control**: Handles incoming byte stream parsing, protocol binding, and data I/O stream abstraction (`network_protocol.cpp`, `network_protocol_group.cpp`, `network_stream.cpp`).

---

### 2. Core Implementation Areas and Technical Elements

* **Network Server Engine & Configuration (`network_server.cpp`, `server_conf.cpp`)**:
  * Performs IP/Port binding, socket listening operations, and applies server configuration parameters (e.g., Max Connections, Timeout).
* **Session Lifecycle & Session Manager (`network_session.cpp`, `network_session_manager.cpp`)**:
  * Controls individual client connection states, connection timeouts, and idle session cleanup operations.
  * Provides unique Session ID mapping and thread-safe session lookup/removal operations.
* **Protocol Handling & Stream Pipeline (`network_protocol.cpp`, `network_stream.cpp`)**:
  * Manages stream read/write byte buffering and integrates protocol parsers.

---

### 3. Core Operating Mechanism

* **Client Connection Accept Flow (`network_server.cpp`, `network_session_manager.cpp`)**:
  * Receives client connection request -> Calls `network_server` accept -> Creates new `network_session` -> Registers session with `network_session_manager`.
* **Stream Read & Protocol Processing (`network_stream.cpp`, `network_protocol.cpp`)**:
  * Receives socket bytes -> Stores in `network_stream` buffer -> Dispatches to and executes parsing on bound upper protocol layers (`http1`, `http2`, `http3`).

---

### 4. TODO List Tracker

| No. | Task Description | Priority | Status |
| --- | --- | --- | --- |
| **TODO-NS-01** | Strengthen file descriptor (FD) leak exception handling upon accept loop errors in `network_server.cpp`<br> | High | Open |
| **TODO-NS-02** | Verify data races and dangling pointers during asynchronous session cleanup in `network_session_manager.cpp`<br> | High | Open |
| **TODO-NS-03** | Verify ring buffer overflow and boundary condition handling in `network_stream.cpp`<br> | Medium | Open |
| **TODO-NS-04** | Supplement configuration file validation and invalid input handling in `server_conf.cpp`<br> | Medium | Open |
| **TODO-NS-05** | Review multi-protocol routing performance profiling in `network_protocol_group.cpp`<br> | Low | Open |
