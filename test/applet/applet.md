## Server Applet - published by Gemini

---

### 1. tcpserver1 (Multiplexer Interface-Based TCP Server)

* **Primary Role**: Implements basic asynchronous TCP server operations using event loop control based on an I/O Multiplexer (IOCP/Epoll, etc.).
* **Core Operating Mechanism**:
  * Registers a TCP listening socket with the Multiplexer object and enters the event loop.
  * Executes handler callbacks upon client connection, read, and write events.

* **TODO List**:

| No. | Task Description | Priority | Status |
| --- | --- | --- | --- |
| **TODO-TS1-01** | Enhance partial read/write handling when socket read events occur | High | Open |
| **TODO-TS1-02** | Verify client session cleanup handling during Multiplexer shutdown | Medium | Open |

---

### 2. tcpserver2 (Network Server Interface-Based TCP Server)

* **Primary Role**: Implements encapsulated TCP server operations utilizing the high-level `network_server` abstraction interface.
* **Core Operating Mechanism**:
  * Instantiates a `network_server` object, configures port and protocol settings, and invokes `start()`.
  * Controls internal thread pool and socket lifecycles via abstracted server event protocols.

* **TODO List**:

| No. | Task Description | Priority | Status |
| --- | --- | --- | --- |
| **TODO-TS2-01** | Verify memory leaks during `network_server` session destruction | High | Open |
| **TODO-TS2-02** | Apply an interface to configure concurrent connection resource limits (Max Connections) | Medium | Open |

---

### 3. udpserver1 (Multiplexer Interface-Based UDP Server)

* **Primary Role**: Handles connectionless UDP socket events via I/O Multiplexer control.
* **Core Operating Mechanism**:
  * Registers a UDP socket with the Multiplexer and waits for data reception read events.
  * Performs synchronous processing of datagrams and dispatches socket events via `recvfrom` / `sendto` operations.

* **TODO List**:

| No. | Task Description | Priority | Status |
| --- | --- | --- | --- |
| **TODO-US1-01** | Strengthen packet drop handling upon UDP datagram buffer overflow | High | Open |
| **TODO-US1-02** | Supplement data structures for client IP/Port management within the Multiplexer | Medium | Open |

---

### 4. udpserver2 (Network Server Interface-Based UDP Server)

* **Primary Role**: Implements a UDP datagram server built on top of the `network_server` abstraction layer.
* **Core Operating Mechanism**:
  * Initializes `network_server` with UDP server attributes and executes the service.
  * Controls asynchronous UDP sessions by binding datagram receive and transmit handlers.

* **TODO List**:

| No. | Task Description | Priority | Status |
| --- | --- | --- | --- |
| **TODO-US2-01** | Check for thread pool bottlenecks during asymmetric UDP send/receive traffic | High | Open |
| **TODO-US2-02** | Handle pending datagram dumps upon stopping `network_server`<br> | Low | Open |

---

### 5. tlsserver (Network Server Interface-Based TLS Server)

* **Primary Role**: Implements an encrypted TLS (Transport Layer Security) server integrating OpenSSL and the Hotplace security framework.
* **Core Operating Mechanism**:
  * Initializes the SSL Context and loads certificates (`cert.pem`) and private keys (`key.pem`).
  * Performs TLS handshakes and manages read/write operations over encrypted channels.

* **TODO List**:

| No. | Task Description | Priority | Status |
| --- | --- | --- | --- |
| **TODO-TS-01** | Supplement detailed logging of SSL error codes upon TLS handshake failures | High | Open |
| **TODO-TS-02** | Verify TLS 1.2 / TLS 1.3 ciphersuite compatibility and DH parameter settings | Medium | Open |

---

### 6. dtlsserver (Network Server Interface-Based DTLS Server)

* **Primary Role**: Implements a datagram-based TLS (DTLS) encrypted communication server.
* **Core Operating Mechanism**:
  * Creates a DTLS context over UDP sockets and executes DTLS cookie exchanges and handshake operations.
  * Controls secure datagram transmission while accounting for packet loss and retransmission timers.

* **TODO List**:

| No. | Task Description | Priority | Status |
| --- | --- | --- | --- |
| **TODO-DS-01** | Verify retransmission timer logic during DTLS handshake packet loss | High | Open |
| **TODO-DS-02** | Improve handling of DTLS client cookie verification calculation errors | Medium | Open |

---

### 7. httpserver1 (HTTP Server Interface-Based HTTP/1.1 Server)

* **Primary Role**: Implements HTTP/1.1 request/response protocol parsing and static resource web server operations using the `http_server` interface.
* **Core Operating Mechanism**:
  * Parses HTTP methods (GET, POST, etc.), URIs, headers, and bodies.
  * Handles static routing for `index.html`, `signin.html`, `style.css`, and renders HTTP responses.

* **TODO List**:

| No. | Task Description | Priority | Status |
| --- | --- | --- | --- |
| **TODO-HS1-01** | Verify HTTP/1.1 keep-alive connection timeout handling logic | High | Open |
| **TODO-HS1-02** | Supplement chunked transfer encoding exception handling during POST body parsing | Medium | Open |

---

### 8. httpserver2 (HTTP Server Interface-Based HTTP/2 Server)

* **Primary Role**: Implements an HTTP/2 server supporting binary frames and multiplexing based on the `http_server` interface.
* **Core Operating Mechanism**:
  * Parses HTTP/2 frames (SETTINGS, HEADERS, DATA, etc.) and decompresses HPACK headers.
  * Dispatches multi-stream sessions and serves static resources over a single TCP connection.

* **TODO List**:

| No. | Task Description | Priority | Status |
| --- | --- | --- | --- |
| **TODO-TODO-HS2-01** | Verify HPACK dynamic table management overflow exception handling | High | Open |
| **TODO-TODO-HS2-02** | Verify HTTP/2 stream flow control (`WINDOW_UPDATE`) control operations | Medium | Open |
