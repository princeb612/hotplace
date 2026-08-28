## HTTP/1.1 Protocol & Server/Client - published by Gemini

---

### 1. Overview and Key Features

* **Module Role**: Core module handling HTTP/1.1 specification-based message parsing, URI routing, authentication, server/client operations, and HTML document response management.
* **Key Features**:
  * **Message and Protocol Parsing**: Parses and serializes HTTP Requests/Responses, Headers, URIs, Status Codes, and Protocols (`http_request`, `http_response`, `http_header`, `http_uri`, `http_protocol`).
  * **Server/Client Facade**: Configures builder pattern-based HTTP Servers and controls asynchronous HTTP Client communication (`http_server`, `http_server_builder`, `http_client`).
  * **Authentication and Routing**: Parses/resolves HTTP authentication (such as Basic/Digest) and routes URI mappings (`http_authentication_provider`, `http_authentication_resolver`, `http_router`).
  * **HTML Document Rendering**: Generates static/dynamic HTML documents and provides resource response helpers (`html_documents`).

---

### 2. Core Implementation Areas and Technical Elements

* **HTTP Message Parsing and Header Control (`http_request.cpp`, `http_response.cpp`, `http_header.cpp`, `http_uri.cpp`)**:
  * Parses Start-line, HTTP Methods, and Header Key-Value pairs, and separates URI Components (Scheme, Host, Port, Path, Query).
* **Server Builder and Router Mechanism (`http_server_builder.cpp`, `http_router.cpp`)**:
  * Configures server options via Fluent Builder Pattern operations to create `http_server` instances.
  * Handles request handler mapping and dispatching based on URI and Method patterns.
* **Authentication and Client Handling (`http_authentication_provider.cpp`, `http_authentication_resolver.cpp`, `http_client.cpp`)**:
  * Parses `Authorization` / `WWW-Authenticate` headers and validates credentials.
  * Handles HTTP Client socket creation, request transmission, and response stream parsing.

---

### 3. Core Operating Mechanism

* **HTTP Request Dispatching Flow (`http_server.cpp`, `http_router.cpp`)**:
  * Receives client socket -> Parses `http_request` -> Verifies via `http_authentication_resolver` -> Performs `http_router` URI lookup -> Invokes Handler Callback -> Generates and transmits `http_response`.
* **Authentication Pipeline (`http_authentication_resolver.cpp`)**:
  * Detects Auth Scheme (Basic, Bearer, etc.) in request headers -> Dispatches to Auth Provider -> Proceeds to Handler upon successful authentication or returns `401 Unauthorized` response upon failure.

---

### 4. TODO List Tracker

| No. | Task Description | Priority | Status |
| --- | --- | --- | --- |
| **TODO-HTTP-01** | Supplement out-of-bounds (OOB) and null pointer exception handling during malformed URI and chunked body parsing in `http_request.cpp`<br> | High | Open |
| **TODO-HTTP-02** | Verify graceful socket session closure upon connection Keep-Alive timeouts in `http_server.cpp`<br> | High | Open |
| **TODO-HTTP-03** | Verify MD5/SHA256 hash validation during Digest authentication calculations in `http_authentication_resolver.cpp`<br> | Medium | Open |
| **TODO-HTTP-04** | Verify dynamic path parameter (wildcard path) mapping regex operations in `http_router.cpp`<br> | Medium | Open |
| **TODO-HTTP-05** | Review applying HTML special character entity escaping operations in `html_documents.cpp`<br> | Low | Open |
