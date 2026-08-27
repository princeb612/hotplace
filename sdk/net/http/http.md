## HTTP/1.1 protocol 및 server/client core module - published by Gemini

---

### 1. 개요 및 주요 특징

* **module 역할**: HTTP/1.1 스펙 기반 message parsing, URI routing, 인증, server/client 동작 및 HTML 문서 응답 제어 core module.
* **주요 기능**:
  * **message 및 protocol parsing**: HTTP Request/Response, Header, URI, Status Code parsing 및 직렬화 연산 (`http_request`, `http_response`, `http_header`, `http_uri`, `http_protocol`).
  * **server/client facade**: builder pattern 기반 HTTP Server 구성 및 비동기 HTTP Client 통신 제어 (`http_server`, `http_server_builder`, `http_client`).
  * **인증 및 routing**: Basic/Digest 등 HTTP 인증 parsing/해결 및 URI mapping routing 연산 (`http_authentication_provider`, `http_authentication_resolver`, `http_router`).
  * **HTML Document redering**: 정적/동적 HTML 문서 생성 및 resource 응답 helper (`html_documents`).

---

### 2. 핵심 구현 영역 및 기술 요소

* **HTTP message parsing 및 header 제어 (`http_request.cpp`, `http_response.cpp`, `http_header.cpp`, `http_uri.cpp`)**:
  * Start-line, HTTP Method, Header Key-Value parsing 연산 및 URI Component(Scheme, Host, Port, Path, Query) 분리.
* **server builder 및 router mechanism (`http_server_builder.cpp`, `http_router.cpp`)**:
  * Fluent Builder Pattern 연산으로 server 구성 option 설정 후 `http_server` instance 생성.
  * URI 및 Method pattern 기반 요청 Handler mapping 및 Dispatch 연산.
* **인증 및 client 처리 (`http_authentication_provider.cpp`, `http_authentication_resolver.cpp`, `http_client.cpp`)**:
  * `Authorization` / `WWW-Authenticate` header parsing 및 Credential validation 연산.
  * HTTP Client socket 생성, 요청 전송 및 응답 Stream parsing 연산.

---

### 3. 핵심 동작 mechanism

* **HTTP Request Dispatching Flow (`http_server.cpp`, `http_router.cpp`)**:
  * client socket 수신 -> http_request parsing -> http_authentication_resolver 검증 -> http_router URI lookup -> Handler Callback 호출 -> http_response 생성 후 송신.
* **Authentication Pipeline (`http_authentication_resolver.cpp`)**:
  * 요청 header의 Auth Scheme(Basic, Bearer 등) 감지 -> Auth Provider dispatch -> 인증 성공 시 Handler 진입, 실패 시 401 Unauthorized 응답 반환.

---

### 4. TODO list

| 번호 | 작업 내용 | 우선순위 | 진행 상황 |
| --- | --- | --- | --- |
| **TODO-HTTP-01** | `http_request.cpp` 내 Malformed URI 및 Chunked Body parsing 시 OOB/Null Pointer 예외 처리 보완 | High | 미진행 |
| **TODO-HTTP-02** | `http_server.cpp` 내 Connection Keep-Alive Timeout 발생 시 socket session Graceful Close 확인 | High | 미진행 |
| **TODO-HTTP-03** | `http_authentication_resolver.cpp` Digest 인증 계산 시 MD5/SHA256 hash validation 검증 | Medium | 미진행 |
| **TODO-HTTP-04** | `http_router.cpp` Dynamic Path Parameter (Wildcard Path) mapping 정규식 연산 확인 | Medium | 미진행 |
| **TODO-HTTP-05** | `html_documents.cpp` 내 HTML Special Character Entity Escaping 연산 적용 검토 | Low | 미진행 |
