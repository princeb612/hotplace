## Multiplexer module - published by Gemini

---

### 1. 개요 및 주요 특징

* **module 역할**: 크로스 platform(Linux / Windows) I/O multiplexing 추상화 및 event loop 제어 module.
* **주요 기능**:
  * **OS별 I/O Multiplexing Abstraction**: Linux의 epoll 및 Windows의 IOCP를 조건부 컴파일 및 캡슐화하여 단일 interface 제공 (`linux/multiplexer_epoll.cpp`, `windows/multiplexer_iocp.cpp`).
  * **Multiplexer Controller**: event loop 제어, socket 등록/해제 및 비동기 이벤트 dispatch pipeline 관리 (`multiplexer_controller.cpp`, `multiplexer.hpp`).

---

### 2. 핵심 구현 영역 및 기술 요소

* **Platform Specific Implementations (`linux/multiplexer_epoll.cpp`, `windows/multiplexer_iocp.cpp`)**:
  * **Linux**: `epoll_create1`, `epoll_ctl` (EPOLL_CTL_ADD, EPOLL_CTL_DEL, EPOLL_CTL_MOD), `epoll_wait` 기반 I/O event polling 연산 구현.
  * **Windows**: `CreateIoCompletionPort`, `GetQueuedCompletionStatus` (GQCS) 기반 비동기 I/O Completion Queue handling 구현.
* **Multiplexer Controller (`multiplexer_controller.cpp`)**:
  * multiplexer instance lifecycle 관리, socket event loop 실행 및 callback mapping 연산.

---

### 3. 핵심 동작 mechanism

* **Cross-Platform Event Loop Flow (`multiplexer_controller.cpp`, `multiplexer.hpp`)**:
  * socket 등록 연산 -> OS별 backend(`epoll` 또는 `IOCP`) handler binding -> 이벤트 대기(`epoll_wait` / `GQCS`) -> I/O 이벤트 발생 시 controller dispatch 호출.

---

### 4. TODO list

| 번호 | 작업 내용 | 우선순위 | 진행 상황 |
| --- | --- | --- | --- |
| **TODO-MP-01** | `linux/multiplexer_epoll.cpp` 내 `epoll_wait` EINTR return 시 retry logic 및 error handling 보완 | High | 미진행 |
| **TODO-MP-02** | `windows/multiplexer_iocp.cpp` 내 GQCS completion key null pointer check 및 overlapped memory layout 검증 | High | 미진행 |
| **TODO-MP-03** | `multiplexer_controller.cpp` 내 event loop terminate 시 worker thread join 및 socket cleanup race condition 확인 | High | 미진행 |
| **TODO-MP-04** | `multiplexer.hpp` 내 edge-triggered (EPOLLET) 및 level-triggered option 설정 확장성 검토 | Medium | 미진행 |
| **TODO-MP-05** | Linux/Windows platform별 non-blocking socket set flag abstraction 유효성 확인 | Low | 미진행 |
