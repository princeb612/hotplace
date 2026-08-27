## pattern matching - published by Gemini

---

### 1. 개요 및 주요 특징

* **module 역할**: 단일/다중 문자열 탐색, 접미사 기반 indexing, wildcard 및 정규표현식(Regex) matching algorithm 구현 및 검증 module.
* **주요 기능**:
  * **단일/다중 문자열 matching**: KMP(Knuth-Morris-Pratt), Aho-Corasick algorithm parsing 및 검색 구현 (`testcase_kmp.cpp`, `testcase_aho_corasick.cpp`).
  * **접미사 및 트라이 자료구조**: Trie, Suffix Tree 생성 및 Ukkonen algorithm 기반 선형 시간 접미사 트라이 구축 (`testcase_trie.cpp`, `testcase_suffixtree.cpp`, `testcase_ukkonen.cpp`).
  * **wildcard 및 정규표현식 matching**: Wildcard 처리, Aho-Corasick Wildcard 확장, Regex matching 연산 (`testcase_wildcard.cpp`, `testcase_aho_corasick_wildcard.cpp`, `testvector_regex.cpp`).
  * **YAML 기반 test vector 검증**: Aho-Corasick, KMP, Regex 검증용 테스트 데이터 연동 (`testvector_*.yml`).

---

### 2. 핵심 구현 영역 및 기술 요소

* **단일 문자열 matching 및 실패 함수 (`testcase_kmp.cpp`, `testvector_kmp.cpp`)**:
  * 접두사/접미사 일치 길이를 활용한 Failure Function (LPS 배열) 계산 및 문맥 전이 logic 구현.
  * YAML test vector 데이터 기반 검색 index 일치 유효성 검증.
* **다중 pattern matching 및 automata (`testcase_aho_corasick.cpp`, `testcase_aho_corasick_wildcard.cpp`)**:
  * Trie 기반 Failure Link 및 Output Link 구축을 통한 BFS 기반 automata 생성 연산.
  * wildcard(`?`, `*`) 포함 다중 pattern matching 시 상태 전이 제어.
* **접미사 구조체 및 Ukkonen algorithm (`testcase_suffixtree.cpp`, `testcase_ukkonen.cpp`)**:
  * Ukkonen algorithm을 활용한 $O(N)$ 시간 복잡도 Suffix Tree 구축 및 Suffix Link 갱신 연산.
  * Active Point, Remaining Count 관리를 통한 암시적/명시적 node 분할 처리.
* **wildcard 및 정규표현식 parsing (`testcase_wildcard.cpp`, `testvector_regex.cpp`)**:
  * Dynamic Programming 및 Greedy 방식을 활용한 pattern matching 연산.
  * NFA/DFA 변환 기반 Regex 엔진 test vector 검증.

---

### 3. 핵심 동작 mechanism

* **Aho-Corasick automata 구축 (`testcase_aho_corasick.cpp`)**:
  * Trie 구성 후 Queue 기반 BFS 탐색을 수행하여 Failure Link 갱신 및 pattern 추출 연산 수행.
* **Ukkonen Suffix Tree 구축 (`testcase_ukkonen.cpp`)**:
  * 문자열을 순차적으로 읽으며 Active Node, Active Edge, Active Length 상태 전이에 맞춰 node 삽입 연산.
* **Regex 및 test vector 검증 (`testvector_*.cpp`, `testvector_*.yml`)**:
  * YAML 파일에서 테스트 입출력 세트를 loading하여 automata 및 algorithm 동작 유효성 확인.

---

### 4. TODO list

| 번호 | 작업 내용 | 우선순위 | 진행 상황 |
| --- | --- | --- | --- |
| **TODO-PAT-01** | `testcase_ukkonen.cpp` 내 대용량 문자열 처리 시 메모리 누수 방지 및 node 할당 optimization | High | 미진행 |
| **TODO-PAT-02** | `testcase_aho_corasick_wildcard.cpp` wildcard 연속 입력 시 상태 전이 예외 처리 보완 | High | 미진행 |
| **TODO-PAT-03** | `testvector_regex.cpp` NFA 변환 과정에서 Backtracking 성능 저하 방지 logic 검증 | Medium | 미진행 |
| **TODO-PAT-04** | `testcase_kmp.cpp` 내 KMP failure function 계산 시 OOB 접근 예외 처리 강화 | Medium | 미진행 |
| **TODO-PAT-05** | `testvector_ahocorasick.yml` 내 특수문자 및 공백 포함 pattern test case 추가 | Low | 미진행 |
