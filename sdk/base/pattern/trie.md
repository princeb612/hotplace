## [C++11] Trie Data Structure (`trie.hpp`) - published by Gemini

---

### 1. 개요 및 주요 특징

* **module 역할**: 접두사 트리(Prefix Tree) 구조를 활용해 문자열 및 트라이 pattern 데이터의 삽입, 검색, 자동완성, 스캔 연산을 제공하는 C++11 template library.
* **주요 기능**:
  * **범용 template 구조**: 기본 타입(`char`), 입력 pattern 타입, tag 데이터(`TP`)를 분리하여 임의의 데이터 타입 지원.
  * **index 및 tag metadata mapping**: trie node의 `eow`(End of Word) 도달 시 index(`index`) 및 사용자 정의 tag 객체(`TP*`)를 자동 연동 관리.
  * **pattern 탐색 및 자동완성 지원**: `search`, `prefix`, `lookup`, `scan`(huffman coding 등의 stream decoding 전용), `suggest`(자동완성 제안) 제공.
* **C++11 특징**:
  * `std::function` 기반의 dump/제안 callback interface(`dump_handler`) 활용.
  * `memberof_t` Functor를 통한 가변 입력 타입 요소 접근 유연성 확보.
  * `std::map`, `std::unordered_map` 및 이동 algorithm 사용.

---

### 2. 주요 class 및 API 구조

**`hotplace::t_trie<BT, T, TP, memberof_t>`**

```cpp
namespace hotplace {

template <typename BT = char, typename T = BT, typename TP = BT, typename memberof_t = memberof_defhandler<BT, T>>
class t_trie {
   public:
    typedef typename std::function<void(const BT* t, size_t size)> dump_handler;

    // pattern 추가 및 node 삽입
    t_trie& add(const T* pattern, size_t size, TP* tag = nullptr);
    t_trie& add(const T* pattern, size_t size, int index, TP* tag = nullptr);
    const trienode* insert(const T* pattern, size_t size, int index = -1, TP* tag = nullptr);

    // 검색 및 스캔 연산
    bool search(const T* pattern, size_t size, TP** tag = nullptr) const;
    int find(const T* input, size_t size, TP** tag = nullptr) const;
    int scan(const T* input, size_t size, size_t& pos, TP** tag = nullptr) const;
    bool prefix(const T* input, size_t size, bool* eow = nullptr, TP** tag = nullptr) const;
    size_t lookup(const T* input, size_t size, TP** tag = nullptr) const;
    bool lookup(int index, std::vector<BT>& pattern) const;

    // 삭제 및 자동완성
    void erase(const T* pattern, size_t size);
    bool suggest(const T* input, size_t size, dump_handler handler) const;
    void dump(dump_handler handler) const;
};

}  // namespace hotplace

```

---

### 3. 핵심 동작 mechanism

* **trie node (`trienode`)**:
  * `children`: `std::map<BT, trienode*>`로 하위 문자를 자식 node pointer와 mapping.
  * `eow` 및 `index`: 단어의 완성 여부와 고유 index를 저장.
  * 소멸자(`~trienode`)에서 자식 node들을 재귀적으로 삭제(`delete`) 처리.
* **역방향 추적 (`_rlookup`) 및 메모리 관리 (`_tags`)**:
  * `_rlookup`: index 번호로 `trienode*`를 즉시 찾아 `parent` pointer를 역추적하여 원본 pattern 문자열을 복원 (`lookup(index, pattern)`).
  * `_tags`: `std::unordered_map<int, TP*>` 구조로 동적 할당된 tag 데이터의 소유권을 보유하고 관리.
* **`scan` 연산**:
  * 연속된 입력 stream에서 `pos` 위치부터 탐색하며 가장 먼저 완성되는 단어(`eow == true`)를 발견 시 해당 단어의 index를 반환하고 `pos`를 다음 탐색 위치로 업데이트.

---

### 4. TODO list

| 번호 | 작업 내용 | 우선순위 | 진행 상황 |
| --- | --- | --- | --- |
| **#1** | `base64_decode` loop 시 유효하지 않은 Base64 문자에 대한 검증 및 오류 처리 강화 | High | 미진행 |
| **#2** | Base64URL decoding 시 입력 끝부분 padding(`=`) 생략 건에 대한 완충 정밀 검증 logic 작성 | Medium | 미진행 |
| **#3** | SIMD/AVX2 적용을 통한 대용량 binary_t Base64 encoding/decoding loop 성능 향상 검토 | Low | 미진행 |
| **#4** | `t_graph::build_*` 팩토리 method의 Raw Pointer 반환 구조를 `std::unique_ptr` 스마트 pointer로 전환하여 메모리 누수 방지 | High | 미진행 |
| **#5** | `graph_dijkstra` 구현 시 음수 가중치 간선 검증 및 오류 처리 logic 추가 | Medium | 미진행 |
| **#6** | `t_trie::erase` 연산 시 `eow` flag 무효화 외에 자식이 없는 부모 node들을 재귀 삭제하는 정리 logic 구현 | Medium | 미진행 |
| **#7** | `t_trie::dump` 내부 재귀 구현 시 `std::vector` 생성 최소화로 메모리 할당 overhead 개선 | Low | 미진행 |
