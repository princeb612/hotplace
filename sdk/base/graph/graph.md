## Graph Library (`graph.hpp`) - published by Gemini

---

### 1. 개요 및 주요 특징

* **module 역할**: C++11 기반의 template 그래프 자료구조 및 탐색/최단경로 algorithm library.
* **주요 기능**:
  * **방향성/무방향성 그래프 지원**: `graph_directed` 및 `graph_undirected` 모드 지원.
  * **다양한 탐색 및 최단거리 algorithm 지원**: 인접 list(`graph_adjacent_list`), 깊이 우선 탐색(`graph_dfs`), 너비 우선 탐색(`graph_bfs`), dijkstra 최단 경로(`graph_dijkstra`) 구현.
  * **method chaining(Method Chaining)**: `add_edge()`, `add_vertex()` 호출을 연속 수행하는 interface 설계.
  * **dijkstra 경로 복원 지원**: 최단 거리 단순 계산을 넘어 `do_infer()` 내 `filler` 재귀 함수를 통해 동일 거리 최단 경로 복수 분기까지 경로 list로 재구성.
* **C++11 특징**:
  * `std::move` 기반 이동 생성자 및 이동 대입 연산자 구현으로 정점/간선 데이터 복사 비용 최적화.
  * `std::function` 기반 방문자 함수 interface (`visitor_t`) 및 lambda 함수 활용.

---

### 2. 주요 class 및 API 구조

**그래프 데이터 관리 (`hotplace::t_graph<T>`)**

```cpp
namespace hotplace {

template <typename T>
class t_graph {
   public:
    // 정점 및 간선 추가 (method chaining 지원)
    t_graph& add_vertex(const T& d);
    t_graph& add_edge(const T& from, const T& to, int weight = 1, graph_direction_t d = graph_directed);
    t_graph& add_directed_edge(const T& from, const T& to, int weight = 1);
    t_graph& add_undirected_edge(const T& from, const T& to, int weight = 1);

    // algorithm 객체 생성 팩토리 method
    graph_adjacent_list* build_adjacent();
    graph_dfs* build_dfs();
    graph_bfs* build_bfs();
    graph_dijkstra* build_dijkstra();
};

}  // namespace hotplace
```
[cite: 61]

**그래프 탐색 베이스 class (`graph_search`)**
* `learn()`: 정점별 탐색/최단거리 정보를 미리 학습 및 계산 처리[cite: 61].
* `infer()`: 학습된 결과를 바탕으로 최종 탐색 경로 구성[cite: 61].
* `traverse(visitor_t f)`: callback 함수를 전달 받아 탐색 결과를 순회 및 출력 처리[cite: 61].

---

### 3. 핵심 동작 mechanism

* **정점 및 간선 내부 구조체**:
  * `vertex`: 내부 데이터 `T _data`를 보관하며, `std::set` 관리를 위해 `operator<` 및 `operator==` overloading[cite: 61].
  * `edge`: `_from`, `_to`, `_weight`, `_direction`으로 구성되며, 무방향 간선 추가 시 내부적으로 역방향 간선을 함께 등록 처리[cite: 61].
* **dijkstra algorithm (`graph_dijkstra`)**:
  * `std::priority_queue<std::pair<int, T>, std::vector<...>, std::greater<...>>` 우선순위 queue 활용[cite: 61].
  * `_dist` 맵에 출발점 기준 최단 거리를 기록하고, `_path` 맵에 최단 거리를 형성하는 직전 정점(predecessor)들을 추적 및 기록[cite: 61].
  * `do_infer()` 실행 시 `filler` lambda 함수가 역방향 추적을 수행하여 출발지부터 목적지까지의 완전한 경로(`route_t`) 생성[cite: 61].

---

### 4. TODO list

| 번호 | 작업 내용 | 우선순위 | 진행 상황 |
| :--- | :--- | :---: | :---: |
| **#1** | `base64_decode` loop 시 유효하지 않은 Base64 문자에 대한 검증 및 오류 처리 강화 | High | 미진행 |
| **#2** | Base64URL decoding 시 입력 끝부분 padding(`=`) 생략 건에 대한 완충 정밀 검증 logic 작성 | Medium | 미진행 |
| **#3** | SIMD/AVX2 적용을 통한 대용량 binary_t Base64 encoding/decoding loop 성능 향상 검토 | Low | 미진행 |
| **#4** | `t_graph::build_*` 팩토리 method의 Raw Pointer 반환 구조를 `std::unique_ptr` 스마트 pointer로 전환하여 메모리 누수 방지 | High | 미진행 |
| **#5** | `graph_dijkstra` 구현 시 음수 가중치 간선 검증 및 오류 처리 logic 추가 | Medium | 미진행 |
