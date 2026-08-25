# Aho-Corasick & Wildcard - published by Gemini

## 1. class 계층 구조 및 역할 분담

C++11 환경에서 다중 pattern matching 및 wildcard 처리 상위 레벨 parser를 지지하는 핵심 C++ library 구조

```
┌──────────────────────────────────────────────────────────┐
│  t_aho_corasick_t<BT, T>                                 │ (순수 가상 interface class)[cite: 3]
└─────────────────────────────┬────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────┐
│  t_aho_corasick<BT, T, memberof_t>                       │ (기본 aho-corasick algorithm)[cite: 3]
└─────────────────────────────┬────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────┐
│  t_aho_corasick_wildcard<BT, T, memberof_t>              │ (단일/임의 wildcard 확장)[cite: 4]
└──────────────────────────────────────────────────────────┘
```

---

## 2. 기본 엔진 (`t_aho_corasick`) 핵심 mechanism

### ① `trienode` 구조체 design

* **`children`**: 정확한 키값 matching을 위한 자식 node trie.
* **`group_children`**: 추후 parser 연동 시 그룹 matching을 확장하기 위해 미리 확보된 trie node 맵.
* **`failure`**: 탐색 실패 시 되돌아갈 Failure Link (aho-corasick의 핵심).
* **`output`**: 해당 node 위치에서 완결되는 pattern ID들의 집합 (`std::set<size_t>`).

### ② algorithm 3단계 life-cycle

1. **`doinsert()`**: pattern 등록

* 입력 sequence를 순회하며 Trie node를 생성하고, pattern의 마지막 node의 `output`에 pattern ID를 추가.

2. **`dobuild()`**: Failure Link 및 Output Merge 구축 (BFS)

* 너비 우선 탐색(BFS)을 통해 각 node의 Failure Link를 형성.
* Failure Link가 가리키는 node의 `output` 목록을 현재 node의 `output`에 합침(Merge).

3. **`dosearch()` / `collect_results()**`: text 탐색 및 결과 수집

* 소스 stream을 1회 스캔($O(N)$)하면서 trie 상태를 이행하고, matching 발생 시 종료 위치와 pattern ID를 결과 맵에 수집.

---

## 3. wildcard 확장 엔진 (`aho_corasick_wildcard`) mechanism

단일 문자 wildcard(`?`, `flag_single`)와 가변 길이 문자열 wildcard(`*`, `flag_any`)를 지원하기 위한 핵심 확장 logic

### ① BFS 기반 탐색 queue(`std::queue`)로의 전환

기본 `t_aho_corasick`은 단일 loop 기반 탐색을 수행하지만, wildcard `*` 탐색 시 생성되는 다중 분기 경로(Branching Paths)를 추적하기 위해 `dosearch`를 **`std::queue<pair_t>` 및 방문 상태 맵(`visit`) 기반의 너비 탐색 방식**으로 재구현

### ② 시작 위치(Starting Position) 보정을 위한 `_hidden` tag 기법

aho-corasick은 matching된 pattern의 종료 위치(Ending Position)만 return하는 한계가 있음.
`h*s`와 같은 가변 길이 pattern은 시작 위치를 구하기 위해 첫 wildcard `*` 직전까지의 Prefix(숨은 pattern)를 추적해야 함.

* **`baseof_prefix` (`0x10000000`)**: wildcard 전방 Prefix용 가상 pattern ID offset.
* **`hidden_tag_t`**:
  * **`size`**: wildcard 직전까지의 Prefix 길이.
  * **`adjust`**: wildcard를 제외한 실제 확정 pattern 문자 수 (`lengthof(pattern) - lengthof(wildcard_any)`).
  * **`modes`**: `*pattern` (startswith) 및 `pattern*` (endswith) 형태 보정 flag.

### ③ wildcard 범위 계산 방식 (`get_result`)

1. `hello*world` pattern 등록 시 `hello`를 가상 Prefix pattern(`PID + 0x10000000`)으로 트리거.
2. 탐색 시 `world` 종료 위치($Pos_{end}$)가 감지되면, 저장된 Prefix 위치 목록에서 $Pos_{end} - Adjust + 1$ 이하인 가장 가까운 `hello`의 위치를 `find_lessthan_or_equal`로 찾아내어 정확한 시작 범위 `range_t(begin, end)`를 복원.

---

## 4. 소스 code 기반 활용 pattern snippet

### ① 유연한 타입 변환 핸들러 (`memberof_t`)

`t_aho_corasick`은 template metaprogramming을 통해 단순 문자열(`char`)뿐만 아니라 **pointer 기반 구조체/token stream 배열**도 탐색 가능.

```cpp
// token 객체 pointer 배열에서 type field를 획득하는 member 추출 Functor 예시[cite: 3]
struct token { int type; };

auto memberof = [](token* const* source, size_t idx) -> int {
    const token* p = source[idx];
    return p->type;
};

// token* 배열 스케일의 Aho-Corasick 구축[cite: 3]
t_aho_corasick<int, token*> ac(memberof);
```

### ② 대소문자 무시(Ignore Case) 및 wildcard 동시 지원

```cpp
// 대소문자를 구분하지 않는 memberof_tolower_handler 적용[cite: 3, 4]
t_aho_corasick_wildcard<char, char, memberof_tolower_handler> ac('?', '*');

ac.insert("we *ing", 7);
ac.insert("we * old", 8);
ac.build();

const char* source = "We don't playing because we grow old;";
auto result = ac.search(source, strlen(source));
```

---

## 5. C++11 구현 특징 및 refactoring 노트

1. **std::function 억제 및 Functor 대체 (2026.05.19 Revision 1003)**
* lambda/`std::function` 호출에 따른 runtime 간섭 overhead 및 가상 함수 호출을 줄이기 위해, template 인자 `memberof_t` 기반 Functor 구조로 전환하여 compile-time 인라인화를 유도

2. **`std::multimap` 및 Hash 함수 사용**
* 구문 비교를 위해 커스텀 hash 함수 `universal_pairhash` 기반의 `unordered_multiset`을 이용한 `equal()` template 함수를 제공

3. **Queue 기반 탐색 overhead 주의사항 (주석 4번)**
* 대용량 데이터 탐색 시 `q` 및 `visit` 중복 방지 queue에 메모리가 누적될 수 있으므로, 이미 통과된 text 범위의 `visit` record를 지속적으로 정리(Pruning)하는 최적화 여지가 남아 있음

