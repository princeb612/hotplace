## 고급 formatting 서식 출력 module (`sprintf.cpp` / `sprintf.hpp`) - published by Gemini

---

### 1. 개요 및 주요 특징

* **module 역할**: 위치 기반 parameter indexing(`{1}`, `{2}`) 및 option 서식 구문을 지원하는 커스텀 formatting 서식 출력 함수.
* **주요 기능**:
  * **위치 기반 index 서식 지원**: C# 또는 Python style의 `{1}`, `{2}`와 같은 1-indexed 가변 인자 mapping.
  * **flag 기반 확장 서식**: 정수(`{1:08x}`), 문자열(`{2:-15s}`), floating point(`{3:le}`), binary(`{4:s}`, `{4:x}`) 등 가변 타입에 대응하는 맞춤형 변환 지원.
  * **안전한 가변 인자 전달**: `valist` 및 C++11 Variadic Templates (`make_valist`) 활용.
* **C++11 특징**: Variadic Templates 기반 Parameter Pack 전개, lambda식 및 `std::move` 활용.

---

### 2. 주요 class 및 함수 구성

```cpp
namespace hotplace {

// sprintf formatting 함수 (valist 기반)
return_t sprintf(stream_t* stream, const char* fmt, valist va);

// C++11 Variadic Template 기반 make_valist helper 함수
template <typename T>
void make_valist(valist& va, T arg) {
    va << arg;
}

template <typename T, typename... Args>
void make_valist(valist& va, T arg, Args... args) {
    va << arg;
    make_valist(va, args...);
}

#if __cplusplus >= 201402L // C++14
// parameter packing 및 가변 서식 출력 제어
template <class... Args>
return_t vprintf(stream_t* stream, const char* fmt, Args... args);
#endif

}  // namespace hotplace
```
[cite: 48]

---

### 3. 핵심 동작 mechanism

* **정규표현식 parsing (`regex_tokens`)**:
  * `\{(\d+):?([^}]*)\}` pattern을 통해 `{n:specifier}` 포맷 token 추출[cite: 47].
  * token의 index(`param_id`)를 검증하여 `valist`의 해당 위치 데이터 추출[cite: 47].

* **타입별 서식 치환 처리**:
  * **Integer**: `x`, `X` 서식 지정 시 `%0x` 형태로 표준 16진수 포맷터 구성[cite: 47].
  * **Binary (`TYPE_BINARY`)**: `s` 구문 지정 시 출력 가능한 문자(`std::isprint`)는 그대로 표시하고 non-printable 값은 `.`으로 치환[cite: 47]. `x`/`X` 서식 지정 시 Base16 encoding 수행[cite: 47].
  * **Type Mismatch Guard**: 인자 타입과 지정한 포맷 지정자가 일치하지 않을 경우 기본 지정자로 Fallback[cite: 47, 48].

---

### 4. TODO list

| 번호 | 작업 내용 | 우선순위 | 진행 상황 |
| :--- | :--- | :---: | :---: |
| **TODO-SPRINTF-01** | 정규표현식 parsing 단계를 Aho-Corasick 또는 커스텀 parser로 대체하여 formatting 속도 개선 | High | 미진행 |
| **TODO-SPRINTF-02** | `TYPE_BINARY` 데이터의 16진수 출력 시 줄바꿈/padding 서식 option 확장 | Medium | 미진행 |
| **TODO-SPRINTF-03** | `vprintf` template의 C++11 환경 호환성 검토 및 lambda 캡처 구조 단순화 | Medium | 진행 중 |
| **TODO-SPRINTF-04** | 잘못된 포맷 문자열 입력 시 예외 제어 검증 및 단위 test case 보강 | Low | 미진행 |
