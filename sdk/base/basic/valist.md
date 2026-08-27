
## 동적 `va_list` 생성 module (`valist`) - published by Gemini

---

### 1. 개요 및 주요 특징

* **module 역할**: 실행 시간에 가변 인자 목록(`va_list`)을 동적으로 구성하여 `vprintf` 계열 함수에 전달할 수 있도록 지원하는 wrapper class.
* **주요 기능**:
  * **platform 호환 메모리 레이아웃 생성**: Windows 및 Linux(x86, x86_64) ABI 차이를 고려하여 인자 메모리를 동적으로 재배치.
  * **Default Argument Promotion 처리**: `float`를 `double`로, `char`/`short`를 정수형으로 승격시켜 C 가변 인자 호출 규약 준수.
  * **동기화 및 안전성**: `critical_section_guard`를 활용하여 thread 안전성 확보.
* **C++11 특징**: Move Semantics(`std::move`)를 통한 이동 삽입 지원, `auto` 키워드 활용.

---

### 2. 주요 class 및 데이터 구조

```cpp
namespace hotplace {

// Linux x86_64 GCC va_list 내부 구조 대응
typedef struct _valist_gcc_x64_t {
    unsigned int gp_offset;
    unsigned int fp_offset;
    void* overflow_arg_area;
    void* reg_save_area;
} valist_gcc_x64_t[1];

typedef struct _valist_t {
    union {
        va_list ap;
        void* va_ptr;
#if defined __linux__ && __WORDSIZE == 64
        valist_gcc_x64_t gcc_va_list64;
#endif
    };
} valist_t;

class valist {
   public:
    valist();
    valist(const valist& object);
    ~valist();

    // 인자 추가 (Streaming Operator)
    valist& operator<<(bool value);
    valist& operator<<(int value);
    valist& operator<<(double value);
    valist& operator<<(const char* value);
    valist& operator<<(const variant_t& v);
    valist& operator<<(variant_t&& v);

    // 동적 생성된 va_list 반환
    va_list& get();
    void clear();
    size_t size() const;

   protected:
    void build(); // platform별 메모리 정렬 및 va_list 구성
    void insert(const variant_t& v);
    void insert(variant_t&& v);

   private:
    valist_t _type;
    void* _va_internal;
    bool _modified;
    mutable critical_section _lock;
    std::vector<variant_t> _args;
};

}  // namespace hotplace
```
[cite: 45, 46]

---

### 3. 핵심 동작 mechanism

* **동적 인자 수집 (`operator<<`)**:
  * stream 연산자를 통해 다양한 타입의 변수를 `variant_t` 객체로 변환하여 내부 벡터(`_args`)에 저장[cite: 45, 46].
  * 인자가 변경되면 `_modified` flag를 `true`로 설정하여 재구성이 필요함을 기록[cite: 45, 46].

* **메모리 구성 및 정렬 (`build`)**:
  * target 아키텍처의 Chunk Size(x86: 4바이트, x64: 8바이트)에 맞춰 메모리 padding 크기 계산[cite: 45].
  * **Linux x86_64**: Register 영역 대신 Overflow 영역(`overflow_arg_area`)에 메모리 block을 직접 binding하여 레지스터 제한 우회[cite: 45].
  * **Windows / x86**: 연속된 메모리 buffer(`arg_list`) 생성 후 데이터 복사 및 pointer binding[cite: 45].

---

### 4. TODO list

### 📌 TODO List Tracker (통합 상태 반영)

| ID | 우선순위 | 작업 항목 (Task Description) | 상태 (Status) | 비고 |
| --- | --- | --- | --- | --- |
| ~~**TODO-VA-01**~~ | `MEDIUM` | **x64 ABI Boundary & Alignment 검증**<br><br>- `testvector_valist.yml` - 개발 환경 AppVerifier PASS 검증 완료 | `Fixed` | 테스트 케이스 구현 완료 |
| **TODO-VA-02** | High | `build()` 내부 `malloc`/`free` 호출을 전용 메모리 풀 또는 `std::vector<uint8_t>`로 대체하여 파편화 방지 | Postponed | 미진행 |
| **TODO-VA-03** | Medium | ARM64(AArch64) 환경 지원을 위한 `valist_t` 레지스터 packing 구조체 확장 | Postponed | 미진행 |
| ~~**TODO-VA-04**~~ | Low | C++11 Variadic Templates 기반의 `make_valist` 헬퍼 함수 구현 | Won't fix | sprintf.hpp 코드 존재 |

---

- TODO-VA-01
  - `valist` 모듈은 C/C++ 표준 라이브러리의 `va_list` 동작을 시스템 스택 메커니즘 수준에서 직조하여 **동적으로 생성**하는 매우 고난도의 ABI(Application Binary Interface) 종속 코드로 작성되어 있습니다.
    - Linux x86_64의 경우, 일반적인 `va_list`는 레지스터 공간(General Purpose / Floating Point)을 먼저 채우고 넘치는 인자를 `overflow_arg_area`에 배치하지만, 코드에서는 레지스터 오프셋을 최대값(`gp_offset = 48`, `fp_offset = 304`)으로 강제 설정하여 **모든 인자가 메모리 영역(`overflow_arg_area`)에서 즉시 읽히도록 속이는 방식**을 사용합니다.
  - 여기서 **Boundary Mapping 검증**이 뜻하는 바는 다음과 같습니다:
    - **정렬(Alignment) 경계 치수 검증**: AMD64/x64 환경에서는 스택 인자가 반드시 **8바이트 단위**(`VLIST_CHUNK_SIZE 8`)로 패딩 및 정렬되어야 합니다. 타입 크기가 1바이트(`char`), 2바이트(`short`), 4바이트(`int`)인 변수들이 연속으로 인입될 때 패딩(`padded_size`) 계산과 `memcpy` 오프셋이 바이트 경계에 정확히 들어맞는지 검증하는 것을 의미합니다.
    - **포인터/구조체 오프셋 검증**: Windows x64 ABI나 64비트 환경에서 8바이트를 초과하는 구조체나 특수 데이터 타입이 전달될 때, 값 복사(Pass-by-value) 방식과 참조 전달(Pass-by-reference) 방식 간의 메모리 경계 표현 차이를 점검하는 항목입니다.
  - Linux 환경: `VLIST_CHUNK_SIZE` 패딩 정렬 (Align) 검증
    - 추천 검증 방안 (`assert` 기반 Boundary Check)
      - `build()` 함수 내부의 복사 루프에 아래와 같이 메모리 경계 정렬 검증(`assert`)을 추가하면 `valgrind` / `ASan` 이외에도 런타임에 정렬 파괴 현상을 명확히 포착할 수 있습니다.
        ```cpp
        // vdata 시작 주소가 VLIST_CHUNK_SIZE (4 또는 8) 경계에 정렬되었는지 검증
        uintptr_t addr = reinterpret_cast<uintptr_t>(vdata);
        assert((addr % VLIST_CHUNK_SIZE) == 0 && "valist memory buffer is misaligned!");
        ```
  - Windows 환경: `va_assign`과 MSVC CRT(표준 라이브러리)의 처리
    - 질문하신 내용대로 Windows/MSVC 환경에서는 MSVC 컴파일러의 `<stdarg.h>` 내 `va_arg` 마크로와 매크로 함수 `va_assign`이 스택 포인터(`ap`)를 직접 전진시키며 값을 기록하므로, **표준 라이브러리 매크로가 ABI 패딩을 완벽히 보장**합니다.
      ```cpp
      #define va_assign(lvalp, type, rval) \
          {                                \
              *((type*)lvalp) = rval;      \
              va_arg(lvalp, type);         \
          }
      
      ```
    - **MSVC C 런타임의 포인터 전진 메커니즘**: MSVC x64 ABI 규약상 모든 `va_arg(ap, type)`는 `sizeof(type)`과 관계없이 최소 **8바이트 단위**로 포인터를 오프셋시킵니다.
    - **컴파일러 경고 방어**: `valist.cpp` 내부에서 `va_assign_type_promotion_int` 등을 도입하여 `char`/`short`를 `int`로, `float`를 `double`로 Type Promotion(승격)하여 전달하고 있으므로 MSVC CRT의 스택 할당 규칙에 정확히 부합합니다.
    - 마땅한 검증 방법이 없을 때의 검증 방안
      - Windows 환경은 물리적 스택 주소를 포인터로 흉내 내는 방식(`union va_union`)이므로, 단위 테스트(Unit Test) 수준에서 **타입 조합별 메모리 덤프 비교** 방식을 추천합니다:
        1. **원소 조합 테스트 (Heterogeneous Types)**:
          - `char` -> `double` -> `int64` -> `const char*` -> `short`와 같이 크기가 서로 다른 타입들을 섞어서 `valist`에 주입.
        2. **`vsscanf` / `vsprintf` 라운드트립 검증**:
          - MSVC CRT 표준 함수인 `vsnprintf`나 `vsscanf`에 `va.get()`을 전달하여 복원된 값이 원본 값과 단 1비트의 오차도 없이 일치하는지 `assert` 검증.
          - 이미 진행하신 **Application Verifier** 및 **MSVC C++ Sanitizer(/fsanitize=address)** 환경에서 불일치나 메모리 오버런이 발생하지 않았다면, MSVC CRT 스택 할당 정렬에 완전히 부합한다고 확신하셔도 좋습니다.

---
