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

| 번호 | 작업 내용 | 우선순위 | 진행 상황 |
| :--- | :--- | :---: | :---: |
| **#1** | Windows x64 ABI 환경에서 대형 구조체/pointer 전달 시 boundary mapping 검증 | High | 미진행 |
| **#2** | `build()` 내부 `malloc`/`free` 호출을 전용 메모리 풀 또는 `std::vector<uint8_t>`로 대체하여 파편화 방지 | High | 미진행 |
| **#3** | ARM64(AArch64) 환경 지원을 위한 `valist_t` 레지스터 packing 구조체 확장 | Medium | 미진행 |
| **#4** | C++11 Variadic Templates 기반의 `make_valist` 헬퍼 함수 구현 | Low | 미진행 |
