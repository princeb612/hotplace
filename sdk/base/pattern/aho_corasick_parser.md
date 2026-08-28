# Aho-Corasick 기반 상향식(Bottom-Up) token reduction parser (Gemini)

---

## 1. 개요 및 설계 아키텍처

ASN.1과 같이 복잡한 구조체 및 제약 조건을 가진 text parsing을 위해, 전통적인 LR parser 대신 **Aho-Corasick 다중 pattern matching algorithm**을 응용한 상향식 token reduction 엔진(Pattern-based Bottom-Up Token Reducer)을 구축

```
[Input Token Stream]
       │
       ▼
┌────────────────────────────────────────────────────────┐
│  Aho-Corasick Multi-Pattern Reduction Engine           │
│  - Virtual Token Replacement (insert_as)               │
│  - Token Categorization (set_group)                    │
│  - Delimiter/Non-delimiter Repetition (repeat_as)      │
└────────────────────────────────────────────────────────┘
       │
       ▼
[Sub-pattern Coordinate Transformation (token_span)]
       │
       ▼
[AST / Reduced Parse Tree Result]

```

### parser 분류 및 특성 비교

| 구분 | 예측 기호(Lookahead) | 상태(State) 수 | 문법 처리 정밀도 | 핵심 동작 mechanism |
| --- | --- | --- | --- | --- |
| **LR(0)** | 사용 안 함 | 적음 | 가장 낮음 | 문법 규칙 기반 DFA Shift/Reduce |
| **LALR** | 합쳐진 예측 기호 | 적음 | 높음 | Lookahead Set 기반 상태 전이 |
| **LR(1)** | 개별 예측 기호 | 매우 많음 | 가장 높음 | 정밀한 문맥 추적 parsing |
| **AC-Reducer** | 사용 안 함 (token 배열 일치) | Trie node 수 비례 | 특화/pattern 기반 | **Aho-Corasick token 배열 pattern 치환** |

---

## 2. 엔진 핵심 기능 구현 사양

### ① 그룹 및 가상 token 구조 (`set_group`, `insert_as`)

* **`set_group`**: 여러 token을 하나의 추상화 그룹으로 묶어 공통 타입 처리
* **`insert_as`**: 하위 token sequence를 상위 가상 token(Virtual Token)으로 축약/치환

```cpp
// 예시: 기본 타입 그룹화 및 단일 pattern 축약
ac.set_group(token_builtintype, {token_bool, token_int, token_visiblestring, token_usertype});
ac.insert_as(token_namedtype, {token_identifier, token_builtintype});

```

### ② 반복 sequence 축약 (`repeat_as`)

구분자(Delimiter)가 포함되거나 포함되지 않은 동일 원소의 연속체를 하나의 단일 token으로 정규화

```cpp
// 예시: comma 구분자로 연결된 element 반복 구조
ac.repeat_as(token_element, token_comma, {token_namedtype, token_taggedtype});

```

### ③ 서브 pattern matching 좌표 변환 (`token_span`)

중첩된 reduction 구간의 원본 token index 범위를 정확히 추적하기 위해 `range_t(begin, end)` 형태의 좌표 변환을 지원

---

## 3. C++ ruleset 정의 pattern (ASN.1 parser 예시)

C++11 환경을 기준으로 작성된 ruleset 정의 code snippet

```cpp
enum token_userdefined {
    token_sequencebody = token_userdefine,
    token_setbody,
    token_namednumberlist,
    token_namednumberelement,
    token_sequenceofbody,
    token_defaultval,
    token_phrase,
    token_sentence
};

// 1. Group / Category Setup
ac->set_group(token_builtintype, {token_bool, token_int, token_visiblestring, token_usertype});
ac->set_group(token_class, {token_application, token_private, token_universal});
ac->set_group(token_taggedmode, {token_implicit, token_explicit});

// 2. Leaf & Tag Rules
ac->insert_as(token_tag, {token_lbracket, token_number, token_rbracket});
ac->insert_as(token_defaultval, {token_default, token_lbrace, token_rbrace});

// 3. Sub-structure & List Rules
ac->insert_as(token_namednumberelement, {token_identifier, token_lparen, token_number, token_rparen});
ac->repeat_as(token_namednumberlist, token_comma, {token_namednumberelement});

// 4. Construct & Sentence Rules
ac->insert_as(token_phrase, {token_enum, token_lbrace, token_namednumberlist, token_rbrace});
ac->insert_as(token_sentence, {token_lvalue, token_assign, token_phrase});
```

---

## 5. AC reduction parser rule 작성 layering 원칙

Aho-Corasick 엔진은 matching되는 즉시 치환하므로, **Specific rule이 Generic rule보다 먼저 실행**되도록 단계를 분리해야 함.

```
┌─────────────────────────────────────────────────────────────┐
│ Layer 5: Sentence    (lvalue ::= phrase)                    │
├─────────────────────────────────────────────────────────────┤
│ Layer 4: Construct   (INTEGER { list }, SEQUENCE { elem })  │
├─────────────────────────────────────────────────────────────┤
│ Layer 3: Repeat/List (repeat_as: element list)              │
├─────────────────────────────────────────────────────────────┤
│ Layer 2: Element     (id ( num ), tag + type)               │
├─────────────────────────────────────────────────────────────┤
│ Layer 1: Leaf/Tag    ([ APPLICATION 0 ])                    │
└─────────────────────────────────────────────────────────────┘

```

### 작성 주의사항 checklist

1. **특수 키워드의 이른 그룹화 금지**: 구문 구조 키워드(`token_int`, `token_enum` 등)를 Broad 그룹(`builtintype`)에 성급히 포함시키면 Generic rule이 삼켜버림.
2. **원소 token의 완전성 보장**: `repeat_as`에 사용되는 원소 token 내부 구조는 최우선 reduction parse에서 깨끗하게 완전 환원되어야 함.
3. **matching 통계 분석 활용**: Specific pattern 실행 전에 Generic pattern의 matching 횟수가 비정상적으로 높다면 rule 충돌 발생 신호임.

---

## 6. Project TODO List

```text
================================================================================
[TODO List] Aho-Corasick Engine Enhancement
================================================================================
[X] 1. Group / Virtual Token basic infrastructure
    [X] 1.1 Support `insert_as` for virtual token replacement
    [X] 1.2 Support `set_group` for token categorization
[X] 2. Sub-pattern reduction & repeat mechanism
    [X] 2.1 Implement loop-based reduction pass in `search()`
    [X] 2.2 Add `repeat_as` delimiter and non-delimiter handling
    [X] 2.3 Coordinate transformation (`token_span`) for nested ranges
[X] 3. Verification & Test Case Suite
    [X] 3.1 Test Case 1: Simple SEQUENCE reduction (PASS)
    [X] 3.2 Test Case 2: Tagged SEQUENCE reduction (PASS)
    [X] 3.3 Test Case 3: Named Number / Enum list reduction (PASS)
    [X] 3.4 Test Case 4: ENUMERATED inside SEQUENCE (PASS)
    [X] 3.5 Test Case 5: PersonnelRecord with DEFAULT & SEQUENCE OF (PASS)
[ ] 4. Optimization & Edge Case Handling
    [ ] 4.1 Memory/Performance optimization for reduction loops
    [ ] 4.2 Specific vs Generic rule priority & ambiguity resolution
[ ] 5. Refactoring & Cleanup
================================================================================

```

## 7. Gemini Q&A : ruleset 작성 주의점을 전부 나열해 보면..

* 상향식(Bottom-Up) reduction을 수행하는 **Aho-Corasick 기반 parser/트랜스파일러**에서 ruleset(Grammar Rules)을 정의할 때 반드시 지켜야 할 주의사항을 정리했습니다.
* Aho-Corasick algorithm은 입력 stream에서 pattern을 발견하는 즉시 가장 빨리/가장 길게 matching된 구간을 치환(Reduce)하려는 성질이 있습니다. 따라서 문맥 자유 문법(CFG) 기반의 LALR parser보다 **token 오염 및 충돌 예방**에 훨씬 세심한 rule 설계가 필요합니다.

---

### 1. 그룹(Group) 및 wildcard 사용 주의점

* **특수 키워드의 그룹 포섭 지양**
  * 특정 구문 구조(예: `INTEGER { ... }`)에 핵심으로 사용되는 단일 token(`token_int`)을 broad한 그룹(`token_builtintype`)에 묶어두면, 상위 rule이 작동하기 전에 generic한 rule(`token_identifier + token_builtintype`)이 먼저 터져서 구문을 집어삼킵니다.
  * **원칙**: 구문 구조의 키워드로 쓰이는 token은 그룹화 시점을 유예하거나, 단독 키워드 pattern을 최우선 reduction 대상에 두어야 합니다.
* **그룹 간 순환/중복 정의 금지**
  * 그룹 $A$가 그룹 $B$를 포함하고, 그룹 $B$의 구성 요소가 다시 그룹 $A$로 치환되는 pattern이 존재하면 무한 reduction loop나 오버랩 충돌이 발생합니다.

---

### 2. reduction 우선순위 및 충돌(Conflict) 제어

* **Specific(구체적) rule과 Generic(포괄적) rule의 격리**
  * 길이/구조가 비슷한 pattern이 경합할 때, 범용 rule이 먼저 환원되면 세부 구문 구조 분석이 불가능해집니다.
  * **예시**: `token_identifier ( token_number )` (Specific) vs `token_identifier token_usertype` (Generic)
  * **원칙**: 가장 명확하고 고유한 문법 요소를 만들어내는 Specific rule이 항상 먼저 실행되도록 rule 정의 순서 및 트리 레벨을 배치해야 합니다.
* **좌측 재귀(Left Recursion) 및 과도한 이중 상속 구조 방지**
  * `A -> A B` 형태의 rule이나 `A -> B`, `B -> A` 형태의 단순 치환 rule이 중첩되면 입력 token의 위치(pos/len) 정보가 왜곡되어 sequence 추적이 실패합니다.

---

### 3. `repeat_as` (sequence/list) 정의 시 주의점

* **원소(Element) token의 완전성(Atomicity) 확보**
  * `repeat_as`에 사용되는 원소 token(예: `token_namednumberelement`) 내부 구성 요소가 **단 하나라도 외부 Generic rule에 의해 먼저 치환되면 `repeat_as` 전체가 무산**됩니다.
  * **원칙**: `repeat_as`로 묶일 기본 단위는 그 어떤 일반 rule과도 부분 matching이 겹치지 않도록 가장 빠른 단계(Early Pass)에서 완전히 reduction시켜 놓아야 합니다.
* **구분자(Delimiter)의 중복 의미 사용 제한**
  * `repeat_as`에서 구분자로 지정된 token(예: `token_comma`)이 다른 rule의 일반 요소로 섞여 들어가면, list의 경계가 무너지거나 list 생성이 도중에 중단됩니다.

---

### 4. 상향식(Bottom-Up) 단계별 layering(Layering) 원칙

Aho-Corasick ruleset은 **단순한 token $\rightarrow$ 복합 구조 $\rightarrow$ 완성된 문장** 순으로 layer가 엄격히 분리되어야 합니다.

| layer 단계 | 주요 역할 | rule 예시 | 작성 주의점 |
| --- | --- | --- | --- |
| **Layer 1: Leaf & Tag** | literal, tag, 기본 단위 결합 | `token_tag ::= [ number ]` | 가장 명확한 최소 단위만 환원 |
| **Layer 2: Element** | list에 들어갈 원소 구조 생성 | `namednumberelement ::= id ( num )` | Generic rule 개입 절대 차단 |
| **Layer 3: Repeat/List** | 동일 원소의 연속체 합성 | `repeat_as(list, comma, {element})` | 원소 및 구분자 순수성 유지 |
| **Layer 4: Construct/Phrase** | 구조체, 타입 block 완성 | `phrase ::= INTEGER { list }` | 키워드 오염 방지 |
| **Layer 5: Sentence/Statement** | 최상위 구문 완성 | `sentence ::= lvalue ::= phrase` | 최종 문장 matching |

---

### 요약: rule 작성 checklist

1. [ ] **키워드 검증**: `INTEGER`, `ENUMERATED`, `SEQUENCE` 등 구문 시작 키워드가 일반 그룹(`builtintype` 등)에 묶여서 엉뚱한 Generic rule을 먼저 트리거하지 않는가?
2. [ ] **원소 보호**: `repeat_as`에 들어갈 원소(Element)가 일반 `namedtype`이나 `taggedtype`으로 오인되어 먼저 치환될 가능성이 없는가?
3. [ ] **통계 활용**: pattern frequency statistics를 확인했을 때, 하위 레벨의 Specific pattern(Pattern 0 등)이 실행되기 전에 상위/범용 pattern(Pattern 14 등)의 matching 횟수가 기형적으로 높지 않은가?
