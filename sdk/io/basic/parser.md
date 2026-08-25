## parser 기초

* 문법 구문 분석 중심 (Grammar-Driven)
  * 문법 규칙(CFG)을 바탕으로 DFA/NFA 상태 전환 table(State Table)과 스택(Stack)을 생성
  * token을 하나씩 보면서 Shift / Reduce 행동을 결정
* Lookahead(예측 기호) 기반
  * 다음에 올 token을 0개~1개 미리 보고
  * 충돌(Shift/Reduce 또는 Reduce/Reduce Conflict)을 해결
* DFA : Deterministic Finite Automata
  * $M = (Q, \Sigma, \delta, q_0, F)$
  * $Q$: 유한 상태 집합 (a finite set of internal states)
  * $\Sigma$: 입력 어휘 집합 (a finite set of symbols called the input alphabet)
  * $\delta : Q \times \Sigma \rightarrow Q$: 단일 상태를 반환하는 전이 함수 (a total function called the transition function)
  * $q_0 \in Q$: 시작 상태 (the initial state)
  * $F \subseteq Q$: 최종/수락 상태 집합 (a set of final states)
  * 정확히 하나의 전이만 존재 (비결정성 없음, 전이 경로가 명확하며 예측 가능함)
* NFA : Non-Deterministic Finite Automata
  * $M = (Q, \Sigma, \delta, q_0, F)$
  * $Q$: 유한 상태 집합 (a finite set of internal states)
  * $\Sigma$: 입력 어휘 집합 (a finite set of symbols called the input alphabet)
  * $\delta : Q \times (\Sigma \cup \{\epsilon\}) \rightarrow 2^Q$: 여러 상태의 집합을 반환하는 전이 함수 (a total function called the transition function)
  * $q_0 \in Q$: 시작 상태 (the initial state)
  * $F \subseteq Q$: 최종/수락 상태 집합 (a set of final states)
  * 0개 이상의 전이 가능 ($\epsilon$-이동 포함)
* LL 문법 : Left to right, Left most derivation
  * 방향: 왼쪽에서 오른쪽으로 읽으며 좌측 유도(Leftmost Derivation)
  * 접근: 상향식이 아닌 하향식(Top-Down) 구조
  * 제약: 좌측 재귀(Left Recursion)가 있으면 무한 loop에 빠지므로 이를 제거
  * 구현: 단순하고 직관적이어서 직접 parser를 만들기 쉬움
* LR 문법 : Left to right, Rightmost derivation in reverse(우측 유도의 역순)
  * 방향: 왼쪽에서 오른쪽으로 읽으나, 우측 유도(Rightmost Derivation)의 역순으로 축소(Reduce)
  * 접근: 하향식이 아닌 상향식(Bottom-Up) 구조
  * 성능: 표현력이 더 강하며, 대부분의 프로그래밍 언어 구문 분석에 적합
  * 구현: 자동 생성 도구(Yacc, Bison 등)를 주로 사용하며 table이 복잡
* LR(0)
  * 특징
    * 예측 기호(Lookahead)가 전혀 없음
    * parser parsing table 상태 수가 적어 메모리 효율 높음. 문법 충돌(Shift-Reduce, Reduce-Reduce Conflict)이 자주 발생
  * 동작: 오직 문법 규칙의 진행 상태만 보고 Shift 또는 Reduce를 결정
  * 단점: 정보가 부족해 충돌(Conflict)이 아주 쉽게 발생하며, 사용할 수 있는 문법 범위가 매우 좁음
* SLR (Simple LR) parser
  * 특징
    * LR(0) 상태를 기반으로 하되, FOLLOW 집합 정보를 추가로 활용
    * parsing table 상태 수가 적어 메모리 효율 높음. 문법 충돌(Shift-Reduce, Reduce-Reduce Conflict)이 자주 발생
  * 동작: Reduce를 수행할 때 다음에 올 수 있는 기호가 FOLLOW 집합에 포함될 때만 허용
  * 장점: LR(0)보다 충돌을 잘 막아주며 table이 작음
  * 단점: 여전히 정밀도가 낮아 복잡한 문법에는 한계가 있음
* LALR Look-Ahead LR Parser
  * 특징
    * LR(1) parser의 상태 중 'core(Core, Lookahead를 제외한 LR(0) 아이템 집합)'가 동일한 상태들을 하나로 병합하여 만듦.
    * LR(1)의 높은 표현력과 SLR(1) 수준의 작은 table 크기라는 장점을 모두 취한 방식
  * 동작: LR(1) 상태 중 문법 위치(Core)가 같은 것끼리 하나로 합쳐서 상태 수를 줄임
  * 장점: 상태 수는 SLR처럼 적으면서도, 문법 처리 능력은 LR(1)에 가까울 정도로 강력
  * 기타: 실제 많은 프로그래밍 언어 컴파일러와 parser 생성기(Yacc, Bison 등)에서 표준으로 사용
  * 스택(Stack)과 parsing table(Parsing Table)을 이용해 이동 및 환원(Shift-Reduce) 방식을 수행
    * Shift (이동): 입력 token을 읽어 스택에 push하고 다음 상태로 이동
    * Reduce (환원): 스택 상단의 token/상태들이 문법 규칙의 우변(RHS)과 일치할 때, 이를 좌변(LHS)의 비terminal(Non-terminal) 기호로 교체
    * Accept (수락): 시작 기호로 성공적으로 환원되고 입력의 끝($)에 도달하면 parsing을 완료
    * Error (오류): 문법에 맞지 않는 입력이 들어오면 error 처리를 수행
* LR(1) (Canonical LR Parser)
  * 특징
    * Lookahead(선행 심볼) 정보를 1개 활용하여 거의 모든 문맥 자유 문법을 정확히 parsing하지만
    * 상태 수가 너무 많아져 table 크기가 거대해짐
  * 동작: 현재 상태에서 허용되는 정확한 다음 기호 조건에서만 Reduce를 수행
  * 장점: 가장 강력하며 정밀한 구문 분석이 가능
  * 단점: 상태(State) 개수가 너무 많아져서 parsing table 크기가 엄청나게 커짐

* LR parser 관계 요약 구조

```
[LR(0) Items] ──(Add FOLLOW set)──> [SLR(1) Parsing Table]
      │
 (Add Lookahead)
      ▼
[LR(1) Items] ──(Merge same LR(0) Core)──> [LALR(1) Parsing Table]
```

* 분류표
  * 전통적인 전형적 결정적 문맥 자유 문법(Deterministic Context-Free Grammar, DCFG) 기반의 결정적 parser(Deterministic Parser)

|  | LR(0) | SLR(1) | LALR(1) | LR(1) |
| --- | --- | --- | --- | --- |
| 상태(State) 수 (table 크기) | 작음 | 작음 (LR(0) 수준) | 작음 (SLR 수준) | 매우 큼 |
| 예측 기호(Look-Ahead) 사용 여부 | 사용 안 함 | FOLLOW 집합 활용 | 합쳐진 예측 기호 활용 | 개별 예측 기호 포함 |
| 문법 처리 능력 (정밀도) | 가장 낮음 | 낮음 | 높음(대부분의 프로그래밍 언어 표현 가능) | 가장 높음 |
| Reduce-Reduce 충돌 | 빈번히 발생 | 발생 가능 | 발생 가능 (병합 시 생성) | 없음 |
| Shift-Reduce 충돌 | 빈번히 발생 | 발생 가능 | 없음 (LR(1) 충돌 무시 가정) | 없음 |

## Gemini Q&A - LL 문법 table 생성 과정

LL parser(주로 **LL(1) parser**)의 parsing table 생성 과정에 대해 설명하겠습니다.
LL(1) parser는 **상향식(Bottom-Up)이 아닌 하향식(Top-Down) parser**로, **첫 번째 L은 Left-to-right scan**(좌에서 우로 입력 읽기), **두 번째 L은 Leftmost derivation**(최좌단 유도), **(1)은 Lookahead 1개**를 의미합니다.
LL(1) 문법 table을 만들기 위해서는 먼저 **FIRST 집합**과 **FOLLOW 집합**을 계산해야 합니다.

---

### 1단계: FIRST 집합과 FOLLOW 집합 계산

#### 1. FIRST 집합: $\text{FIRST}(X)$

비terminal 또는 terminal 기호 $X$로부터 유도될 수 있는 문장 형태의 **첫 번째 terminal 기호들의 집합**입니다.

* **terminal $a$:** $\text{FIRST}(a) = \{a\}$
* **비terminal $A \rightarrow \epsilon$:** $\epsilon \in \text{FIRST}(A)$
* **비terminal $A \rightarrow Y_1 Y_2 \dots Y_k$:**
* $\text{FIRST}(Y_1)$의 모든 terminal을 $\text{FIRST}(A)$에 추가합니다.
* 만약 $Y_1$이 $\epsilon$을 유도할 수 있다면($\epsilon \in \text{FIRST}(Y_1)$), $\text{FIRST}(Y_2)$의 terminal도 추가하며, 이 과정을 $\epsilon$을 안 가질 때까지 반복합니다.

#### 2. FOLLOW 집합: $\text{FOLLOW}(A)$

비terminal $A$ **바로 다음에 올 수 있는 terminal 기호들의 집합**입니다.

* **시작 기호 $S$:** $\text{FOLLOW}(S)$에 입력의 끝을 나타내는 **`$`** 기호를 넣습니다.
* **생산 규칙 $A \rightarrow \alpha B \beta$:** $\text{FIRST}(\beta)$의 $\epsilon$을 제외한 모든 요소를 $\text{FOLLOW}(B)$에 추가합니다.
* **생산 규칙 $A \rightarrow \alpha B$ 또는 $A \rightarrow \alpha B \beta$ ($\epsilon \in \text{FIRST}(\beta)$):** $\text{FOLLOW}(A)$의 모든 요소를 $\text{FOLLOW}(B)$에 추가합니다.

---

### 2단계: LL(1) parsing table 구축 규칙

parsing table $M[A, a]$는 **[비terminal $A$, terminal $a$]** 행렬 구조로 만들어지며, 적용할 생산 규칙 번호(또는 우변)를 기록합니다.
문법의 각 생산 규칙 $A \rightarrow \alpha$에 대해 다음 과정을 수행합니다:

1. **FIRST 기반 채우기:**
$\text{FIRST}(\alpha)$에 속하는 모든 terminal $a$에 대해, $M[A, a]$에 규칙 $A \rightarrow \alpha$를 추가합니다.
2. **FOLLOW 기반 채우기 ($\epsilon$ 처리):**
만약 $\epsilon \in \text{FIRST}(\alpha)$라면, $\text{FOLLOW}(A)$에 속하는 모든 terminal $b$(엔드마크 `$` 포함)에 대해 $M[A, b]$에 규칙 $A \rightarrow \alpha$를 추가합니다.

> **LL(1) 문법 조건:** 만약 table의 한 셀 $M[A, a]$에 **2개 이상의 생산 규칙이 들어간다면 충돌(Conflict)**이 발생한 것이며, 해당 문법은 LL(1) 문법이 아닙니다. (좌우선 좌재귀 문법 등이 원인이 됨)

---

### 3단계: 구체적인 예시 적용

다음 간단한 산술 문법으로 table을 생성해 보겠습니다.

#### 예시 문법 (좌재귀가 제거된 상태)

1. $E \rightarrow T E'$
2. $E' \rightarrow + T E' \mid \epsilon$
3. $T \rightarrow F T'$
4. $T' \rightarrow * F T' \mid \epsilon$
5. $F \rightarrow ( E ) \mid \text{id}$

#### FIRST & FOLLOW 계산 결과

* **$\text{FIRST}$**
  * $\text{FIRST}(E) = \text{FIRST}(T) = \text{FIRST}(F) = \{ (, \text{id} \}$
  * $\text{FIRST}(E') = \{ +, \epsilon \}$
  * $\text{FIRST}(T') = \{ *, \epsilon \}$

* **$\text{FOLLOW}$**
  * $\text{FOLLOW}(E) = \text{FOLLOW}(E') = \{ ), \$ \}$
  * $\text{FOLLOW}(T) = \text{FOLLOW}(T') = \{ +, ), \$ \}$
  * $\text{FOLLOW}(F) = \{ *, +, ), \$ \}$

#### 완성된 LL(1) parsing table $M[A, a]$

| Non-terminal | id | + | * | ( | ) | $ |
| --- | --- | --- | --- | --- | --- | --- |
| **$E$** | $E \rightarrow T E'$ |  |  | $E \rightarrow T E'$ |  |  |
| **$E'$** |  | $E' \rightarrow + T E'$ |  |  | $E' \rightarrow \epsilon$ | $E' \rightarrow \epsilon$ |
| **$T$** | $T \rightarrow F T'$ |  |  | $T \rightarrow F T'$ |  |  |
| **$T'$** |  | $T' \rightarrow \epsilon$ | $T' \rightarrow * F T'$ |  | $T' \rightarrow \epsilon$ | $T' \rightarrow \epsilon$ |
| **$F$** | $F \rightarrow \text{id}$ |  |  | $F \rightarrow ( E )$ |  |  |

---

## Gemini Q&A - LR(0)/SLR(1) 문법 table 생성 과정

LR parser는 하향식(LL)과 달리 입력 문자열을 스택에 쌓으면서 비terminal로 줄여나가는 **상향식(Bottom-Up) parser**입니다. parsing table을 만들기 위해 **점(Dot, `•`)** 기호를 활용한 아이템 집합과 DFA(유한 automata)를 구축합니다.

---

### 1단계: 확장 문법(Augmented Grammar) 생성

시작 기호 $S$에 대해 새로운 시작 기호 $S'$를 도입하여 규칙 $S' \rightarrow S$를 추가합니다. 이는 parser가 입력 전체를 성공적으로 받아들였는지(Accept) 쉽게 판별하기 위함입니다.

---

### 2단계: LR(0) 아이템 및 closure / goto 함수

#### 1. LR(0) Item (아이템)

생산 규칙의 우변에 점(`•`)을 찍어 parsing의 진행 상태를 표현합니다.

* 예: $A \rightarrow X Y Z$ 규칙에 대해
* $A \rightarrow • X Y Z$ : $X Y Z$를 읽을 준비가 됨
* $A \rightarrow X • Y Z$ : $X$를 읽었고 $Y Z$를 기다림
* $A \rightarrow X Y Z •$ : $X Y Z$를 모두 읽어 $A$로 환원(Reduce)할 준비가 됨

#### 2. closure(I) 함수

아이템 집합 $I$에서 점(`•`) 바로 뒤에 비terminal $B$가 올 경우($A \rightarrow \alpha • B \beta$), $B$를 좌변으로 하는 모든 규칙의 점을 맨 앞에 찍어($B \rightarrow • \gamma$) 집합에 포함시킵니다. 더 이상 새로운 아이템이 추가되지 않을 때까지 반복합니다.

#### 3. goto(I, X) 함수

상태 $I$에서 기호 $X$(terminal 또는 비terminal)를 읽었을 때 이동하는 다음 상태를 구합니다.

* $I$에 속한 아이템 중 $A \rightarrow \alpha • X \beta$ 형태의 점을 한 칸 뒤로 옮긴 $A \rightarrow \alpha X • \beta$ 들을 모은 후, 이 집합에 `closure()`를 적용합니다.

---

### 3단계: Canonical LR(0) Collection (상태들의 집합) 구축

1. $I_0 = \text{closure}(\{S' \rightarrow • S\})$ 로 시작 상태를 만듭니다.
2. 현재 존재하는 모든 상태 $I_i$에 대해 문법 기호 $X$로 이동할 수 있는 $\text{goto}(I_i, X)$를 계산하여 새로운 상태 $I_j$들을 계속 찾아냅니다.
3. 더 이상 새로운 상태(DFA node)가 생기지 않을 때까지 반복합니다.

---

### 4단계: parsing table(ACTION & GOTO) 구성 규칙

상태 집합 $I_0, I_1, \dots, I_n$이 완성되면 **ACTION table**(terminal 대상)과 **GOTO table**(비terminal 대상)을 채웁니다.

1. **Shift (이동):**

* $A \rightarrow \alpha • a \beta \in I_i$ 이고 $\text{goto}(I_i, a) = I_j$ (단, $a$는 terminal)이면, $\text{ACTION}[i, a] = \text{Shift } j$ ($S_j$)

2. **Reduce (환원):**

* $A \rightarrow \alpha • \in I_i$ 이면 (단, $A \neq S'$)
* **LR(0) parser:** 모든 terminal $a$ (및 `$`)에 대해 $\text{ACTION}[i, a] = \text{Reduce } (A \rightarrow \alpha)$
* **SLR(1) parser:** $a \in \mathbf{FOLLOW(A)}$ 인 terminal에 대해서만 $\text{ACTION}[i, a] = \text{Reduce } (A \rightarrow \alpha)$

3. **Accept (수락):**

* $S' \rightarrow S • \in I_i$ 이면, $\text{ACTION}[i, \$] = \text{Accept}$

4. **GOTO:**

* $\text{goto}(I_i, A) = I_j$ (단, $A$는 비terminal)이면, $\text{GOTO}[i, A] = j$

> **SLR(1)의 핵심 차이:** LR(0)는 환원할 때 모든 입력에 Reduce를 넣어서 충돌이 자주 납니다. SLR(1)은 환원할 비terminal $A$의 **$\text{FOLLOW}(A)$ 집합에 포함된 token이 들어올 때만** Reduce를 넣어 충돌을 줄입니다.

---

## Gemini Q&A - SLR(1) 기초 class 구현 및 테스트

C++11 기반으로 작성된 SLR(1) parser 구현 code입니다. 앞서 살펴본 문법 규칙과 closure, goto, FOLLOW 집합을 기반으로 parsing table을 생성 및 수행하는 기본 class 구조로 설계되었습니다.

### 주요 설계 구조

* `LR0Item`: `[Production Index, Dot Position]` 상태 표현
* `SLRParser`: LR(0) 아이템 집합 생성, Closure/Goto 계산, FOLLOW 집합 기반 ACTION/GOTO table 구축 및 구문 분석 수행

```cpp
#include <iostream>
#include <vector>
#include <string>
#include <set>
#include <map>
#include <stack>
#include <algorithm>
#include <iomanip>

// Production rule representation (1-indexed for convenience)
struct Rule {
    int id;
    std::string lhs;
    std::vector<std::string> rhs;
};

// LR(0) Item: [rule_index, dot_position]
struct LR0Item {
    int rule_id;
    size_t dot;

    bool operator<(const LR0Item& other) const {
        if (rule_id != other.rule_id) return rule_id < other.rule_id;
        return dot < other.dot;
    }

    bool operator==(const LR0Item& other) const {
        return rule_id == other.rule_id && dot == other.dot;
    }
};

using State = std::set<LR0Item>;

enum class ActionType { SHIFT, REDUCE, ACCEPT, ERROR };

struct Action {
    ActionType type = ActionType::ERROR;
    int target = -1; // State index for SHIFT, Rule index for REDUCE
};

class SLRParser {
private:
    std::vector<Rule> rules;
    std::set<std::string> terminals;
    std::set<std::string> non_terminals;
    std::string start_symbol;

    std::vector<State> states;
    std::map<int, std::map<std::string, Action>> action_table;
    std::map<int, std::map<std::string, int>> goto_table;
    std::map<std::string, std::set<std::string>> follow_sets;

    // Compute closure of a given item set
    State compute_closure(State I) {
        bool added = true;
        while (added) {
            added = false;
            State current = I;
            for (const auto& item : current) {
                const auto& rule = rules[item.rule_id];
                if (item.dot < rule.rhs.size()) {
                    std::string B = rule.rhs[item.dot];
                    if (non_terminals.count(B)) {
                        for (const auto& r : rules) {
                            if (r.lhs == B) {
                                LR0Item newItem{r.id, 0};
                                if (I.find(newItem) == I.end()) {
                                    I.insert(newItem);
                                    added = true;
                                }
                            }
                        }
                    }
                }
            }
        }
        return I;
    }

    // Compute GOTO(I, X)
    State compute_goto(const State& I, const std::string& X) {
        State J;
        for (const auto& item : I) {
            const auto& rule = rules[item.rule_id];
            if (item.dot < rule.rhs.size() && rule.rhs[item.dot] == X) {
                J.insert(LR0Item{item.rule_id, item.dot + 1});
            }
        }
        return compute_closure(J);
    }

    // Build Canonical Collection of LR(0) items and Parsing Tables
    void build_tables() {
        // Step 1: Initial State I0 = closure({S' -> . S})
        State start_state = compute_closure({LR0Item{0, 0}});
        states.push_back(start_state);

        std::vector<std::string> symbols;
        symbols.insert(symbols.end(), terminals.begin(), terminals.end());
        symbols.insert(symbols.end(), non_terminals.begin(), non_terminals.end());

        // Step 2: Build DFA State sets
        for (size_t i = 0; i < states.size(); ++i) {
            for (const auto& X : symbols) {
                State next_state = compute_goto(states[i], X);
                if (next_state.empty()) continue;

                auto it = std::find(states.begin(), states.end(), next_state);
                int next_idx = 0;
                if (it == states.end()) {
                    states.push_back(next_state);
                    next_idx = static_cast<int>(states.size() - 1);
                } else {
                    next_idx = static_cast<int>(std::distance(states.begin(), it));
                }

                if (terminals.count(X)) {
                    action_table[static_cast<int>(i)][X] = Action{ActionType::SHIFT, next_idx};
                } else if (non_terminals.count(X) && X != rules[0].lhs) {
                    goto_table[static_cast<int>(i)][X] = next_idx;
                }
            }
        }

        // Step 3: Fill REDUCE and ACCEPT actions using FOLLOW sets
        for (size_t i = 0; i < states.size(); ++i) {
            for (const auto& item : states[i]) {
                const auto& rule = rules[item.rule_id];
                if (item.dot == rule.rhs.size()) { // Dot is at the end
                    if (rule.lhs == rules[0].lhs) {
                        action_table[static_cast<int>(i)]["$"] = Action{ActionType::ACCEPT, 0};
                    } else {
                        // SLR(1): Apply REDUCE for all symbols in FOLLOW(lhs)
                        for (const auto& a : follow_sets[rule.lhs]) {
                            action_table[static_cast<int>(i)][a] = Action{ActionType::REDUCE, rule.id};
                        }
                    }
                }
            }
        }
    }

public:
    SLRParser(std::vector<Rule> grammar_rules,
              std::set<std::string> terms,
              std::set<std::string> non_terms,
              std::map<std::string, std::set<std::string>> follows)
        : rules(std::move(grammar_rules)),
          terminals(std::move(terms)),
          non_terminals(std::move(non_terms)),
          follow_sets(std::move(follows)) {
        terminals.insert("$");
        build_tables();
    }

    bool parse(const std::vector<std::string>& input_tokens) {
        std::stack<int> state_stack;
        state_stack.push(0);

        std::vector<std::string> tokens = input_tokens;
        tokens.push_back("$");

        size_t cursor = 0;
        std::cout << std::left << std::setw(10) << "Step"
                  << std::setw(20) << "Action"
                  << "Lookahead\n";
        std::cout << std::string(45, '-') << "\n";

        int step = 1;
        while (true) {
            int state = state_stack.top();
            std::string a = tokens[cursor];

            if (action_table[state].find(a) == action_table[state].end()) {
                std::cout << "Syntax Error at token: " << a << "\n";
                return false;
            }

            Action act = action_table[state][a];
            if (act.type == ActionType::SHIFT) {
                std::cout << std::left << std::setw(10) << step++
                          << std::setw(20) << ("Shift " + std::to_string(act.target))
                          << a << "\n";
                state_stack.push(act.target);
                ++cursor;
            } else if (act.type == ActionType::REDUCE) {
                const auto& rule = rules[act.target];
                std::cout << std::left << std::setw(10) << step++
                          << std::setw(20) << ("Reduce " + std::to_string(rule.id) + " (" + rule.lhs + ")")
                          << a << "\n";
                for (size_t i = 0; i < rule.rhs.size(); ++i) {
                    state_stack.pop();
                }
                int top_state = state_stack.top();
                state_stack.push(goto_table[top_state][rule.lhs]);
            } else if (act.type == ActionType::ACCEPT) {
                std::cout << std::left << std::setw(10) << step
                          << std::setw(20) << "ACCEPT"
                          << a << "\n";
                return true;
            }
        }
    }
};

int main() {
    // Grammar definition:
    // 0: S' -> E
    // 1: E  -> E + T
    // 2: E  -> T
    // 3: T  -> id
    std::vector<Rule> rules = {
        {0, "S'", {"E"}},
        {1, "E",  {"E", "+", "T"}},
        {2, "E",  {"T"}},
        {3, "T",  {"id"}}
    };

    std::set<std::string> terminals = {"+", "id"};
    std::set<std::string> non_terminals = {"S'", "E", "T"};

    // Pre-calculated FOLLOW sets for SLR(1)
    std::map<std::string, std::set<std::string>> follow_sets = {
        {"S'", {"$"}},
        {"E",  {"+", "$"}},
        {"T",  {"+", "$"}}
    };

    SLRParser parser(rules, terminals, non_terminals, follow_sets);

    std::vector<std::string> input = {"id", "+", "id"};
    std::cout << "Testing SLR(1) Parser with input: id + id\n\n";

    if (parser.parse(input)) {
        std::cout << "\nParsing Succeeded!\n";
    } else {
        std::cout << "\nParsing Failed!\n";
    }

    return 0;
}
```

Console Output

```
Testing SLR(1) Parser with input: id + id

Step      Action              Lookahead
---------------------------------------------
1         Shift 1             id
2         Reduce 3 (T)        +
3         Reduce 2 (E)        +
4         Shift 4             +
5         Shift 1             id
6         Reduce 3 (T)        $
7         Reduce 1 (E)        $
8         ACCEPT              $

Parsing Succeeded!
```

---

## Gemini Q&A - LALR(1) 기초 class 구현 및 테스트

LALR(1) parser는 LR(1) 아이템 집합 중 core(점의 위치와 규칙이 동일한 상태)가 같은 상태들을 병합(Merge)하여 table 크기를 SLR(1) 수준으로 유지하면서도 표현력을 높이는 parser입니다.
C++11 기반으로 작성된 LALR(1) parser 모사 소스 code입니다. LR(1) 아이템 생성 $\rightarrow$ Core 기반 상태 병합 $\rightarrow$ LALR parsing table 구축 및 테스트의 전체 흐름을 구현했습니다.

---

### 주요 구현 특징

* **`LR1Item`:** `[Rule Index, Dot Position, Lookahead]`를 포함하는 LR(1) 단위 표현
* **`extract_core()`:** LR(1) 상태에서 Lookahead를 제외한 LR(0) core 집합을 추출
* **`merge_states()`:** 동일한 core를 가진 LR(1) 상태들을 찾아 Lookahead 집합을 합치며 병합

> [!NOTE]
> **Note:** 본 예제 code는 핵심 구조 이해를 위해 `compute_first_of_sequence`의 FIRST 집합 계산이 간소화되어 있습니다. 실전 컴파일러 환경에서는 비terminal 전개 및 $\epsilon$-transition을 포함하는 완전한 FIRST algorithm을 적용해야 합니다.

```cpp
#include <iostream>
#include <vector>
#include <string>
#include <set>
#include <map>
#include <stack>
#include <algorithm>
#include <iomanip>

// Production rule representation
struct Rule {
    int id;
    std::string lhs;
    std::vector<std::string> rhs;
};

// LR(0) Item (Core representation)
struct LR0Item {
    int rule_id;
    size_t dot;

    bool operator<(const LR0Item& other) const {
        if (rule_id != other.rule_id) return rule_id < other.rule_id;
        return dot < other.dot;
    }

    bool operator==(const LR0Item& other) const {
        return rule_id == other.rule_id && dot == other.dot;
    }
};

// LR(1) Item: [LR(0) Core + Lookahead Symbol]
struct LR1Item {
    LR0Item core;
    std::string lookahead;

    bool operator<(const LR1Item& other) const {
        if (!(core == other.core)) return core < other.core;
        return lookahead < other.lookahead;
    }

    // operator== 추가 (C++11 방식)
    bool operator==(const LR1Item& other) const {
        return core == other.core && lookahead == other.lookahead;
    }
};

using LR1State = std::set<LR1Item>;
using CoreState = std::set<LR0Item>;

enum class ActionType { SHIFT, REDUCE, ACCEPT, ERROR };

struct Action {
    ActionType type = ActionType::ERROR;
    int target = -1; // State index for SHIFT, Rule index for REDUCE
};

class LALRParser {
private:
    std::vector<Rule> rules;
    std::set<std::string> terminals;
    std::set<std::string> non_terminals;

    std::vector<LR1State> lalr_states;
    std::map<int, std::map<std::string, Action>> action_table;
    std::map<int, std::map<std::string, int>> goto_table;

    // Helper: Extract LR(0) core from an LR(1) state
    CoreState extract_core(const LR1State& state) {
        CoreState core;
        for (const auto& item : state) {
            core.insert(item.core);
        }
        return core;
    }

    // Compute FIRST set for a sequence of symbols given a lookahead
    std::set<std::string> compute_first_of_sequence(
        const std::vector<std::string>& seq, size_t start_idx, const std::string& lookahead) {

        std::set<std::string> result;
        if (start_idx >= seq.size()) {
            result.insert(lookahead);
            return result;
        }

        std::string sym = seq[start_idx];
        if (terminals.count(sym)) {
            result.insert(sym);
        } else {
            // Simplified FIRST set logic for minimal grammar example
            // In actual complex grammars, a complete first calculation involving non-terminal expansion and $\epsilon$ processing is required.
            result.insert(lookahead);
        }
        return result;
    }

    // Compute Closure for LR(1) items
    LR1State compute_closure(LR1State I) {
        bool added = true;
        while (added) {
            added = false;
            LR1State current = I;
            for (const auto& item : current) {
                const auto& rule = rules[item.core.rule_id];
                if (item.core.dot < rule.rhs.size()) {
                    std::string B = rule.rhs[item.core.dot];
                    if (non_terminals.count(B)) {
                        auto lookaheads = compute_first_of_sequence(rule.rhs, item.core.dot + 1, item.lookahead);
                        for (const auto& r : rules) {
                            if (r.lhs == B) {
                                for (const auto& la : lookaheads) {
                                    LR1Item new_item{{r.id, 0}, la};
                                    if (I.find(new_item) == I.end()) {
                                        I.insert(new_item);
                                        added = true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        return I;
    }

    // Compute GOTO(I, X) for LR(1)
    LR1State compute_goto(const LR1State& I, const std::string& X) {
        LR1State J;
        for (const auto& item : I) {
            const auto& rule = rules[item.core.rule_id];
            if (item.core.dot < rule.rhs.size() && rule.rhs[item.core.dot] == X) {
                J.insert(LR1Item{{item.core.rule_id, item.core.dot + 1}, item.lookahead});
            }
        }
        return compute_closure(J);
    }

    // Merge canonical LR(1) states with matching cores into LALR(1) states
    void build_lalr_tables() {
        // Step 1: Generate Canonical LR(1) States
        LR1State start_state = compute_closure({LR1Item{{0, 0}, "$"}});
        std::vector<LR1State> lr1_states;
        lr1_states.push_back(start_state);

        std::vector<std::string> symbols;
        symbols.insert(symbols.end(), terminals.begin(), terminals.end());
        symbols.insert(symbols.end(), non_terminals.begin(), non_terminals.end());

        for (size_t i = 0; i < lr1_states.size(); ++i) {
            for (const auto& X : symbols) {
                LR1State next_state = compute_goto(lr1_states[i], X);
                if (next_state.empty()) continue;

                auto it = std::find(lr1_states.begin(), lr1_states.end(), next_state);
                if (it == lr1_states.end()) {
                    lr1_states.push_back(next_state);
                }
            }
        }

        // Step 2: Merge LR(1) states sharing the same LR(0) Core
        std::map<CoreState, std::vector<size_t>> core_to_state_indices;
        for (size_t i = 0; i < lr1_states.size(); ++i) {
            CoreState core = extract_core(lr1_states[i]);
            core_to_state_indices[core].push_back(i);
        }

        std::map<size_t, size_t> lr1_to_lalr_index;
        for (const auto& pair : core_to_state_indices) {
            LR1State merged_state;
            size_t new_lalr_idx = lalr_states.size();

            for (size_t orig_idx : pair.second) {
                merged_state.insert(lr1_states[orig_idx].begin(), lr1_states[orig_idx].end());
                lr1_to_lalr_index[orig_idx] = new_lalr_idx;
            }
            lalr_states.push_back(merged_state);
        }

        // Step 3: Populate LALR(1) ACTION and GOTO tables
        for (size_t i = 0; i < lalr_states.size(); ++i) {
            for (const auto& X : symbols) {
                LR1State next_state = compute_goto(lalr_states[i], X);
                if (next_state.empty()) continue;

                CoreState next_core = extract_core(next_state);
                size_t target_lalr_idx = 0;

                for (size_t k = 0; k < lalr_states.size(); ++k) {
                    if (extract_core(lalr_states[k]) == next_core) {
                        target_lalr_idx = k;
                        break;
                    }
                }

                if (terminals.count(X)) {
                    action_table[static_cast<int>(i)][X] = Action{ActionType::SHIFT, static_cast<int>(target_lalr_idx)};
                } else if (non_terminals.count(X) && X != rules[0].lhs) {
                    goto_table[static_cast<int>(i)][X] = static_cast<int>(target_lalr_idx);
                }
            }

            // Reduce and Accept actions based on exact Lookaheads
            for (const auto& item : lalr_states[i]) {
                const auto& rule = rules[item.core.rule_id];
                if (item.core.dot == rule.rhs.size()) { // Dot is at end
                    if (rule.lhs == rules[0].lhs) {
                        action_table[static_cast<int>(i)]["$"] = Action{ActionType::ACCEPT, 0};
                    } else {
                        // LALR(1): REDUCE only on exact LR(1) lookahead symbol
                        action_table[static_cast<int>(i)][item.lookahead] = Action{ActionType::REDUCE, rule.id};
                    }
                }
            }
        }
    }

public:
    LALRParser(std::vector<Rule> grammar_rules,
               std::set<std::string> terms,
               std::set<std::string> non_terms)
        : rules(std::move(grammar_rules)),
          terminals(std::move(terms)),
          non_terminals(std::move(non_terms)) {
        terminals.insert("$");
        build_lalr_tables();
    }

    bool parse(const std::vector<std::string>& input_tokens) {
        std::stack<int> state_stack;
        state_stack.push(0);

        std::vector<std::string> tokens = input_tokens;
        tokens.push_back("$");

        size_t cursor = 0;
        std::cout << std::left << std::setw(10) << "Step"
                  << std::setw(20) << "Action"
                  << "Lookahead\n";
        std::cout << std::string(45, '-') << "\n";

        int step = 1;
        while (true) {
            int state = state_stack.top();
            std::string a = tokens[cursor];

            if (action_table[state].find(a) == action_table[state].end()) {
                std::cout << "Syntax Error at token: " << a << "\n";
                return false;
            }

            Action act = action_table[state][a];
            if (act.type == ActionType::SHIFT) {
                std::cout << std::left << std::setw(10) << step++
                          << std::setw(20) << ("Shift " + std::to_string(act.target))
                          << a << "\n";
                state_stack.push(act.target);
                ++cursor;
            } else if (act.type == ActionType::REDUCE) {
                const auto& rule = rules[act.target];
                std::cout << std::left << std::setw(10) << step++
                          << std::setw(20) << ("Reduce " + std::to_string(rule.id) + " (" + rule.lhs + ")")
                          << a << "\n";
                for (size_t i = 0; i < rule.rhs.size(); ++i) {
                    state_stack.pop();
                }
                int top_state = state_stack.top();
                state_stack.push(goto_table[top_state][rule.lhs]);
            } else if (act.type == ActionType::ACCEPT) {
                std::cout << std::left << std::setw(10) << step
                          << std::setw(20) << "ACCEPT"
                          << a << "\n";
                return true;
            }
        }
    }
};

int main() {
    // Grammar definition:
    // 0: S' -> S
    // 1: S  -> V = R
    // 2: S  -> R
    // 3: L  -> * R
    // 4: L  -> id
    // 5: R  -> L
    std::vector<Rule> rules = {
        {0, "S'", {"S"}},
        {1, "S",  {"V", "=", "R"}},
        {2, "S",  {"R"}},
        {3, "V",  {"*", "R"}},
        {4, "V",  {"id"}},
        {5, "R",  {"V"}}
    };

    std::set<std::string> terminals = {"=", "*", "id"};
    std::set<std::string> non_terminals = {"S'", "S", "V", "R"};

    LALRParser parser(rules, terminals, non_terminals);

    std::vector<std::string> input = {"*", "id", "=", "id"};
    std::cout << "Testing LALR(1) Parser with input: * id = id\n\n";

    if (parser.parse(input)) {
        std::cout << "\nLALR(1) Parsing Succeeded!\n";
    } else {
        std::cout << "\nLALR(1) Parsing Failed!\n";
    }

    return 0;
}

```

Console Output

```
Testing LALR(1) Parser with input: * id = id

Step      Action              Lookahead
---------------------------------------------
1         Shift 6             *
2         Shift 8             id
3         Reduce 4 (V)        =
4         Reduce 5 (R)        =
5         Reduce 3 (V)        =
6         Shift 3             =
7         Shift 8             id
8         Reduce 4 (V)        $
9         Reduce 5 (R)        $
10        Reduce 1 (S)        $
11        ACCEPT              $

LALR(1) Parsing Succeeded!
```

---

### SLR(1) vs LALR(1) 차이 요약

* **SLR(1):** LR(0) 상태에 단순히 비terminal의 전체 $\text{FOLLOW}(A)$ 집합을 붙여 환원(Reduce)을 판단하므로, 오탐으로 인한 충돌이 발생할 확률이 높습니다.
* **LALR(1):** 구체적인 경로를 반영하는 LR(1) Lookahead 정보만을 보존하여 병합하므로, SLR(1)과 동일한 상태 수(table 크기)를 유지하면서도 정확한 시점에만 Reduce를 수행합니다.

---

## 토론 & TODO

* [ ] TODO 1: LALR(1) parser 예제에 완전한 FIRST/FOLLOW 자동 계산 algorithm 통합하기
* [ ] TODO 2: Shift-Reduce Conflict 발생 시 parser 생성기(Bison/Yacc)의 연산자 우선순위(Precedence) 처리 방식 분석하기
* [ ] Discussion: LALR(1) 상태 병합 시 Shift-Reduce 충돌은 새로 생기지 않지만, Reduce-Reduce 충돌은 왜 새로 생길 수 있는지 아이템 집합 수준에서 설명해보기

---

## references

* [Top-down_parsing](https://en.wikipedia.org/wiki/Top-down_parsing)
* [Bottom-up_parsing](https://en.wikipedia.org/wiki/Bottom-up_parsing)
* [LR_parser](https://en.wikipedia.org/wiki/LR_parser)
* [SLR_parser](https://en.wikipedia.org/wiki/SLR_parser)
* [LALR_parser](https://en.wikipedia.org/wiki/LALR_parser)
* [Canonical_LR_parser](https://en.wikipedia.org/wiki/Canonical_LR_parser)
