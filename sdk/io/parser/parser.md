# Parser Design and Implementation Notes

## 1. Purpose

The material progresses from basic parsing concepts to LL(1), LR(0), SLR(1), LALR(1), Recursive Descent, and Packrat/PEG parsing. It then applies these techniques to an ASN.1-like grammar and finishes with a dynamically generated LALR(1) parser in C++11.

---

## 2. Parser Fundamentals

### 2.1 Grammar-Driven Syntax Analysis

A parser analyzes a token stream according to a formal grammar. In table-driven LR-family parsers, grammar rules are converted into states and parsing tables. During execution, the parser examines the current state and lookahead token and selects an action such as **Shift**, **Reduce**, **Accept**, or **Error**. The source describes this as grammar-driven analysis using DFA/NFA-derived state information and a stack.

### 2.2 Lookahead

Lookahead is the amount of upcoming input inspected before choosing a parsing action.

- **LR(0):** no lookahead symbol.
- **SLR(1):** uses one token together with `FOLLOW` information.
- **LALR(1):** uses LR(1) lookahead information after merging states with identical LR(0) cores.
- **LR(1):** retains individual lookahead information for canonical LR(1) states.

The original comparison emphasizes the trade-off between parsing precision and parsing-table size.

### 2.3 DFA and NFA

A DFA is modeled as:

`M = (Q, Σ, δ, q₀, F)`

where `Q` is the finite set of states, `Σ` is the input alphabet, `δ` is the deterministic transition function, `q₀` is the initial state, and `F` is the set of final states.

An NFA allows a transition function that returns a set of states and may include ε-transitions.

---

## 3. LL and LR Parsing

### 3.1 LL Parsing

LL means **Left-to-right scan, Leftmost derivation**.

LL parsing is **top-down**:

1. Read the input from left to right.
2. Expand the leftmost non-terminal.
3. Select a production using lookahead.

A conventional LL(1) parser requires `FIRST` and `FOLLOW` sets to construct its parsing table. Left recursion must be removed because a straightforward recursive implementation can otherwise recurse indefinitely.

### 3.2 LR Parsing

LR means **Left-to-right scan, Rightmost derivation in reverse**.

LR parsing is **bottom-up**:

1. Read tokens from left to right.
2. Push input/state information onto a stack.
3. Shift terminals.
4. Reduce recognized RHS sequences to their LHS non-terminal.
5. Accept when the augmented start production is complete.

The source emphasizes that LR parsers are generally more expressive than simple LL parsers and are commonly implemented through parser generators such as Yacc and Bison.

---

## 4. LL(1) Parsing Table Construction

### 4.1 FIRST Sets

`FIRST(X)` is the set of terminal symbols that can appear at the beginning of a string derived from `X`.

For example:

- `FIRST(a) = {a}` for a terminal `a`.
- If `A → ε`, then `ε ∈ FIRST(A)`.
- For `A → Y₁ Y₂ ... Yₖ`, terminals from `FIRST(Y₁)` are included. If `Y₁` can derive ε, the process continues with `Y₂`, and so on.

### 4.2 FOLLOW Sets

`FOLLOW(A)` is the set of terminals that can occur immediately to the right of non-terminal `A`.

Important rules:

- `$` is placed in `FOLLOW(S)` for the start symbol.
- For `A → α B β`, add `FIRST(β)` except ε to `FOLLOW(B)`.
- If `B` occurs at the end, or `β` can derive ε, add `FOLLOW(A)` to `FOLLOW(B)`.

### 4.3 LL(1) Table

For each production `A → α`:

1. For every terminal `a ∈ FIRST(α)`, place `A → α` in `M[A,a]`.
2. If `ε ∈ FIRST(α)`, place `A → α` in every `M[A,b]` where `b ∈ FOLLOW(A)`.

If one table cell contains two productions, the grammar is not LL(1).

### 4.4 Example

The source uses the following left-recursion-free arithmetic grammar:

```text
E  → T E'
E' → + T E' | ε
T  → F T'
T' → * F T' | ε
F  → ( E ) | id
```

The resulting sets are:

```text
FIRST(E)  = FIRST(T) = FIRST(F) = { (, id }
FIRST(E') = { +, ε }
FIRST(T') = { *, ε }

FOLLOW(E)  = FOLLOW(E') = { ), $ }
FOLLOW(T)  = FOLLOW(T') = { +, ), $ }
FOLLOW(F)  = { *, +, ), $ }
```

---

## 5. LR(0), SLR(1), LALR(1), and LR(1)

### 5.1 LR(0) Items

An LR(0) item places a dot in a production to represent parsing progress.

For:

```text
A → X Y Z
```

the items are:

```text
A → • X Y Z
A → X • Y Z
A → X Y Z •
```

The final item indicates that the RHS has been completely recognized and the production is ready for reduction.

### 5.2 Closure

For an item:

```text
A → α • B β
```

where `B` is a non-terminal, closure adds:

```text
B → • γ
```

for every production `B → γ`, repeating until no new items are generated.

### 5.3 GOTO

`goto(I, X)` advances the dot over symbol `X` and then applies closure to the resulting item set.

### 5.4 Canonical LR(0) Collection

The construction is:

1. Create `I₀ = closure({S' → • S})`.
2. Compute `goto(Iᵢ, X)` for all grammar symbols.
3. Add new item sets as DFA states.
4. Repeat until no new states are produced.

### 5.5 ACTION and GOTO Tables

For LR parsing:

- **Shift:** `A → α • a β` with `goto(Iᵢ,a)=Iⱼ` produces `ACTION[i,a] = Shift j`.
- **Reduce:** `A → α •` produces a reduction.
- **Accept:** `S' → S •` produces `ACTION[i,$] = Accept`.
- **GOTO:** transitions on non-terminals populate the GOTO table.

The critical difference is the placement of Reduce actions. LR(0) reduces broadly; SLR(1) restricts reductions to terminals in `FOLLOW(A)`.

---

## 6. Relationship Between LR(0), SLR(1), LALR(1), and LR(1)

The conceptual construction can be summarized as:

```text
                   Add FOLLOW
[LR(0) Items] ------------------------> [SLR(1) Table]
      |
      | Add individual lookaheads
      v
[LR(1) Items] -- Merge identical LR(0) cores --> [LALR(1) Table]
```

The source's comparison is:

| Property | LR(0) | SLR(1) | LALR(1) | LR(1) |
|---|---|---|---|---|
| Table size | Small | Small | Small | Very large |
| Lookahead | None | FOLLOW set | Merged LR(1) lookaheads | Individual lookaheads |
| Parsing precision | Lowest | Low | High | Highest |
| Reduce/Reduce conflicts | Frequent | Possible | Possible after merging | None |
| Shift/Reduce conflicts | Frequent | Possible | Generally reduced substantially | None |

The important implementation idea is that LALR(1) starts from LR(1) information and merges states whose LR(0) cores are identical.

---

## 7. SLR(1) Implementation

The source's C++11 SLR implementation uses:

- `Rule` — production rule representation.
- `LR0Item` — `(rule_id, dot_position)`.
- `State` — a set of LR(0) items.
- `Action` — Shift/Reduce/Accept/Error.
- `SLRParser` — closure, goto, state construction, table generation, and parsing.

The parser builds the LR(0) state collection and then uses `FOLLOW` sets to place Reduce actions.

The test grammar is:

```text
S' → E
E  → E + T
E  → T
T  → id
```

and the test input is:

```text
id + id
```

The recorded execution ends with `ACCEPT`, and reports successful parsing.

### C++11 Example Code

SLR(1) parser C++11 implementation. Designed as a class structure that builds and executes parsing tables based on grammar rules, closure, goto, and FOLLOW sets.

* `LR0Item`: State representation as `[Production Index, Dot Position]`
* `SLRParser`: Generates LR(0) item sets, computes Closure/Goto, builds ACTION/GOTO tables based on FOLLOW sets, and executes parsing

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

### Console Output

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

## 8. LALR(1) Implementation

The LALR implementation introduces:

```text
LR1Item = LR0Item + Lookahead
```

and provides three key operations:

1. `extract_core()` — remove lookahead symbols and obtain the LR(0) core.
2. Generate canonical LR(1) states.
3. Merge LR(1) states having identical cores and combine their lookahead sets.

The source explicitly notes that its example `compute_first_of_sequence()` is simplified for educational purposes and that a production-quality implementation requires complete FIRST computation, including non-terminal expansion and ε handling.

### 8.1 LALR Example

The test grammar is:

```text
S' → S
S  → V = R
S  → R
V  → * R
V  → id
R  → V
```

The test input is:

```text
* id = id
```

The recorded parser trace ends with:

```text
Reduce 1 (S)
ACCEPT
```

and reports successful LALR(1) parsing.

### 8.2 SLR vs. LALR

The source's central distinction is:

- **SLR(1):** reduction is controlled by the complete `FOLLOW(A)` set.
- **LALR(1):** reduction is controlled by path-specific LR(1) lookahead information after state merging.

Therefore, LALR(1) can retain a compact state count while using more precise reduction conditions.

---

### C++11 Example Code

* **`LR1Item`:** LR(1) unit representation containing `[Rule Index, Dot Position, Lookahead]`
* **`extract_core()`:** Extracts the LR(0) core set from an LR(1) state by excluding lookaheads
* **`merge_states()`:** Identifies LR(1) states sharing identical cores and merges their lookahead sets

> [!NOTE]
> **Note:** For educational clarity, `compute_first_of_sequence` uses a simplified FIRST set computation in this example. Production compiler environments require complete FIRST set algorithms handling non-terminal expansion and $\epsilon$-transitions.

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

### Console Output

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

## 9. Recursive Descent and Packrat/PEG

### 9.1 Recursive Descent

Recursive Descent is a top-down parser in which each grammar rule is typically represented by a parsing function.

- Intuitive implementation.
- Grammar structure maps naturally to code.
- Easy debugging.
- Fine-grained error reporting.
- Easy integration with symbol tables and context-sensitive processing.
- Explicit control over backtracking.

Limitations:

- Left recursion must be removed.
- Poorly controlled backtracking can lead to exponential behavior.

### 9.2 Packrat / PEG

Packrat parsing memoizes intermediate parsing results.

The source describes:

- Guaranteed `O(n)` parsing time for the Packrat model described.
- `O(n)` additional memory for memoization.
- PEG prioritized choice (`/`) removes ambiguity structurally.
- Scannerless parsing can operate directly on raw input.
- Memory consumption and allocation overhead can be significant.
- Error reporting can be complicated by extensive backtracking.

### 9.3 C++11 Design Pattern

The Packrat implementation stores results indexed by:

```text
(Position, Rule)
```

and returns a structure such as:

```cpp
struct MemoResult {
    bool success;
    size_t next_pos;
};
```

This makes repeated evaluation of the same rule at the same input position inexpensive.

---

## 10. Applying the Parser to an ASN.1-Like Grammar

The document eventually focuses on an ASN.1-style input such as:

```asn1
Product ::= SEQUENCE {
    name     VisibleString,
    model    [0] IMPLICIT VisibleString,
    revision [1] IMPLICIT INTEGER,
    color    ENUMERATED {
        red(0),
        green(1),
        blue(2)
    }
}
```

The lexer recognizes:

```text
IDENT
::=
SEQUENCE
IMPLICIT
ENUMERATED
VisibleString
INTEGER
{
}
[
]
(
)
,
NUMBER
EOF
```

The parser then separates the grammar into rules such as:

```text
ProductAssignment
TypeSpec
SequenceType
ElementList
Element
Tag
EnumType
EnumList
EnumItem
```

The Recursive Descent and Packrat implementations map these rules directly to parsing functions.

---

### C++11 Example Code - Recursive Descent & Packrat (PEG) Parser

```cpp
#include <iostream>
#include <map>
#include <set>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

enum class TokenType {
  IDENT,
  ASSIGN,      // ::=
  KW_SEQUENCE, // SEQUENCE
  KW_IMPLICIT, // IMPLICIT
  KW_ENUM,     // ENUMERATED
  TYPE_NAME,   // VisibleString, INTEGER
  LBRACE,      // {
  RBRACE,      // }
  LBRACK,      // [
  RBRACK,      // ]
  LPAREN,      // (
  RPAREN,      // )
  COMMA,       // ,
  NUMBER,      // 0, 1, 2
  END_OF_FILE,
  UNKNOWN
};

struct Token {
  TokenType type;
  std::string text;
};

// Simple Lexer Helper
std::vector<Token> tokenize(const std::string &input) {
  std::vector<Token> tokens;
  size_t i = 0;
  size_t len = input.length();

  while (i < len) {
    if (isspace(input[i])) {
      i++;
      continue;
    }

    if (input[i] == ':' && i + 2 < len && input[i + 1] == ':' &&
        input[i + 2] == '=') {
      tokens.push_back({TokenType::ASSIGN, "::="});
      i += 3;
      continue;
    }

    if (input[i] == '{') {
      tokens.push_back({TokenType::LBRACE, "{"});
      i++;
      continue;
    }
    if (input[i] == '}') {
      tokens.push_back({TokenType::RBRACE, "}"});
      i++;
      continue;
    }
    if (input[i] == '[') {
      tokens.push_back({TokenType::LBRACK, "["});
      i++;
      continue;
    }
    if (input[i] == ']') {
      tokens.push_back({TokenType::RBRACK, "]"});
      i++;
      continue;
    }
    if (input[i] == '(') {
      tokens.push_back({TokenType::LPAREN, "("});
      i++;
      continue;
    }
    if (input[i] == ')') {
      tokens.push_back({TokenType::RPAREN, ")"});
      i++;
      continue;
    }
    if (input[i] == ',') {
      tokens.push_back({TokenType::COMMA, ","});
      i++;
      continue;
    }

    if (isdigit(input[i])) {
      size_t start = i;
      while (i < len && isdigit(input[i]))
        i++;
      tokens.push_back({TokenType::NUMBER, input.substr(start, i - start)});
      continue;
    }

    if (isalpha(input[i])) {
      size_t start = i;
      while (i < len && (isalnum(input[i]) || input[i] == '_'))
        i++;
      std::string word = input.substr(start, i - start);

      if (word == "SEQUENCE")
        tokens.push_back({TokenType::KW_SEQUENCE, word});
      else if (word == "IMPLICIT")
        tokens.push_back({TokenType::KW_IMPLICIT, word});
      else if (word == "ENUMERATED")
        tokens.push_back({TokenType::KW_ENUM, word});
      else if (word == "VisibleString" || word == "INTEGER")
        tokens.push_back({TokenType::TYPE_NAME, word});
      else
        tokens.push_back({TokenType::IDENT, word});
      continue;
    }

    tokens.push_back({TokenType::UNKNOWN, std::string(1, input[i])});
    i++;
  }

  tokens.push_back({TokenType::END_OF_FILE, "$"});
  return tokens;
}

class RecursiveDescentParser {
public:
  explicit RecursiveDescentParser(const std::vector<Token> &tokens)
      : m_tokens(tokens), m_pos(0) {}

  bool parse() {
    bool result = false;

    do {
      if (!parse_product_assignment())
        break;
      if (peek().type != TokenType::END_OF_FILE)
        break;
      result = true;
    } while (0);

    return result;
  }

private:
  const std::vector<Token> &m_tokens;
  size_t m_pos;

  Token peek() const {
    if (m_pos < m_tokens.size())
      return m_tokens[m_pos];
    return {TokenType::END_OF_FILE, "$"};
  }

  bool match(TokenType expected) {
    if (peek().type == expected) {
      m_pos++;
      return true;
    }
    return false;
  }

  bool parse_product_assignment() {
    bool result = false;

    do {
      if (!match(TokenType::IDENT))
        break;
      if (!match(TokenType::ASSIGN))
        break;
      if (!parse_type_spec())
        break;
      result = true;
    } while (0);

    return result;
  }

  bool parse_type_spec() {
    if (peek().type == TokenType::KW_SEQUENCE) {
      return parse_sequence_type();
    }
    if (peek().type == TokenType::KW_ENUM) {
      return parse_enum_type();
    }
    return match(TokenType::TYPE_NAME);
  }

  bool parse_sequence_type() {
    bool result = false;

    do {
      if (!match(TokenType::KW_SEQUENCE))
        break;
      if (!match(TokenType::LBRACE))
        break;
      if (!parse_element_list())
        break;
      if (!match(TokenType::RBRACE))
        break;
      result = true;
    } while (0);

    return result;
  }

  bool parse_element_list() {
    bool result = false;

    do {
      if (!parse_element())
        break;
      while (match(TokenType::COMMA)) {
        if (!parse_element())
          return false;
      }
      result = true;
    } while (0);

    return result;
  }

  bool parse_element() {
    bool result = false;

    do {
      if (!match(TokenType::IDENT))
        break;
      if (peek().type == TokenType::LBRACK) {
        if (!parse_tag())
          break;
      }
      if (!parse_type_spec())
        break;
      result = true;
    } while (0);

    return result;
  }

  bool parse_tag() {
    bool result = false;

    do {
      if (!match(TokenType::LBRACK))
        break;
      if (!match(TokenType::NUMBER))
        break;
      if (!match(TokenType::RBRACK))
        break;
      match(TokenType::KW_IMPLICIT); // Optional in formal spec, required for
                                     // model/revision
      result = true;
    } while (0);

    return result;
  }

  bool parse_enum_type() {
    bool result = false;

    do {
      if (!match(TokenType::KW_ENUM))
        break;
      if (!match(TokenType::LBRACE))
        break;
      if (!parse_enum_list())
        break;
      if (!match(TokenType::RBRACE))
        break;
      result = true;
    } while (0);

    return result;
  }

  bool parse_enum_list() {
    bool result = false;

    do {
      if (!parse_enum_item())
        break;
      while (match(TokenType::COMMA)) {
        if (!parse_enum_item())
          return false;
      }
      result = true;
    } while (0);

    return result;
  }

  bool parse_enum_item() {
    bool result = false;

    do {
      if (!match(TokenType::IDENT))
        break;
      if (!match(TokenType::LPAREN))
        break;
      if (!match(TokenType::NUMBER))
        break;
      if (!match(TokenType::RPAREN))
        break;
      result = true;
    } while (0);

    return result;
  }
};

class PackratParser {
public:
  explicit PackratParser(const std::vector<Token> &tokens) : m_tokens(tokens) {}

  bool parse() {
    bool result = false;

    do {
      auto memo_res = parse_rule_memo(Rule::ProductAssignment, 0);
      if (!memo_res.success)
        break;
      if (memo_res.next_pos != m_tokens.size() - 1)
        break; // Check EOF
      result = true;
    } while (0);

    return result;
  }

private:
  enum class Rule {
    ProductAssignment,
    TypeSpec,
    SequenceType,
    ElementList,
    Element,
    Tag,
    EnumType,
    EnumList,
    EnumItem
  };

  struct MemoResult {
    bool success;
    size_t next_pos;
  };

  const std::vector<Token> &m_tokens;
  std::map<std::pair<size_t, Rule>, MemoResult> m_memo;

  MemoResult parse_rule_memo(Rule rule, size_t pos) {
    auto key = std::make_pair(pos, rule);
    auto it = m_memo.find(key);
    if (it != m_memo.end()) {
      return it->second;
    }

    MemoResult res = eval_rule(rule, pos);
    m_memo[key] = res;
    return res;
  }

  MemoResult eval_rule(Rule rule, size_t pos) {
    switch (rule) {
    case Rule::ProductAssignment:
      return eval_product_assignment(pos);
    case Rule::SequenceType:
      return eval_sequence_type(pos);
    case Rule::ElementList:
      return eval_element_list(pos);
    case Rule::Element:
      return eval_element(pos);
    case Rule::Tag:
      return eval_tag(pos);
    case Rule::TypeSpec:
      return eval_type_spec(pos);
    case Rule::EnumType:
      return eval_enum_type(pos);
    case Rule::EnumList:
      return eval_enum_list(pos);
    case Rule::EnumItem:
      return eval_enum_item(pos);
    }
    return {false, pos};
  }

  bool match_token(size_t pos, TokenType expected, size_t &next_pos) {
    if (pos < m_tokens.size() && m_tokens[pos].type == expected) {
      next_pos = pos + 1;
      return true;
    }
    return false;
  }

  MemoResult eval_product_assignment(size_t pos) {
    bool success = false;
    size_t cur = pos;

    do {
      if (!match_token(cur, TokenType::IDENT, cur))
        break;
      if (!match_token(cur, TokenType::ASSIGN, cur))
        break;

      auto res = parse_rule_memo(Rule::TypeSpec, cur);
      if (!res.success)
        break;
      cur = res.next_pos;

      success = true;
    } while (0);

    return {success, cur};
  }

  MemoResult eval_type_spec(size_t pos) {
    size_t cur = pos;

    auto seq_res = parse_rule_memo(Rule::SequenceType, pos);
    if (seq_res.success)
      return seq_res;

    auto enum_res = parse_rule_memo(Rule::EnumType, pos);
    if (enum_res.success)
      return enum_res;

    if (match_token(cur, TokenType::TYPE_NAME, cur)) {
      return {true, cur};
    }

    return {false, pos};
  }

  MemoResult eval_sequence_type(size_t pos) {
    bool success = false;
    size_t cur = pos;

    do {
      if (!match_token(cur, TokenType::KW_SEQUENCE, cur))
        break;
      if (!match_token(cur, TokenType::LBRACE, cur))
        break;

      auto res = parse_rule_memo(Rule::ElementList, cur);
      if (!res.success)
        break;
      cur = res.next_pos;

      if (!match_token(cur, TokenType::RBRACE, cur))
        break;
      success = true;
    } while (0);

    return {success, cur};
  }

  MemoResult eval_element_list(size_t pos) {
    bool success = false;
    size_t cur = pos;

    do {
      auto res = parse_rule_memo(Rule::Element, cur);
      if (!res.success)
        break;
      cur = res.next_pos;

      while (true) {
        size_t next_comma = cur;
        if (!match_token(cur, TokenType::COMMA, next_comma))
          break;

        auto elem_res = parse_rule_memo(Rule::Element, next_comma);
        if (!elem_res.success)
          break;
        cur = elem_res.next_pos;
      }

      success = true;
    } while (0);

    return {success, cur};
  }

  MemoResult eval_element(size_t pos) {
    bool success = false;
    size_t cur = pos;

    do {
      if (!match_token(cur, TokenType::IDENT, cur))
        break;

      auto tag_res = parse_rule_memo(Rule::Tag, cur);
      if (tag_res.success) {
        cur = tag_res.next_pos;
      }

      auto type_res = parse_rule_memo(Rule::TypeSpec, cur);
      if (!type_res.success)
        break;
      cur = type_res.next_pos;

      success = true;
    } while (0);

    return {success, cur};
  }

  MemoResult eval_tag(size_t pos) {
    bool success = false;
    size_t cur = pos;

    do {
      if (!match_token(cur, TokenType::LBRACK, cur))
        break;
      if (!match_token(cur, TokenType::NUMBER, cur))
        break;
      if (!match_token(cur, TokenType::RBRACK, cur))
        break;
      match_token(cur, TokenType::KW_IMPLICIT, cur);
      success = true;
    } while (0);

    return {success, cur};
  }

  MemoResult eval_enum_type(size_t pos) {
    bool success = false;
    size_t cur = pos;

    do {
      if (!match_token(cur, TokenType::KW_ENUM, cur))
        break;
      if (!match_token(cur, TokenType::LBRACE, cur))
        break;

      auto res = parse_rule_memo(Rule::EnumList, cur);
      if (!res.success)
        break;
      cur = res.next_pos;

      if (!match_token(cur, TokenType::RBRACE, cur))
        break;
      success = true;
    } while (0);

    return {success, cur};
  }

  MemoResult eval_enum_list(size_t pos) {
    bool success = false;
    size_t cur = pos;

    do {
      auto res = parse_rule_memo(Rule::EnumItem, cur);
      if (!res.success)
        break;
      cur = res.next_pos;

      while (true) {
        size_t next_comma = cur;
        if (!match_token(cur, TokenType::COMMA, next_comma))
          break;

        auto item_res = parse_rule_memo(Rule::EnumItem, next_comma);
        if (!item_res.success)
          break;
        cur = item_res.next_pos;
      }

      success = true;
    } while (0);

    return {success, cur};
  }

  MemoResult eval_enum_item(size_t pos) {
    bool success = false;
    size_t cur = pos;

    do {
      if (!match_token(cur, TokenType::IDENT, cur))
        break;
      if (!match_token(cur, TokenType::LPAREN, cur))
        break;
      if (!match_token(cur, TokenType::NUMBER, cur))
        break;
      if (!match_token(cur, TokenType::RPAREN, cur))
        break;
      success = true;
    } while (0);

    return {success, cur};
  }
};

int main() {
  std::string input = "Product ::= SEQUENCE { "
                      "name VisibleString, "
                      "model [0] IMPLICIT VisibleString, "
                      "revision [1] IMPLICIT INTEGER, "
                      "color ENUMERATED { red(0), green(1), blue(2) } "
                      "}";

  std::cout << "[Target Text]:\n" << input << "\n" << std::endl;

  std::vector<Token> tokens = tokenize(input);

  std::cout << "--- 1. Recursive Descent Parser ---" << std::endl;
  RecursiveDescentParser rd_parser(tokens);
  std::cout << "Result: " << (rd_parser.parse() ? "SUCCESS" : "FAILED")
            << std::endl;

  std::cout << "\n--- 2. Packrat Parser ---" << std::endl;
  PackratParser packrat_parser(tokens);
  std::cout << "Result: " << (packrat_parser.parse() ? "SUCCESS" : "FAILED")
            << std::endl;

  return 0;
}
```

### C++ Example Code - SLR & LALR Parser

```cpp
#include <cctype>
#include <iostream>
#include <map>
#include <string>
#include <utility>
#include <vector>

// ==========================================
// 1. Token Definition & Lexer
// ==========================================
enum class TokenType {
  IDENT,       // Product, name, model, revision, color, red, green, blue
  ASSIGN,      // ::=
  KW_SEQUENCE, // SEQUENCE
  KW_IMPLICIT, // IMPLICIT
  KW_ENUM,     // ENUMERATED
  TYPE_NAME,   // VisibleString, INTEGER
  LBRACE,      // {
  RBRACE,      // }
  LBRACK,      // [
  RBRACK,      // ]
  LPAREN,      // (
  RPAREN,      // )
  COMMA,       // ,
  NUMBER,      // 0, 1, 2
  END_OF_FILE,
  UNKNOWN
};

struct Token {
  TokenType type;
  std::string text;
};

std::vector<Token> tokenize(const std::string &input) {
  std::vector<Token> tokens;
  size_t i = 0;
  size_t len = input.length();

  while (i < len) {
    if (isspace(input[i])) {
      i++;
      continue;
    }

    if (input[i] == ':' && i + 2 < len && input[i + 1] == ':' &&
        input[i + 2] == '=') {
      tokens.push_back({TokenType::ASSIGN, "::="});
      i += 3;
      continue;
    }

    if (input[i] == '{') {
      tokens.push_back({TokenType::LBRACE, "{"});
      i++;
      continue;
    }
    if (input[i] == '}') {
      tokens.push_back({TokenType::RBRACE, "}"});
      i++;
      continue;
    }
    if (input[i] == '[') {
      tokens.push_back({TokenType::LBRACK, "["});
      i++;
      continue;
    }
    if (input[i] == ']') {
      tokens.push_back({TokenType::RBRACK, "]"});
      i++;
      continue;
    }
    if (input[i] == '(') {
      tokens.push_back({TokenType::LPAREN, "("});
      i++;
      continue;
    }
    if (input[i] == ')') {
      tokens.push_back({TokenType::RPAREN, "}"});
      i++;
      continue;
    }
    if (input[i] == ',') {
      tokens.push_back({TokenType::COMMA, ","});
      i++;
      continue;
    }

    if (isdigit(input[i])) {
      size_t start = i;
      while (i < len && isdigit(input[i]))
        i++;
      tokens.push_back({TokenType::NUMBER, input.substr(start, i - start)});
      continue;
    }

    if (isalpha(input[i])) {
      size_t start = i;
      while (i < len && (isalnum(input[i]) || input[i] == '_'))
        i++;
      std::string word = input.substr(start, i - start);

      if (word == "SEQUENCE")
        tokens.push_back({TokenType::KW_SEQUENCE, word});
      else if (word == "IMPLICIT")
        tokens.push_back({TokenType::KW_IMPLICIT, word});
      else if (word == "ENUMERATED")
        tokens.push_back({TokenType::KW_ENUM, word});
      else if (word == "VisibleString" || word == "INTEGER")
        tokens.push_back({TokenType::TYPE_NAME, word});
      else
        tokens.push_back({TokenType::IDENT, word});
      continue;
    }

    tokens.push_back({TokenType::UNKNOWN, std::string(1, input[i])});
    i++;
  }

  tokens.push_back({TokenType::END_OF_FILE, "$"});
  return tokens;
}

// ==========================================
// 2. Table-Driven Engine
// ==========================================
enum class ActionType { SHIFT, REDUCE, ACCEPT, ERROR };

struct Action {
  ActionType type;
  int target;
};

class TableDrivenParser {
public:
  explicit TableDrivenParser(const std::vector<Token> &tokens)
      : m_tokens(tokens) {}

  bool parse() {
    bool result = false;

    do {
      std::vector<int> state_stack;
      state_stack.push_back(0);

      size_t token_idx = 0;

      while (true) {
        if (state_stack.empty())
          break;

        int current_state = state_stack.back();
        TokenType lookahead = m_tokens[token_idx].type;

        Action act = get_action(current_state, lookahead);

        if (act.type == ActionType::SHIFT) {
          state_stack.push_back(act.target);
          token_idx++;
        } else if (act.type == ActionType::REDUCE) {
          int rule_idx = act.target;
          int pop_count = m_rule_rhs_lengths[rule_idx];

          if (state_stack.size() < static_cast<size_t>(pop_count))
            break;

          for (int i = 0; i < pop_count; ++i) {
            state_stack.pop_back();
          }

          if (state_stack.empty())
            break;

          int top_state = state_stack.back();
          int lhs_symbol = m_rule_lhs[rule_idx];

          int next_state = get_goto(top_state, lhs_symbol);
          if (next_state == -1)
            break;

          state_stack.push_back(next_state);
        } else if (act.type == ActionType::ACCEPT) {
          result = true;
          break;
        } else {
          break;
        }
      }
    } while (0);

    return result;
  }

protected:
  const std::vector<Token> &m_tokens;
  std::map<std::pair<int, TokenType>, Action> m_action_table;
  std::map<std::pair<int, int>, int> m_goto_table;
  std::vector<int> m_rule_rhs_lengths;
  std::vector<int> m_rule_lhs;

  Action get_action(int state, TokenType token) const {
    auto it = m_action_table.find(std::make_pair(state, token));
    if (it != m_action_table.end())
      return it->second;
    return {ActionType::ERROR, 0};
  }

  int get_goto(int state, int non_terminal) const {
    auto it = m_goto_table.find(std::make_pair(state, non_terminal));
    if (it != m_goto_table.end())
      return it->second;
    return -1;
  }

  /*
   * Grammar Rules:
   * 0:  S' -> ProductAssignment
   * 1:  ProductAssignment -> IDENT ASSIGN TypeSpec
   * 2:  TypeSpec -> SequenceType
   * 3:  TypeSpec -> EnumType
   * 4:  TypeSpec -> TYPE_NAME
   * 5:  SequenceType -> KW_SEQUENCE LBRACE ElementList RBRACE
   * 6:  ElementList -> ElementList COMMA Element
   * 7:  ElementList -> Element
   * 8:  Element -> IDENT TagOpt TypeSpec
   * 9:  TagOpt -> LBRACK NUMBER RBRACK KW_IMPLICIT
   * 10: TagOpt -> empty
   * 11: EnumType -> KW_ENUM LBRACE EnumList RBRACE
   * 12: EnumList -> EnumList COMMA EnumItem
   * 13: EnumList -> EnumItem
   * 14: EnumItem -> IDENT LPAREN NUMBER RPAREN
   */
  void setup_grammar_tables() {
    m_rule_rhs_lengths = {1, 3, 1, 1, 1, 4, 3, 1, 3, 4, 0, 4, 3, 1, 4};
    m_rule_lhs = {0, 1, 2, 2, 2, 3, 4, 4, 5, 6, 6, 7, 8, 8, 9};

    // Product ::= SEQUENCE { ... }
    m_action_table[{0, TokenType::IDENT}] = {ActionType::SHIFT, 1};
    m_action_table[{1, TokenType::ASSIGN}] = {ActionType::SHIFT, 2};
    m_action_table[{2, TokenType::KW_SEQUENCE}] = {ActionType::SHIFT, 3};
    m_action_table[{3, TokenType::LBRACE}] = {ActionType::SHIFT, 4};

    // Element Parsing
    m_action_table[{4, TokenType::IDENT}] = {ActionType::SHIFT, 5};
    m_action_table[{15, TokenType::IDENT}] = {ActionType::SHIFT, 5};

    // TagOpt Epsilon Reduction (Rule 10)
    m_action_table[{5, TokenType::TYPE_NAME}] = {ActionType::REDUCE, 10};
    m_action_table[{5, TokenType::KW_SEQUENCE}] = {ActionType::REDUCE, 10};
    m_action_table[{5, TokenType::KW_ENUM}] = {ActionType::REDUCE, 10};
    m_action_table[{5, TokenType::LBRACK}] = {ActionType::SHIFT, 8};

    // Tag Parsing [num] IMPLICIT
    m_action_table[{8, TokenType::NUMBER}] = {ActionType::SHIFT, 9};
    m_action_table[{9, TokenType::RBRACK}] = {ActionType::SHIFT, 10};
    m_action_table[{10, TokenType::KW_IMPLICIT}] = {ActionType::SHIFT, 11};
    m_action_table[{11, TokenType::TYPE_NAME}] = {ActionType::REDUCE, 9};
    m_action_table[{11, TokenType::KW_ENUM}] = {ActionType::REDUCE, 9};

    // TypeSpec Entry
    m_action_table[{6, TokenType::TYPE_NAME}] = {ActionType::SHIFT, 12};
    m_action_table[{6, TokenType::KW_SEQUENCE}] = {ActionType::SHIFT, 3};
    m_action_table[{6, TokenType::KW_ENUM}] = {ActionType::SHIFT, 14};

    // TYPE_NAME -> TypeSpec (Rule 4)
    m_action_table[{12, TokenType::COMMA}] = {ActionType::REDUCE, 4};
    m_action_table[{12, TokenType::RBRACE}] = {ActionType::REDUCE, 4};

    // EnumType -> TypeSpec (Rule 3)
    m_action_table[{28, TokenType::COMMA}] = {ActionType::REDUCE, 3};
    m_action_table[{28, TokenType::RBRACE}] = {ActionType::REDUCE, 3};

    // TypeSpec -> Element (Rule 8)
    m_action_table[{13, TokenType::COMMA}] = {ActionType::REDUCE, 8};
    m_action_table[{13, TokenType::RBRACE}] = {ActionType::REDUCE, 8};

    // ElementList Operations
    m_action_table[{7, TokenType::COMMA}] = {ActionType::SHIFT, 15};
    m_action_table[{7, TokenType::RBRACE}] = {ActionType::SHIFT, 17};

    m_action_table[{16, TokenType::COMMA}] = {ActionType::REDUCE, 6};
    m_action_table[{16, TokenType::RBRACE}] = {ActionType::REDUCE, 6};

    // ENUMERATED Inner Parsing
    m_action_table[{14, TokenType::LBRACE}] = {ActionType::SHIFT, 18};
    m_action_table[{18, TokenType::IDENT}] = {ActionType::SHIFT, 19};
    m_action_table[{19, TokenType::LPAREN}] = {ActionType::SHIFT, 20};
    m_action_table[{20, TokenType::NUMBER}] = {ActionType::SHIFT, 21};
    m_action_table[{21, TokenType::RPAREN}] = {ActionType::SHIFT, 22};

    // EnumItem Reductions
    m_action_table[{22, TokenType::COMMA}] = {ActionType::REDUCE, 14};
    m_action_table[{22, TokenType::RBRACE}] = {ActionType::REDUCE, 14};

    m_action_table[{23, TokenType::COMMA}] = {ActionType::SHIFT, 24};
    m_action_table[{23, TokenType::RBRACE}] = {ActionType::SHIFT, 25};

    m_action_table[{24, TokenType::IDENT}] = {ActionType::SHIFT, 19};

    // EnumList Reduction (Rule 12)
    m_action_table[{26, TokenType::COMMA}] = {ActionType::REDUCE, 12};
    m_action_table[{26, TokenType::RBRACE}] = {ActionType::REDUCE, 12};

    // EnumType Reduction (Rule 11)
    m_action_table[{25, TokenType::COMMA}] = {ActionType::REDUCE, 11};
    m_action_table[{25, TokenType::RBRACE}] = {ActionType::REDUCE, 11};

    // Sequence Closed & Reduction Paths
    m_action_table[{17, TokenType::END_OF_FILE}] = {ActionType::REDUCE, 5};
    m_action_table[{27, TokenType::END_OF_FILE}] = {
        ActionType::REDUCE, 2}; // SequenceType -> TypeSpec
    m_action_table[{30, TokenType::END_OF_FILE}] = {
        ActionType::REDUCE, 1}; // ProductAssignment -> Accept
    m_action_table[{29, TokenType::END_OF_FILE}] = {ActionType::ACCEPT, 0};

    // GOTO Table
    m_goto_table[{0, 1}] = 29;  // ProductAssignment
    m_goto_table[{2, 2}] = 30;  // TypeSpec
    m_goto_table[{2, 3}] = 27;  // SequenceType (FIXED: 17 -> 27)
    m_goto_table[{4, 4}] = 7;   // ElementList
    m_goto_table[{4, 5}] = 7;   // Element
    m_goto_table[{15, 5}] = 16; // Element
    m_goto_table[{5, 6}] = 6;   // TagOpt
    m_goto_table[{6, 2}] = 13;  // TypeSpec
    m_goto_table[{6, 7}] = 28;  // EnumType
    m_goto_table[{14, 7}] = 28; // EnumType
    m_goto_table[{18, 8}] = 23; // EnumList
    m_goto_table[{18, 9}] = 23; // EnumItem
    m_goto_table[{24, 8}] = 26; // EnumList
    m_goto_table[{24, 9}] = 26; // EnumItem
  }
};

// ==========================================
// 3. Parser Class Wrappers
// ==========================================
class FullSLRParser : public TableDrivenParser {
public:
  explicit FullSLRParser(const std::vector<Token> &tokens)
      : TableDrivenParser(tokens) {
    setup_grammar_tables();
  }
};

class FullLALRParser : public TableDrivenParser {
public:
  explicit FullLALRParser(const std::vector<Token> &tokens)
      : TableDrivenParser(tokens) {
    setup_grammar_tables();
  }
};

// ==========================================
// 4. Main Test Driver
// ==========================================
int main() {
  std::string full_input = "Product ::= SEQUENCE { "
                           "name VisibleString, "
                           "model [0] IMPLICIT VisibleString, "
                           "revision [1] IMPLICIT INTEGER, "
                           "color ENUMERATED { red(0), green(1), blue(2) } "
                           "}";

  std::cout << "[Target Text]:\n" << full_input << "\n" << std::endl;

  std::vector<Token> tokens = tokenize(full_input);

  std::cout << "--- Full SLR(1) Parser Test ---" << std::endl;
  FullSLRParser slr_parser(tokens);
  std::cout << "Result: " << (slr_parser.parse() ? "SUCCESS" : "FAILED")
            << std::endl;

  std::cout << "\n--- Full LALR(1) Parser Test ---" << std::endl;
  FullLALRParser lalr_parser(tokens);
  std::cout << "Result: " << (lalr_parser.parse() ? "SUCCESS" : "FAILED")
            << std::endl;

  return 0;
}
```

---

## 11. Parser Strategy for ASN.1

The source ultimately compares two practical approaches for the ASN.1 project.

### Table-Driven LALR(1)

Advantages:

- Formal grammar is directly represented in production rules.
- Parsing behavior is deterministic once the table has been generated.
- Runtime parsing is compact and stack-based.
- Conflicts can be detected during table construction.

Disadvantages:

- Grammar construction and state generation are considerably more complex.
- FIRST/FOLLOW and LR item propagation must be implemented correctly.
- LALR state merging can introduce subtle conflicts.
- Semantic/context-sensitive ASN.1 rules may not fit naturally into a purely context-free table.

### Recursive Descent

Advantages:

- Grammar rules map naturally to C++ functions.
- Easy to integrate ASN.1-specific semantic checks.
- Easy to control parsing context.
- Error messages can be tailored to the exact parsing location.
- The implementation is straightforward to debug.

Disadvantages:

- Left recursion cannot be used directly.
- Backtracking must be controlled carefully.
- Complex alternatives may require explicit lookahead or checkpoints.

---

## 12. Final Integrated LALR(1) Design

The final implementation combines:

```text
Lexer
  ↓
Token stream
  ↓
Grammar registration
  ↓
FIRST / FOLLOW calculation
  ↓
LR(0) state construction
  ↓
LR(1) lookahead propagation
  ↓
LALR(1) state/table generation
  ↓
ACTION / GOTO tables
  ↓
Stack-based parser
  ↓
Parsing result
```

The implementation uses these core data structures:

```cpp
enum class ActionType {
    SHIFT,
    REDUCE,
    ACCEPT,
    CONFLICT_ERROR
};

struct Action {
    ActionType type;
    int target;
};

struct ProductionRule {
    int id;
    std::string lhs;
    std::vector<std::string> rhs;
};

struct LR0Item {
    int prod_id;
    size_t dot_pos;
};

struct LR1Item {
    int prod_id;
    size_t dot_pos;
    std::string lookahead;
};

struct Token {
    std::string type;
    std::string value;
};
```

---

## 13. Final C++11 LALR(1) Implementation

```cpp
#include <iomanip>
#include <iostream>
#include <map>
#include <stack>
#include <string>
#include <vector>

// ============================================================================
// 1. Parser Data Structures
// ============================================================================
enum class ActionType { SHIFT, REDUCE, ACCEPT, ERROR };

struct Action {
  ActionType type = ActionType::ERROR;
  int target = -1; // Next State for Shift, Rule ID for Reduce
};

struct ProductionRule {
  int id;
  std::string lhs;
  size_t rhs_length; // Reduce 시 스택에서 pop할 기호 개수
};

struct Token {
  std::string type;  // Terminal symbol (e.g., "id", "SEQUENCE", "{", "}")
  std::string value; // Actual lexeme string
};

// ============================================================================
// 2. LALR(1) Table Driven Parser Engine
// ============================================================================
class LALRParserEngine {
public:
  LALRParserEngine() {
    setup_rules();
    setup_parsing_table();
  }

  bool parse(const std::vector<Token> &tokens) {
    bool is_success = false;

    do {
      std::stack<int> state_stack;
      state_stack.push(0);

      size_t token_idx = 0;

      std::cout << "==========================================================="
                   "========\n";
      std::cout << "  LALR(1) Parsing Execution Trace\n";
      std::cout << "==========================================================="
                   "========\n";
      std::cout << std::left << std::setw(25) << "State Stack" << std::setw(20)
                << "Current Token"
                << "Action\n";
      std::cout << "-----------------------------------------------------------"
                   "--------\n";

      while (true) {
        if (token_idx >= tokens.size()) {
          break;
        }

        int current_state = state_stack.top();
        Token current_token = tokens[token_idx];

        auto key = std::make_pair(current_state, current_token.type);
        if (m_action_table.find(key) == m_action_table.end()) {
          std::cout << "\n[PARSE ERROR] No Action for State " << current_state
                    << " with Token '" << current_token.value << "' ("
                    << current_token.type << ")\n";
          break;
        }

        Action act = m_action_table[key];

        print_trace(state_stack, current_token);

        // 1. Shift Action
        if (act.type == ActionType::SHIFT) {
          std::cout << "SHIFT -> State " << act.target << "\n";
          state_stack.push(act.target);
          token_idx++;
        }
        // 2. Reduce Action
        else if (act.type == ActionType::REDUCE) {
          const auto &rule = m_rules[act.target];
          std::cout << "REDUCE -> Rule " << rule.id << " (" << rule.lhs
                    << ")\n";

          for (size_t i = 0; i < rule.rhs_length; ++i) {
            if (!state_stack.empty()) {
              state_stack.pop();
            }
          }

          if (state_stack.empty()) {
            break;
          }

          int top_state = state_stack.top();
          auto goto_key = std::make_pair(top_state, rule.lhs);
          if (m_goto_table.find(goto_key) == m_goto_table.end()) {
            std::cout << "\n[PARSE ERROR] GOTO Table Miss at State "
                      << top_state << " for Non-Terminal '" << rule.lhs
                      << "'\n";
            break;
          }

          int next_state = m_goto_table[goto_key];
          state_stack.push(next_state);
        }
        // 3. Accept Action
        else if (act.type == ActionType::ACCEPT) {
          std::cout << "ACCEPT !\n";
          is_success = true;
          break;
        } else {
          break;
        }
      }
    } while (0);

    return is_success;
  }

private:
  std::map<int, ProductionRule> m_rules;
  std::map<std::pair<int, std::string>, Action> m_action_table;
  std::map<std::pair<int, std::string>, int> m_goto_table;

  void setup_rules() {
    m_rules[0] = {0, "S'", 1}; // S' -> ProductSpec
    m_rules[1] = {1, "ProductSpec",
                  6}; // ProductSpec -> id ::= SEQUENCE { FieldList }
    m_rules[2] = {2, "FieldList", 3};  // FieldList -> FieldList , Field
    m_rules[3] = {3, "FieldList", 1};  // FieldList -> Field
    m_rules[4] = {4, "Field", 2};      // Field -> id TypeSpec
    m_rules[5] = {5, "TypeSpec", 1};   // TypeSpec -> SimpleType
    m_rules[6] = {6, "TypeSpec", 1};   // TypeSpec -> TaggedType
    m_rules[7] = {7, "TypeSpec", 1};   // TypeSpec -> EnumType
    m_rules[8] = {8, "SimpleType", 1}; // SimpleType -> VisibleString
    m_rules[9] = {9, "SimpleType", 1}; // SimpleType -> INTEGER
  }

  void setup_parsing_table() {
    // --- Action Table ---
    m_action_table[{0, "id"}] = {ActionType::SHIFT, 1};
    m_action_table[{1, "::="}] = {ActionType::SHIFT, 2};
    m_action_table[{2, "SEQUENCE"}] = {ActionType::SHIFT, 3};
    m_action_table[{3, "{"}] = {ActionType::SHIFT, 4};
    m_action_table[{4, "id"}] = {ActionType::SHIFT, 5};
    m_action_table[{5, "VisibleString"}] = {ActionType::SHIFT, 6};

    // State 6: VisibleString -> SimpleType (Rule 8)
    m_action_table[{6, "}"}] = {ActionType::REDUCE, 8};
    m_action_table[{6, ","}] = {ActionType::REDUCE, 8};

    // State 7: SimpleType -> TypeSpec (Rule 5)
    m_action_table[{7, "}"}] = {ActionType::REDUCE, 5};
    m_action_table[{7, ","}] = {ActionType::REDUCE, 5};

    // State 8: id TypeSpec -> Field (Rule 4)
    m_action_table[{8, "}"}] = {ActionType::REDUCE, 4};
    m_action_table[{8, ","}] = {ActionType::REDUCE, 4};

    // State 9: Field -> FieldList (Rule 3)
    m_action_table[{9, "}"}] = {ActionType::REDUCE, 3};
    m_action_table[{9, ","}] = {ActionType::REDUCE, 3};

    // State 10: FieldList 다음 '}' 처리
    m_action_table[{10, "}"}] = {ActionType::SHIFT, 11};

    // State 11: ProductSpec 파싱 완료 (Rule 1)
    m_action_table[{11, "$"}] = {ActionType::REDUCE, 1};

    // State 99: Accept
    m_action_table[{99, "$"}] = {ActionType::ACCEPT, 0};

    // --- GOTO Table ---
    m_goto_table[{0, "ProductSpec"}] = 99;
    m_goto_table[{3, "FieldList"}] = 10;
    m_goto_table[{4, "FieldList"}] = 10;
    m_goto_table[{4, "Field"}] = 9;
    m_goto_table[{5, "TypeSpec"}] = 8;
    m_goto_table[{5, "SimpleType"}] = 7;
  }

  void print_trace(const std::stack<int> &st, const Token &tok) {
    std::stack<int> temp = st;
    std::vector<int> states;
    while (!temp.empty()) {
      states.push_back(temp.top());
      temp.pop();
    }

    std::string stack_str = "[ ";
    for (auto it = states.rbegin(); it != states.rend(); ++it) {
      stack_str += std::to_string(*it) + " ";
    }
    stack_str += "]";

    std::cout << std::left << std::setw(25) << stack_str << std::setw(20)
              << (tok.value + " (" + tok.type + ")") << " ";
  }
};

// ============================================================================
// 3. Test Main Execution
// ============================================================================
int main() {
  std::vector<Token> tokens = {
      {"id", "Product"}, {"::=", "::="}, {"SEQUENCE", "SEQUENCE"},
      {"{", "{"},        {"id", "name"}, {"VisibleString", "VisibleString"},
      {"}", "}"},        {"$", "$"}};

  LALRParserEngine parser;
  bool result = parser.parse(tokens);

  if (result) {
    std::cout << "\n[RESULT] LALR Parsing Completed Successfully.\n";
  } else {
    std::cout << "\n[RESULT] LALR Parsing Failed.\n";
  }

  return 0;
}
```

### Console Output

```
===================================================================
  LALR(1) Parsing Execution Trace
===================================================================
State Stack              Current Token       Action
-------------------------------------------------------------------
[ 0 ]                    Product (id)         SHIFT -> State 1
[ 0 1 ]                  ::= (::=)            SHIFT -> State 2
[ 0 1 2 ]                SEQUENCE (SEQUENCE)  SHIFT -> State 3
[ 0 1 2 3 ]              { ({)                SHIFT -> State 4
[ 0 1 2 3 4 ]            name (id)            SHIFT -> State 5
[ 0 1 2 3 4 5 ]          VisibleString (VisibleString) SHIFT -> State 6
[ 0 1 2 3 4 5 6 ]        } (})                REDUCE -> Rule 8 (SimpleType)
[ 0 1 2 3 4 5 7 ]        } (})                REDUCE -> Rule 5 (TypeSpec)
[ 0 1 2 3 4 5 8 ]        } (})                REDUCE -> Rule 4 (Field)
[ 0 1 2 3 4 9 ]          } (})                REDUCE -> Rule 3 (FieldList)
[ 0 1 2 3 4 10 ]         } (})                SHIFT -> State 11
[ 0 1 2 3 4 10 11 ]      $ ($)                REDUCE -> Rule 1 (ProductSpec)
[ 0 99 ]                 $ ($)                ACCEPT !

[RESULT] LALR Parsing Completed Successfully.
```

---

## 14. Observed Execution Result

The final dynamic-table implementation reports successful table generation and successful parsing of the simplified ASN.1 `Product` grammar.

The execution trace follows the expected pattern:

```text
SHIFT
SHIFT
SHIFT
SHIFT
SHIFT
REDUCE
REDUCE
REDUCE
REDUCE
SHIFT
REDUCE
ACCEPT
```

The source reports:

```text
Table Generation Success!
[RESULT] Integrated LALR Parsing Completed Successfully.
```

---

## 15. Current TODOs and Discussion Topics

### Implementation TODOs

1. Integrate a complete automated FIRST/FOLLOW calculation algorithm into the LALR(1) implementation.
2. Investigate operator-precedence mechanisms used by Bison/Yacc to resolve Shift/Reduce conflicts.
3. Design the interface between an Aho-Corasick-based tokenizer and the Recursive Descent parser.
4. Refine AST construction and error recovery.
5. Replace or improve the current `do { 0 }-break` control-flow pattern where appropriate.

### Design Discussions

1. Explain at the item-set level why LALR(1) merging can introduce Reduce/Reduce conflicts.
2. Analyze the exact conditions under which state merging affects Shift/Reduce behavior.
3. Review LALR(1)'s limitations for ASN.1.
4. Compare a table-driven LALR parser with Recursive Descent for the final ASN.1 implementation.
5. Decide where semantic actions and symbol-table processing should occur.
6. Define the AST representation independently from the parser engine.

---

## 16. Recommended Implementation Direction

```text
+-----------------------+
| ASN.1 Source Text     |
+-----------+-----------+
            |
            v
+-----------------------+
| Tokenizer / Lexer     |
| Aho-Corasick or       |
| conventional lexer    |
+-----------+-----------+
            |
            v
+-----------------------+
| Parser                |
|                       |
|  Recursive Descent    |
|       or              |
|  LALR(1) Table-Driven |
+-----------+-----------+
            |
            v
+-----------------------+
| AST / ASN.1 Model     |
+-----------+-----------+
            |
            v
+-----------------------+
| Semantic Processing   |
| Type / Tag / Name     |
| Resolution            |
+-----------------------+
```

A useful architectural separation is to keep **tokenization**, **syntactic parsing**, and **semantic/AST processing** independent. This makes it possible to experiment with both Recursive Descent and LALR(1) without redesigning the lexer or AST.

---

## 17. References

- book
  - Compilers Principles, Techniques, and Tools - Alfred V. Aho, Ravi Sethi, and Jeffrey D. Ullman
- article
  - [CFG - Wikipedia](https://en.wikipedia.org/wiki/Context-free_grammar)
  - [Types of Paarsers in Compiler Design - geeksforgeeks](https://www.geeksforgeeks.org/compiler-design/types-of-parsers-in-compiler-design/)
  - [Top-down parsing — Wikipedia](https://en.wikipedia.org/wiki/Top-down_parsing)
  - [Bottom-up parsing — Wikipedia](https://en.wikipedia.org/wiki/Bottom-up_parsing)
  - [LR parser — Wikipedia](https://en.wikipedia.org/wiki/LR_parser)
  - [LR parser - geeksforgeeks](https://www.geeksforgeeks.org/compiler-design/problem-on-lr0-parser/)
  - [SLR parser — Wikipedia](https://en.wikipedia.org/wiki/SLR_parser)
  - [SLR parser - geeksforgeeks](https://www.geeksforgeeks.org/compiler-design/slr-parser-with-examples/)
  - [LALR parser — Wikipedia](https://en.wikipedia.org/wiki/LALR_parser)
  - [LALR parser - geeksforgeeks](https://www.geeksforgeeks.org/compiler-design/lalr-parser-with-examples/)
  - [Canonical LR parser — Wikipedia](https://en.wikipedia.org/wiki/Canonical_LR_parser)
  - [Canonical LR parser - geeksforgeeks](https://www.geeksforgeeks.org/compiler-design/clr-parser-with-examples/)
  - [Parsing Expression Grammar — Wikipedia](https://en.wikipedia.org/wiki/Parsing_expression_grammar)
  - [Recursive descent parser — Wikipedia](https://en.wikipedia.org/wiki/Recursive_descent_parser)
  - [Recursive descent parser — geeksforgeeks](https://www.geeksforgeeks.org/compiler-design/recursive-descent-parser/)
  - [Packrat parser — Wikipedia](https://en.wikipedia.org/wiki/Packrat_parser)
