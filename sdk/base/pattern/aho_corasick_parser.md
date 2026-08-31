# Aho-Corasick-Based Bottom-Up Token Reduction Parser

## 1. Overview and Design Architecture

For parsing text with complex structures and constraints, such as ASN.1, a **Pattern-based Bottom-Up Token Reducer** is constructed by applying the **Aho-Corasick multi-pattern matching algorithm**, instead of using a traditional LR parser.

```text
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

### Parser Classification and Characteristics

| Parser         | Lookahead                       |                         Number of States | Grammar Processing Precision | Core Mechanism                                   |
| -------------- | ------------------------------- | ---------------------------------------: | ---------------------------- | ------------------------------------------------ |
| **LR(0)**      | Not used                        |                                    Small | Lowest                       | Grammar-rule-based DFA Shift/Reduce              |
| **LALR**       | Merged lookahead symbols        |                                    Small | High                         | State transitions based on Lookahead Sets        |
| **LR(1)**      | Individual lookahead symbols    |                               Very large | Highest                      | Precise context-aware parsing                    |
| **AC-Reducer** | Not used (token-array matching) | Proportional to the number of trie nodes | Specialized / Pattern-based  | **Aho-Corasick token-array pattern replacement** |

---

## 2. Core Engine Implementation Specification

### ① Group and Virtual Token Structure (`set_group`, `insert_as`)

* **`set_group`**: Groups multiple tokens into a single abstraction group so that they can be processed as a common type.
* **`insert_as`**: Reduces/replaces a lower-level token sequence with a higher-level Virtual Token.

```cpp
// Example: Grouping basic types and reducing a single pattern
ac.set_group(token_builtintype,
             {token_bool, token_int, token_visiblestring, token_usertype});

ac.insert_as(token_namedtype,
             {token_identifier, token_builtintype});
```

### ② Repetition Sequence Reduction (`repeat_as`)

Normalizes a sequence of consecutive identical elements, either with or without a delimiter, into a single token.

```cpp
// Example: Repeated elements connected by a comma delimiter
ac.repeat_as(token_element,
             token_comma,
             {token_namedtype, token_taggedtype});
```

### ③ Coordinate Transformation for Sub-pattern Matching (`token_span`)

Supports coordinate transformation in the form of `range_t(begin, end)` to accurately track the original token-index range of nested reduction regions.

---

## 3. C++ Ruleset Definition Pattern (ASN.1 Parser Example)

Ruleset definition code snippets written for a C++11 environment.

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
ac->set_group(token_builtintype,
              {token_bool, token_int, token_visiblestring, token_usertype});

ac->set_group(token_class,
              {token_application, token_private, token_universal});

ac->set_group(token_taggedmode,
              {token_implicit, token_explicit});

// 2. Leaf & Tag Rules
ac->insert_as(token_tag,
              {token_lbracket, token_number, token_rbracket});

ac->insert_as(token_defaultval,
              {token_default, token_lbrace, token_rbrace});

// 3. Sub-structure & List Rules
ac->insert_as(token_namednumberelement,
              {token_identifier, token_lparen, token_number, token_rparen});

ac->repeat_as(token_namednumberlist,
              token_comma,
              {token_namednumberelement});

// 4. Construct & Sentence Rules
ac->insert_as(token_phrase,
              {token_enum, token_lbrace, token_namednumberlist, token_rbrace});

ac->insert_as(token_sentence,
              {token_lvalue, token_assign, token_phrase});
```

---

## 5. Layering Principle for Writing AC Reduction Parser Rules

Because the Aho-Corasick engine performs a replacement as soon as a match is detected, the processing stages must be separated so that **Specific rules are executed before Generic rules**.

```text
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

### Writing Guidelines Checklist

1. **Do not group special keywords too early**: If syntax-structuring keywords such as `token_int` or `token_enum` are prematurely included in a broad group such as `builtintype`, a Generic rule may consume them before the intended rule gets a chance to execute.
2. **Ensure element-token completeness**: The internal structure of an element token used by `repeat_as` must be completely reduced during the earliest reduction pass.
3. **Use matching statistics for analysis**: If the matching count of a Generic pattern is abnormally high before a Specific pattern is executed, this may indicate a rule conflict.

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

---

## 7. Gemini Q&A: Complete List of Ruleset Design Considerations

The following summarizes the key considerations that must be observed when defining rulesets (Grammar Rules) for an **Aho-Corasick-based parser/transpiler** that performs Bottom-Up reduction.

The Aho-Corasick algorithm tends to replace a matched region as soon as a pattern is detected, favoring the earliest and/or longest matching region. Therefore, compared with an LALR parser based on a context-free grammar (CFG), it requires much more careful rule design to prevent **token contamination and conflicts**.

---

### 1. Considerations for Groups and Wildcards

* **Avoid prematurely including special keywords in broad groups**

  * If a single token such as `token_int`, which is a key element of a specific syntax structure such as `INTEGER { ... }`, is included in a broad group such as `token_builtintype`, a Generic rule such as `token_identifier + token_builtintype` may fire first and consume the syntax before the higher-level rule can operate.
  * **Principle**: Delay grouping tokens that serve as syntax keywords, or make standalone keyword patterns the highest-priority reduction targets.

* **Avoid cyclic or overlapping group definitions**

  * If group `A` contains group `B`, while a pattern exists that replaces an element of group `B` with group `A`, an infinite reduction loop or overlapping conflict may occur.

---

### 2. Reduction Priority and Conflict Control

* **Isolate Specific and Generic rules**

  * When patterns with similar lengths or structures compete, reducing a Generic rule first may make it impossible to analyze the detailed syntax structure.
  * **Example**: `token_identifier ( token_number )` (Specific) vs. `token_identifier token_usertype` (Generic)
  * **Principle**: The rule definition order and trie levels must be arranged so that the Specific rule, which produces the most explicit and distinctive grammatical element, is always executed first.

* **Avoid left recursion and excessive mutual substitution**

  * When rules such as `A -> A B` or simple substitution rules such as `A -> B`, `B -> A` are nested, the position/length information of input tokens may become distorted, causing sequence tracking to fail.

---

### 3. Considerations When Defining `repeat_as` (Sequence/List)

* **Ensure element-token completeness (Atomicity)**

  * If even one component of an element token used by `repeat_as`, such as `token_namednumberelement`, is replaced first by an external Generic rule, the entire `repeat_as` reduction may fail.
  * **Principle**: The basic unit grouped by `repeat_as` must be completely reduced during an early pass so that it does not partially overlap with any Generic rule.

* **Limit multiple semantic uses of delimiters**

  * If a token designated as a delimiter in `repeat_as`, such as `token_comma`, is also used as a normal element in another rule, list boundaries may be broken or list construction may terminate prematurely.

---

### 4. Bottom-Up Layering Principle

The Aho-Corasick ruleset must be strictly separated into layers in the order of:

**simple tokens → composite structures → complete statements**

| Layer                           | Main Role                                      | Example Rule                        | Key Consideration                              |
| ------------------------------- | ---------------------------------------------- | ----------------------------------- | ---------------------------------------------- |
| **Layer 1: Leaf & Tag**         | Combine literals, tags, and basic units        | `token_tag ::= [ number ]`          | Reduce only clearly defined minimal units      |
| **Layer 2: Element**            | Construct elements that can be placed in lists | `namednumberelement ::= id ( num )` | Completely prevent Generic-rule interference   |
| **Layer 3: Repeat/List**        | Compose sequences of identical elements        | `repeat_as(list, comma, {element})` | Preserve the purity of elements and delimiters |
| **Layer 4: Construct/Phrase**   | Complete structures and type blocks            | `phrase ::= INTEGER { list }`       | Prevent keyword contamination                  |
| **Layer 5: Sentence/Statement** | Complete top-level syntax                      | `sentence ::= lvalue ::= phrase`    | Final sentence matching                        |

---

### Summary: Rule-Writing Checklist

1. [ ] **Keyword validation**: Could syntax-starting keywords such as `INTEGER`, `ENUMERATED`, and `SEQUENCE` be included in a general group such as `builtintype`, causing an unintended Generic rule to trigger first?
2. [ ] **Element protection**: Could an element used by `repeat_as` be mistakenly recognized as a general `namedtype` or `taggedtype` and therefore be replaced too early?
3. [ ] **Use of statistics**: When checking pattern-frequency statistics, is the matching count of a higher-level/Generic pattern such as Pattern 14 abnormally high before a lower-level Specific pattern such as Pattern 0 is executed?
