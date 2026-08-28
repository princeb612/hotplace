# Pattern Matching - published by Gemini

---

### 1. Overview and Key Features

* **Module Role**: Implementation and verification module for single/multiple string searching, suffix-based indexing, wildcard matching, and regular expression (Regex) matching algorithms.
* **Key Features**:
  * **Single/Multiple String Matching**: Implements parsing and searching using Knuth-Morris-Pratt (KMP) and Aho-Corasick algorithms (`testcase_kmp.cpp`, `testcase_aho_corasick.cpp`).
  * **Suffix and Trie Data Structures**: Builds Trie and Suffix Tree data structures, and constructs linear-time suffix tries using Ukkonen's algorithm (`testcase_trie.cpp`, `testcase_suffixtree.cpp`, `testcase_ukkonen.cpp`).
  * **Wildcard and Regular Expression Matching**: Executes wildcard processing, Aho-Corasick wildcard extensions, and Regex matching operations (`testcase_wildcard.cpp`, `testcase_aho_corasick_wildcard.cpp`, `testvector_regex.cpp`).
  * **YAML-Based Test Vector Verification**: Integrates test data for Aho-Corasick, KMP, and Regex verification (`testvector_*.yml`).

---

### 2. Core Implementation Areas and Technical Elements

* **Single String Matching and Failure Functions (`testcase_kmp.cpp`, `testvector_kmp.cpp`)**:
  * Calculates the Failure Function (LPS array) using prefix/suffix match lengths and implements context transition logic.
  * Verifies search index match validity based on YAML test vector data.
* **Multiple Pattern Matching and Automata (`testcase_aho_corasick.cpp`, `testcase_aho_corasick_wildcard.cpp`)**:
  * Constructs BFS-based automata by establishing Trie-based Failure Links and Output Links.
  * Controls state transitions during multiple pattern matching involving wildcards (`?`, `*`).
* **Suffix Structures and Ukkonen's Algorithm (`testcase_suffixtree.cpp`, `testcase_ukkonen.cpp`)**:
  * Constructs Suffix Trees in $O(N)$ time complexity and performs Suffix Link updates using Ukkonen's algorithm.
  * Handles implicit/explicit node splitting via Active Point and Remaining Count management.
* **Wildcard and Regular Expression Parsing (`testcase_wildcard.cpp`, `testvector_regex.cpp`)**:
  * Performs pattern matching operations using Dynamic Programming and Greedy approaches.
  * Verifies Regex engines against test vectors based on NFA/DFA conversions.

---

### 3. Core Operating Mechanism

* **Aho-Corasick Automata Construction (`testcase_aho_corasick.cpp`)**:
  * Performs Queue-based BFS traversal after Trie construction to update Failure Links and extract patterns.
* **Ukkonen Suffix Tree Construction (`testcase_ukkonen.cpp`)**:
  * Reads strings sequentially and inserts nodes according to state transitions for Active Node, Active Edge, and Active Length.
* **Regex and Test Vector Verification (`testvector_*.cpp`, `testvector_*.yml`)**:
  * Loads test input/output sets from YAML files to validate the behavior of automata and algorithms.

---

### 4. TODO List Tracker

| No. | Task Description | Priority | Status |
| --- | --- | --- | --- |
| **TODO-PAT-01** | Optimize node allocation and prevent memory leaks when processing large strings in `testcase_ukkonen.cpp`<br> | High | Open |
| **TODO-PAT-02** | Supplement exception handling for state transitions on consecutive wildcard inputs in `testcase_aho_corasick_wildcard.cpp`<br> | High | Open |
| **TODO-PAT-03** | Validate logic preventing backtracking performance degradation during NFA conversion in `testvector_regex.cpp`<br> | Medium | Open |
| **TODO-PAT-04** | Strengthen out-of-bounds (OOB) access exception handling when calculating the KMP failure function in `testcase_kmp.cpp`<br> | Medium | Open |
| **TODO-PAT-05** | Add test cases for patterns containing special characters and spaces in `testvector_ahocorasick.yml`<br> | Low | Open |
